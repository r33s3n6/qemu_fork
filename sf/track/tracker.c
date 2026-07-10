/*
 * sf/track/tracker — thin glue between the KVM dirty-ring primitives and a
 * pluggable restore store (plan 2026-07-08-03 §3.2). It owns nothing but the
 * drain buffer + the 2-thread apply worker; all policy lives in the store, all
 * protection in the store's boundary hooks. resolve is injected so the tracker
 * stays independent of the snapshot tree. Clean-room: no Nyx code.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/thread.h"
#include "system/kvm.h"
#include "system/memory.h"
#include "sf/track/tracker.h"

static SfResolveFn       g_resolve;
static void             *g_user;
static SfRestoreStore   *g_store;
static bool              g_armed;

/* Drain scratch: host pages read from the ring in one batch (reused). Sized to
 * the whole ring so a single drain never truncates. */
static void  **g_hostbuf;
static size_t  g_hostbuf_cap;

/* Fault injection (selftest only): a host page the drain must pretend it never
 * saw, so it never enters the store's restore set. */
static void   *g_inject_drop;

void sf_track_inject_drop(void *host)
{
    g_inject_drop = host;
}

bool sf_track_active(void)
{
    return g_armed && g_store;
}

void sf_track_begin(const SfBlockReg *blocks, size_t n_blocks,
                    SfResolveFn resolve, void *user, SfRestoreStore *store)
{
    size_t ring = sf_kvm_ring_capacity();

    (void)blocks;      /* the store holds its own block table (host→idx); the */
    (void)n_blocks;    /* tracker works in host pointers from the ring drain. */
    g_resolve = resolve;
    g_user = user;
    g_store = store;

    /* Arm KVM dirty tracking from a clean slate (idempotent within a session). */
    if (!g_armed) {
        memory_global_dirty_log_start(GLOBAL_DIRTY_MIGRATION, &error_abort);
        sf_kvm_dirty_ring_set_owned(true);
        g_armed = true;
    }
    sf_kvm_dirty_clean_slate();

    if (g_hostbuf_cap < ring) {
        g_hostbuf_cap = ring;
        g_hostbuf = g_renew(void *, g_hostbuf, g_hostbuf_cap);
    }
}

void sf_track_end(void)
{
    /* Detach only; the snap layer owns the store's lifetime (frees via ops->free). */
    g_store = NULL;
    g_resolve = NULL;
    if (g_armed) {
        sf_kvm_dirty_ring_set_owned(false);
        g_armed = false;
    }
}

void sf_track_drain(void)
{
    size_t n;

    if (!g_store) {
        return;
    }
    n = sf_kvm_drain_ring(g_hostbuf, g_hostbuf_cap);
    if (g_inject_drop) {   /* selftest: elide the injected page from the batch */
        size_t w = 0;
        for (size_t i = 0; i < n; i++) {
            if (g_hostbuf[i] != g_inject_drop) {
                g_hostbuf[w++] = g_hostbuf[i];
            }
        }
        n = w;
    }
    g_store->ops->note_batch(g_store, g_hostbuf, n);
}

const SfRestorePlan *sf_track_plan(void *target)
{
    return g_store ? g_store->ops->plan(g_store, target) : NULL;
}

size_t sf_track_after_restore(void *target)
{
    if (g_store) {
        return g_store->ops->after_restore(g_store, target);
    }
    return 0;
}

void sf_track_after_drain(void)
{
    if (g_store) {
        g_store->ops->after_drain(g_store);
    }
}

uint8_t *sf_track_resolve(void *target, void *host)
{
    return g_resolve ? g_resolve(target, host, g_user) : NULL;
}

void sf_track_set_active(void *node)
{
    if (g_store) {
        g_store->ops->set_active(g_store, node);
    }
}

void sf_track_invalidate(void *target)
{
    if (g_store) {
        g_store->ops->invalidate(g_store, target);
    }
}

/* ---- apply memcpy: default 2-thread, SF_APPLY_THREADS=1 forces single-thread *
 * main + one persistent background worker = measured ~×2 sweet spot
 * (archive 2026-06-21-08). SF_APPLY_THREADS=1 = no background thread (all
 * memcpy on the caller). Two-pass (resolve-all in plan, then memcpy-all).
 */
static void sf_copy_slice(const SfPlanPage *pages, size_t start, size_t end)
{
    size_t psize = qemu_real_host_page_size();
    for (size_t i = start; i < end; i++) {
        if (pages[i].dst && pages[i].src) {
            memcpy(pages[i].dst, pages[i].src, psize);
        }
    }
}

/* 1 = single-thread (no bg worker); 2 = default dual-thread. Read once. */
static int sf_apply_nthreads(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *e = getenv("SF_APPLY_THREADS");
        cached = 2;
        if (e && *e) {
            char *end = NULL;
            long v = strtol(e, &end, 10);
            if (end != e && *end == '\0' && (v == 1 || v == 2)) {
                cached = (int)v;
            }
        }
    }
    return cached;
}

typedef struct {
    QemuThread thread;
    QemuMutex  mtx;
    QemuCond   cond_work;
    QemuCond   cond_done;
    const SfPlanPage *pages;
    size_t start, end;
    bool have_work, done, started;
} SfApplyWorker;

static SfApplyWorker g_worker;

#define SF_APPLY_PARALLEL_MIN 2048   /* below this the handoff isn't worth it */

static void *sf_apply_worker_fn(void *opaque)
{
    SfApplyWorker *w = opaque;
    qemu_mutex_lock(&w->mtx);
    for (;;) {
        while (!w->have_work) {
            qemu_cond_wait(&w->cond_work, &w->mtx);
        }
        const SfPlanPage *pages = w->pages;
        size_t s = w->start, e = w->end;
        qemu_mutex_unlock(&w->mtx);

        sf_copy_slice(pages, s, e);

        qemu_mutex_lock(&w->mtx);
        w->have_work = false;
        w->done = true;
        qemu_cond_signal(&w->cond_done);
    }
    /* ponytail: never signalled to exit; lives for the process (blocked in wait). */
}

void sf_track_apply(const SfPlanPage *pages, size_t n)
{
    SfApplyWorker *w = &g_worker;
    size_t mid;

    if (!n) {
        return;
    }
    /* SF_APPLY_THREADS=1: no background thread; always single-thread memcpy. */
    if (sf_apply_nthreads() == 1 || n < SF_APPLY_PARALLEL_MIN) {
        sf_copy_slice(pages, 0, n);
        return;
    }
    if (!w->started) {
        qemu_mutex_init(&w->mtx);
        qemu_cond_init(&w->cond_work);
        qemu_cond_init(&w->cond_done);
        qemu_thread_create(&w->thread, "sf-apply", sf_apply_worker_fn, w,
                           QEMU_THREAD_JOINABLE);
        w->started = true;
    }

    mid = n / 2;
    qemu_mutex_lock(&w->mtx);
    w->pages = pages; w->start = mid; w->end = n;
    w->done = false; w->have_work = true;
    qemu_cond_signal(&w->cond_work);
    qemu_mutex_unlock(&w->mtx);

    sf_copy_slice(pages, 0, mid);       /* caller does the lower half */

    qemu_mutex_lock(&w->mtx);
    while (!w->done) {
        qemu_cond_wait(&w->cond_done, &w->mtx);
    }
    qemu_mutex_unlock(&w->mtx);
}
