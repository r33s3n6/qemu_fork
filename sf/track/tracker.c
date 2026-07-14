/*
 * sf/track/tracker — thin glue between the KVM dirty-ring primitives and a
 * pluggable restore store (plan 2026-07-08-03 §3.2). It owns nothing but the
 * drain buffer + the 2-thread apply worker; all policy lives in the store, all
 * protection in the store's boundary hooks. resolve is injected so the tracker
 * stays independent of the snapshot tree. Clean-room: no Nyx code.
 */
#include "qemu/osdep.h"
#include <sched.h>
#ifdef __x86_64__
#include <immintrin.h>
#endif
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
    bool dbit = sf_kvm_dbit_mode();
    size_t cap;

    g_resolve = resolve;
    g_user = user;
    g_store = store;

    if (dbit) {
        /* NPT D-bit mode (plan 2026-07-14-03): no write-protection at all — the
         * guest keeps pages writable and hardware sets D on write (exit-free);
         * the boundary drain harvests + clears D via the sf-kvm ioctl. No global
         * dirty log, no ring. Batch is sized to every guest page (worst-case all
         * dirty). blocks give the per-RAMBlock page counts. */
        size_t psize = qemu_real_host_page_size();
        cap = 0;
        for (size_t b = 0; b < n_blocks; b++) {
            cap += DIV_ROUND_UP(blocks[b].len, psize);
        }
        g_armed = true;
    } else {
        (void)blocks;      /* the store holds its own block table (host→idx); the */
        (void)n_blocks;    /* tracker works in host pointers from the ring drain. */
        cap = sf_kvm_ring_capacity();
        /* Arm KVM dirty tracking from a clean slate (idempotent within a session). */
        if (!g_armed) {
            memory_global_dirty_log_start(GLOBAL_DIRTY_MIGRATION, &error_abort);
            sf_kvm_dirty_ring_set_owned(true);
            g_armed = true;
        }
        sf_kvm_dirty_clean_slate();
    }

    if (g_hostbuf_cap < cap) {
        g_hostbuf_cap = cap;
        g_hostbuf = g_renew(void *, g_hostbuf, g_hostbuf_cap);
    }

    /* dbit: discard one harvest to zero every D-bit set during boot/cold-start,
     * so the first tracked round reflects only post-arm guest writes. */
    if (dbit) {
        (void)sf_kvm_harvest_dbit(g_hostbuf, g_hostbuf_cap);
    }
}

void sf_track_end(void)
{
    /* Detach only; the snap layer owns the store's lifetime (frees via ops->free). */
    g_store = NULL;
    g_resolve = NULL;
    if (g_armed) {
        if (!sf_kvm_dbit_mode()) {
            sf_kvm_dirty_ring_set_owned(false);
        }
        g_armed = false;
    }
}

void sf_track_drain(void)
{
    size_t n;

    if (!g_store) {
        return;
    }
    n = sf_kvm_dbit_mode() ? sf_kvm_harvest_dbit(g_hostbuf, g_hostbuf_cap)
                           : sf_kvm_drain_ring(g_hostbuf, g_hostbuf_cap);
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

/* ---- apply memcpy: threads auto by CPU affinity (≥2 CPUs → caller + one
 * persistent bg worker = measured ~×2 at wide affinity, archive 2026-06-21-08;
 * pinned to 1 CPU → single-thread, bg would only time-share the core — tag
 * sf-restore-perf). SF_APPLY_THREADS=1|2 overrides. Two-pass (resolve-all in
 * plan, then memcpy-all).
 */
#ifdef __x86_64__
/* Non-temporal (streaming) stores for the destination pages, skipping the
 * write-allocate RFO read of every destination line. Default ON — production
 * is high-C where it nets races/s 1.30–1.50× (grid3); SF_APPLY_NT=0 opts out
 * for low-C diagnostic runs, where the guest-first-read tax makes it a small
 * net loss (plan 2026-07-14-02 / tag sf-restore-perf). */
static bool sf_apply_nt(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *e = getenv("SF_APPLY_NT");
        cached = !(e && *e == '0');
    }
    return cached;
}

static void sf_copy_nt(void *dst, const uint8_t *src, size_t bytes)
{
    /* bytes is a multiple of the (power-of-two ≥ 64) page size and dst is
     * page-aligned, so 16B-aligned movntdq never faults and there is no tail. */
    for (size_t off = 0; off < bytes; off += 64) {
        __m128i a = _mm_loadu_si128((const __m128i *)(src + off));
        __m128i b = _mm_loadu_si128((const __m128i *)(src + off + 16));
        __m128i c = _mm_loadu_si128((const __m128i *)(src + off + 32));
        __m128i d = _mm_loadu_si128((const __m128i *)(src + off + 48));
        _mm_stream_si128((__m128i *)((uint8_t *)dst + off), a);
        _mm_stream_si128((__m128i *)((uint8_t *)dst + off + 16), b);
        _mm_stream_si128((__m128i *)((uint8_t *)dst + off + 32), c);
        _mm_stream_si128((__m128i *)((uint8_t *)dst + off + 48), d);
    }
}
#endif

/* SF_APPLY_MERGE=1: sf_track_apply hands this function an address-sorted
 * scratch copy of the plan; coalesce dst+src-contiguous neighbours into one
 * larger copy each (experiment knob, plan 07-14-02 follow-up; default off). */
static bool sf_apply_merge(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *e = getenv("SF_APPLY_MERGE");
        cached = (e && *e == '1');
    }
    return cached;
}

static void sf_copy_slice(const SfPlanPage *pages, size_t start, size_t end)
{
    size_t psize = qemu_real_host_page_size();
    bool nt = false;
#ifdef __x86_64__
    nt = sf_apply_nt();
#endif
    if (sf_apply_merge()) {
        for (size_t i = start; i < end; ) {
            if (!pages[i].dst || !pages[i].src) {
                i++;
                continue;
            }
            size_t j = i + 1;
            while (j < end && pages[j].dst && pages[j].src &&
                   (uint8_t *)pages[j].dst ==
                       (uint8_t *)pages[i].dst + (j - i) * psize &&
                   pages[j].src == pages[i].src + (j - i) * psize) {
                j++;
            }
#ifdef __x86_64__
            if (nt) {
                sf_copy_nt(pages[i].dst, pages[i].src, (j - i) * psize);
            } else
#endif
            {
                memcpy(pages[i].dst, pages[i].src, (j - i) * psize);
            }
            i = j;
        }
    } else if (nt) {
#ifdef __x86_64__
        for (size_t i = start; i < end; i++) {
            if (pages[i].dst && pages[i].src) {
                sf_copy_nt(pages[i].dst, pages[i].src, psize);
            }
        }
#endif
    } else {
        for (size_t i = start; i < end; i++) {
            if (pages[i].dst && pages[i].src) {
                memcpy(pages[i].dst, pages[i].src, psize);
            }
        }
    }
#ifdef __x86_64__
    if (nt) {
        /* NT stores are weakly ordered: fence before anyone (vCPU, or the
         * caller joining the bg worker) may read these pages. Every apply path
         * ends in this function on its own thread, so one sfence per slice
         * covers single-thread, caller-half and worker-half (the worker fences
         * before its done-signal; the mutex hand-off orders the rest). Missing
         * this = silent stale guest pages, worse than a crash. */
        _mm_sfence();
    }
#endif
}

/* 1 = single-thread (no bg worker); 2 = dual-thread. Default auto by CPU
 * affinity: the bg half only helps if this process may run on ≥2 CPUs —
 * production workers are taskset-pinned to one logical CPU, where a second
 * apply thread just time-shares the core (measured zero wall gain, doubled
 * apply cpu; tag sf-restore-perf). SF_APPLY_THREADS=1|2 overrides. Read once. */
static int sf_apply_nthreads(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *e = getenv("SF_APPLY_THREADS");
        if (e && *e) {
            char *end = NULL;
            long v = strtol(e, &end, 10);
            if (end != e && *end == '\0' && (v == 1 || v == 2)) {
                cached = (int)v;
            }
        }
        if (cached < 0) {
            cpu_set_t set;
            cached = (sched_getaffinity(0, sizeof(set), &set) == 0 &&
                      CPU_COUNT(&set) >= 2) ? 2 : 1;
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
    uint64_t cpu_ns;            /* thread-CPU spent on the last slice (for ram_cpu) */
    bool have_work, done, started;
} SfApplyWorker;

static SfApplyWorker g_worker;
static uint64_t g_last_bg_cpu_ns;   /* bg-thread CPU of the last apply (0 = single-thread) */

#define SF_APPLY_PARALLEL_MIN 2048   /* below this the handoff isn't worth it */

static uint64_t sf_thread_cpu_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

/* SF_APPLY_SIBLING=1: pin the bg apply thread to the SMT sibling of the CPU the
 * worker is pinned to, so the two apply halves land on 2 hardware threads of the
 * same physical core instead of time-sharing one. Experiment knob (memcpy is
 * memory-bound → SMT siblings share L2/mem ports, so expect little at a full
 * machine). No-op if topology can't be read. */
static void sf_apply_pin_sibling(void)
{
    int cpu = sched_getcpu();
    if (cpu < 0) {
        return;
    }
    char path[128], buf[128];
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu);
    FILE *f = fopen(path, "r");
    if (!f) {
        return;
    }
    int sib = -1;
    if (fgets(buf, sizeof(buf), f)) {
        for (char *p = buf; *p; ) {
            int v = (int)strtol(p, &p, 10);
            if (v != cpu) { sib = v; break; }
            while (*p == ',' || *p == '-') { p++; }
        }
    }
    fclose(f);
    if (sib >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(sib, &set);
        sched_setaffinity(0, sizeof(set), &set);
    }
}

static void *sf_apply_worker_fn(void *opaque)
{
    SfApplyWorker *w = opaque;
    if (getenv("SF_APPLY_SIBLING")) {
        sf_apply_pin_sibling();
    }
    qemu_mutex_lock(&w->mtx);
    for (;;) {
        while (!w->have_work) {
            qemu_cond_wait(&w->cond_work, &w->mtx);
        }
        const SfPlanPage *pages = w->pages;
        size_t s = w->start, e = w->end;
        qemu_mutex_unlock(&w->mtx);

        uint64_t c0 = sf_thread_cpu_ns();
        sf_copy_slice(pages, s, e);
        uint64_t slice_cpu = sf_thread_cpu_ns() - c0;

        qemu_mutex_lock(&w->mtx);
        w->cpu_ns = slice_cpu;
        w->have_work = false;
        w->done = true;
        qemu_cond_signal(&w->cond_done);
    }
    /* ponytail: never signalled to exit; lives for the process (blocked in wait). */
}

/* bg-thread CPU (ns) consumed by the most recent sf_track_apply; 0 if that apply
 * ran single-threaded (caller CPU already covers it). */
uint64_t sf_track_last_apply_bg_cpu_ns(void)
{
    return g_last_bg_cpu_ns;
}

static int sf_plan_cmp_dst(const void *a, const void *b)
{
    const SfPlanPage *pa = a, *pb = b;
    return pa->dst < pb->dst ? -1 : pa->dst > pb->dst;
}

void sf_track_apply(const SfPlanPage *pages, size_t n)
{
    SfApplyWorker *w = &g_worker;
    size_t mid;

    if (!n) {
        return;
    }
    if (sf_apply_merge()) {
        /* Address-sort a scratch copy (the store's plan order carries the
         * unsure_n carry semantics — don't touch it). Sort cost lands inside
         * the caller's ram timing window, so measurements stay honest. */
        static SfPlanPage *scratch;
        static size_t scratch_cap;
        if (n > scratch_cap) {
            scratch_cap = n * 2;
            scratch = g_renew(SfPlanPage, scratch, scratch_cap);
        }
        memcpy(scratch, pages, n * sizeof(*pages));
        qsort(scratch, n, sizeof(*scratch), sf_plan_cmp_dst);
        pages = scratch;
        if (getenv("SF_DIRTY_TRACE")) {   /* achieved merge rate (diagnostic) */
            size_t psize = qemu_real_host_page_size(), ext = 0;
            for (size_t i = 0; i < n; ) {
                size_t j = i + 1;
                while (j < n && scratch[j].dst && scratch[j].src &&
                       scratch[i].dst && scratch[i].src &&
                       (uint8_t *)scratch[j].dst ==
                           (uint8_t *)scratch[i].dst + (j - i) * psize &&
                       scratch[j].src == scratch[i].src + (j - i) * psize) {
                    j++;
                }
                ext++;
                i = j;
            }
            fprintf(stderr, "sf-apply-merge: n=%zu extents=%zu\n", n, ext);
        }
    }
    /* SF_APPLY_THREADS=1: no background thread; always single-thread memcpy. */
    if (sf_apply_nthreads() == 1 || n < SF_APPLY_PARALLEL_MIN) {
        g_last_bg_cpu_ns = 0;   /* caller-thread CPU already covers the whole apply */
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
    g_last_bg_cpu_ns = w->cpu_ns;   /* fold bg half into ram_cpu (see restore.c) */
    qemu_mutex_unlock(&w->mtx);
}
