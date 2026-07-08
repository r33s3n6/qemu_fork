/*
 * sf/snap/restore — top-level snapshot save/restore for the multi-level tree.
 * Impl truth: research/plans/2026-07-06-04-m3-core-engine-impl.md (§2 save, §3
 * restore). T1 (行为不变闸): only the root node exists; RAM/device still
 * delegate to the existing dirty engine + preparse/replay. The delta-restore
 * resolve path (sf_resolve) is implemented in node.c and exercised by the
 * root-creation self-check; T2/T3 put it on the hot path.
 *
 * Clock semantics are split per-path (preserved exactly from the M0-S spike):
 *  - HMP path: caller wraps vm_stop/vm_start; vm_start fires the runstate
 *    handlers (kvmclock KVM_SET_CLOCK, vapic). The core here does NOT touch
 *    kvmclock/vapic.
 *  - terminal CHECKPOINT path: no vm_start, so sf_apply_clock_tail() explicitly
 *    re-anchors kvmclock + reactivates vapic after the core.
 * The TSC forced rewind (sf_kvm_refreeze_tsc) is common-core (both paths need
 * it; vm_start does not do it). See sf/kvm_tsc.h + ARCHITECTURE §4.4.
 *
 * Caller owns quiescence (HMP vm_stop crutch, or the vcpu CHECKPOINT boundary).
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/thread.h"
#include "monitor/monitor.h"
#include "system/runstate.h"
#include "system/hw_accel.h"
#include "system/kvm.h"
#include "hw/core/cpu.h"
#include "hw/i386/kvm/clock.h"
#include "hw/i386/vapic.h"
#include "hw/nvram/fw_cfg.h"
#include "migration/vmstate.h"
#include "sf/kvm_tsc.h"
#include "sf/dirty/engine.h"
#include "sf/vmstate_replay/preparse.h"
#include "sf/vmstate_replay/replay.h"
#include "sf/snap/node.h"
#include "sf/snap/exclude.h"
#include "sf/snap/tripwire.h"
#include "sf/sf.h"          /* sf_skip_tsc declaration (defined here) */

/* ---- timing probe (SF_TIME) ---- */
static bool sf_timing(void)
{
    const char *s = getenv("SF_TIME");
    return s && *s;
}
static uint64_t sf_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ---- test knobs (teeth for the phase1.5 gates) ---- */
bool sf_skip_tsc(void)   /* exposed for the terminal snapshot path's refreeze */
{
    const char *s = getenv("SF_CP_SKIP_TSC");
    return s && *s;
}
static bool sf_skip_kvmclock(void)
{
    const char *s = getenv("SF_CP_SKIP_KVMCLOCK");
    return s && *s;
}

/* ---- device-table helpers (moved from sf.c) ---- */

static void *sf_find_opaque(const SfReplayTables *t, const char *name)
{
    for (size_t i = 0; i < t->n_posts; i++) {
        if (!strcmp(t->posts[i].vmsd->name, name)) {
            return t->posts[i].opaque;
        }
    }
    return NULL;
}

static bool sf_name_in(const char *name, const char * const *allowed)
{
    for (size_t i = 0; allowed[i]; i++) {
        if (!strcmp(name, allowed[i])) {
            return true;
        }
    }
    return false;
}

/*
 * Hot-profile guard: the minimal in-kernel restore set (ARCHITECTURE §4.4) is
 * only correct for the microvm device set actually enumerated. Refuse to snapshot
 * an unverified set so a vmstate drift doesn't silently break restore. Returns
 * true iff @t (may be NULL when preparse failed) is the supported profile.
 */
static bool sf_validate_hot_profile(Monitor *mon, const SfReplayTables *t)
{
    static const char * const allowed_pre[] = {
        "apic", "cpu_common", "kvmclock", "serial", NULL,
    };
    static const char * const allowed_post[] = {
        "apic", "fw_cfg/acpi_mr", "cpu_common", "cpu", "kvm-tpr-opt",
        "ioapic", "serial", "globalstate", NULL,
    };
    CPUState *cpu;
    size_t ncpus = 0;

    if (!t) {
        return true;   /* device preparse failed (best-effort); RAM still usable */
    }

    CPU_FOREACH(cpu) {
        ncpus++;
    }
    if (ncpus != 1) {
        monitor_printf(mon, "sf: hot-profile guard failed: expected 1 vCPU, "
                       "saw %zu\n", ncpus);
        return false;
    }

    for (size_t i = 0; i < t->n_gets; i++) {
        const SfGet *g = &t->gets[i];
        if (strcmp(g->vmsd_name, "fpreg") ||
            strcmp(g->field->name, "tmp") ||
            strcmp(g->info->name, "tmp")) {
            monitor_printf(mon, "sf: hot-profile guard failed: unsupported get "
                           "%s/%s info=%s at index %zu\n",
                           g->vmsd_name, g->field->name, g->info->name, i);
            return false;
        }
    }

    for (size_t i = 0; i < t->n_posts; i++) {
        const SfPost *p = &t->posts[i];
        const char *name = p->vmsd->name;

        if (p->is_pre) {
            if (!sf_name_in(name, allowed_pre)) {
                monitor_printf(mon, "sf: hot-profile guard failed: unsupported "
                               "pre_load %s at index %zu\n", name, i);
                return false;
            }
            if (!strcmp(name, "kvmclock") &&
                !kvmclock_sf_guard_clock_reliable(p->opaque)) {
                monitor_printf(mon, "sf: hot-profile guard failed: kvmclock "
                               "clock_is_reliable is false\n");
                return false;
            }
        } else if (!sf_name_in(name, allowed_post)) {
            monitor_printf(mon, "sf: hot-profile guard failed: unsupported "
                           "post_load %s at index %zu\n", name, i);
            return false;
        } else if (!strcmp(name, "kvm-tpr-opt") &&
                   !vapic_sf_guard_inactive(p->opaque)) {
            monitor_printf(mon, "sf: hot-profile guard failed: vapic is active "
                           "or has rom_state_paddr\n");
            return false;
        } else if (!strcmp(name, "fw_cfg/acpi_mr") &&
                   !fw_cfg_acpi_mr_restore_sizes_match(p->opaque)) {
            monitor_printf(mon, "sf: hot-profile guard failed: ACPI memory "
                           "region sizes differ from captured sizes\n");
            return false;
        }
    }
    return true;
}

/*
 * Root-creation self-check (T1 teeth for the new block-table / key / resolve
 * machinery, which T2/T3 will rely on): for every registered block, the
 * host<->key round-trip and root owner-resolution must return the engine shadow
 * that backs the same host page. Cheap (O(blocks)); runs only under SF_TIME so
 * it never weighs on a real run. Failures abort the snapshot.
 */
static int sf_root_selfcheck(Monitor *mon)
{
    for (size_t i = 0; i < sf_n_blocks; i++) {
        SfBlockDesc *b = &sf_blocks[i];
        uint8_t *host = (uint8_t *)b->host;
        uint64_t remain = 0;
        SfPageKey key;
        uint8_t *back, *shadow;

        if (!sf_host_to_key_safe(host, &key) ||
            SF_KEY_BLOCK(key) != i || SF_KEY_PFN(key) != 0) {
            monitor_printf(mon, "sf: selfcheck FAIL block %zu host->key=%llx\n",
                           i, (unsigned long long)key);
            return -EIO;
        }
        back = sf_key_to_host(key);
        if (back != host) {
            monitor_printf(mon, "sf: selfcheck FAIL block %zu key->host mismatch\n",
                           i);
            return -EIO;
        }
        /* resolve(root, key) must yield the engine shadow for this host page. */
        shadow = sf_dirty_shadow_for(host, &remain);
        if (!shadow || sf_resolve(sf_active, key) != shadow) {
            monitor_printf(mon, "sf: selfcheck FAIL block %zu resolve != shadow\n",
                           i);
            return -EIO;
        }
    }
    return 0;
}

/* ---- W key-set builder (shared by save diff + delta restore) ---- */

/* selftest injection: build_diff omits the HOT union (proves HOT∪ is required
 * under blind — plan -04 §7 case 4). Test-only. */
static bool g_inject_skip_hot;
void sf_snap_inject_skip_hot(bool skip) { g_inject_skip_hot = skip; }

typedef struct SfWAcc {
    SfPageKey *keys;
    size_t     n, cap;
} SfWAcc;

static void sf_w_push(SfWAcc *a, SfPageKey k)
{
    if (a->n == a->cap) {
        a->cap = a->cap ? a->cap * 2 : 4096;
        a->keys = g_renew(SfPageKey, a->keys, a->cap);
    }
    a->keys[a->n++] = k;
}

static void sf_w_push_host(void *host, void *user)
{
    SfPageKey k;
    if (sf_host_to_key_safe(host, &k)) {
        sf_w_push((SfWAcc *)user, k);
    }
}

/* Sort + unique in place; return the unique count. */
static size_t sf_w_sort_uniq(SfWAcc *a)
{
    qsort(a->keys, a->n, sizeof(SfPageKey), sf_key_cmp);
    size_t u = 0;
    for (size_t i = 0; i < a->n; i++) {
        if (i == 0 || a->keys[i] != a->keys[i - 1]) {
            a->keys[u++] = a->keys[i];
        }
    }
    return u;
}

/* W -= NO_RESTORE 排除区 (plan 2026-07-06-06 §1 接入点): drop keys whose host
 * page is excluded. Empty table → no-op (one branch per key). */
static size_t sf_w_filter_excluded(SfWAcc *a, size_t n)
{
    size_t u = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t *host = sf_key_to_host(a->keys[i]);
        /* Each key is one page-aligned page → point query (bsearch), not the
         * linear range scan. */
        if (host && sf_excluded(host)) {
            continue;   /* NO_RESTORE: not saved, not restored */
        }
        a->keys[u++] = a->keys[i];
    }
    return u;
}

/* Push every index key of a diff node into W (for the restore path union). */
static void sf_w_push_index(SfWAcc *a, const SfRamStore *s)
{
    if (!s->index) {
        return;
    }
    for (uint32_t i = 0; i < s->n_pages; i++) {
        sf_w_push(a, s->index[i]);
    }
}

/* ---- RAM-only cores (selftest / building blocks; no device, no guard) ----
 * Production save/restore wrap these with device capture (T4) + clock tail.
 * Exposed so the RAM diff/delta mechanics are testable under pc KVM, where the
 * microvm hot-profile guard refuses the full preparse. */

/*
 * RAM-only root: engine full-shadow + block registry + root node, sets sf_active.
 * No device preparse, no hot-profile guard. The selftest and the production
 * ROOT save both build on this (production adds preparse+guard+kvm.tsc).
 */
SfSnapNode *sf_snap_ram_root(Error **errp)
{
    Error *err = NULL;
    SfSnapNode *node;
    SfDirtyShadowDesc *shadows = NULL;
    const char *root_dir = getenv("SF_ROOT_DIR");
    char *root_path = NULL;

    /* Drop any previous tree + block table; the engine snapshot drops the old
     * shadow itself. */
    if (sf_active) {
        SfSnapNode *root = sf_active;
        while (root->parent) { root = root->parent; }
        sf_snap_hot_cache_invalidate();
        sf_node_destroy(root);
        sf_active = NULL;
    }
    sf_blocks_destroy();

    if (sf_blocks_enumerate(&err) < 0) {
        error_propagate(errp, err);
        return NULL;
    }

    node = sf_node_new(NULL, SF_SNAP_ROOT);
    if (root_dir && *root_dir) {
        if (g_mkdir_with_parents(root_dir, 0700) < 0) {
            error_setg_errno(errp, errno, "sf_snap_ram_root: mkdir %s", root_dir);
            sf_node_destroy(node);
            sf_blocks_destroy();
            return NULL;
        }
        root_path = g_build_filename(root_dir, "root.ram", NULL);
        if (sf_rootstore_create_file(&node->ram, root_path, &err) < 0) {
            error_propagate(errp, err);
            g_free(root_path);
            sf_node_destroy(node);
            sf_blocks_destroy();
            return NULL;
        }
        g_free(root_path);
    } else if (sf_rootstore_create_anon(&node->ram) < 0) {
        error_setg(errp, "sf_snap_ram_root: root backing allocation failed");
        sf_node_destroy(node);
        sf_blocks_destroy();
        return NULL;
    }

    shadows = g_new0(SfDirtyShadowDesc, sf_n_blocks);
    for (size_t i = 0; i < sf_n_blocks; i++) {
        SfBlockDesc *b = &sf_blocks[i];
        uint8_t *dst = node->ram.data + b->root_off;
        memcpy(dst, b->host, b->len);
        shadows[i].host = b->host;
        shadows[i].len = b->len;
        shadows[i].shadow = dst;
    }

    if (sf_dirty_use_external_shadows(shadows, sf_n_blocks, &err) < 0) {
        error_propagate(errp, err);
        g_free(shadows);
        sf_node_destroy(node);
        sf_blocks_destroy();
        return NULL;
    }
    g_free(shadows);
    if (kvm_enabled() && current_cpu) {
        node->kvm.tsc = sf_kvm_read_tsc(current_cpu);
    }
    sf_active = node;
    /* Arm the tripwire: a snapshot tree now exists, host writes to its RAM
     * must be caught. Stays armed until the tree is torn down (sf_node_destroy
     * on the root disarms). */
    sf_tripwire_arm(true);
    return node;
}

/*
 * RAM-only non-root diff: collect this generation's dirty pages (the diff vs the
 * active node = parent), union the HOT set, build a diff ramstore copying live
 * pages into it (eager, live→store). Resets the ring (INV-B) so the next
 * generation is relative to this new node. Does NOT set sf_active (the caller
 * decides — production save does, after device capture; selftest controls it).
 */
SfSnapNode *sf_snap_build_diff(SfSnapNode *parent, SfSnapKind kind, Error **errp)
{
    size_t psize = qemu_real_host_page_size();
    SfWAcc acc = { 0 };
    SfSnapNode *node;
    size_t n_dirty, n_uniq;
    void *const *dirty;

    if (!parent) {
        error_setg(errp, "sf_snap_build_diff: parent required");
        return NULL;
    }
    if (!sf_dirty_have_snapshot()) {
        error_setg(errp, "sf_snap_build_diff: no root shadow (build root first)");
        return NULL;
    }

    /* Step 1: collect this generation's dirty pages (diff vs active = parent). */
    sf_dirty_collect();
    dirty = sf_dirty_collected(&n_dirty);
    for (size_t i = 0; i < n_dirty; i++) {
        SfPageKey k;
        if (sf_host_to_key_safe(dirty[i], &k)) {
            sf_w_push(&acc, k);
        }
    }
    /* Step 2: ∪ HOT (保守超集 today; 正确性必需 once I.3 blind lands — plan §3).
     * g_inject_skip_hot (test-only) omits this to prove HOT∪ is required. */
    if (!g_inject_skip_hot) {
        sf_dirty_iter_hot(sf_w_push_host, &acc);
    }
    /* Step 3: W -= NO_RESTORE 排除区 (plan 2026-07-06-06; table empty → no-op). */

    n_uniq = sf_w_sort_uniq(&acc);
    n_uniq = sf_w_filter_excluded(&acc, n_uniq);

    node = sf_node_new(parent, kind);
    if (sf_ramstore_create_anon(&node->ram, (uint32_t)n_uniq) < 0) {
        error_setg(errp, "sf_snap_build_diff: ramstore oom");
        sf_node_destroy(node);
        g_free(acc.keys);
        return NULL;
    }
    /* Step 4: eager copy live→store, parallel to the sorted index. */
    for (size_t i = 0; i < n_uniq; i++) {
        uint8_t *host = sf_key_to_host(acc.keys[i]);
        node->ram.index[i] = acc.keys[i];
        if (host) {
            memcpy(node->ram.data + i * psize, host, psize);
        }
    }
    g_free(acc.keys);

    /* Step 6: INV-B — clear the vector + reset the ring so the next generation
     * is relative to this new node. */
    sf_dirty_clear_collected();
    sf_dirty_force_reset_ring();
    return node;
}

/*
 * Build the restore W set (plan §4): collect (live dirty to roll back) ∪ HOT ∪
 * path(src→L] (undo src-side layers) ∪ path(dst→L] (apply dst-side layers),
 * sorted + unique. Side effect: collect() called. Caller applies W then resets.
 */
static size_t sf_build_restore_w(SfSnapNode *src, SfSnapNode *dst, SfSnapNode *L,
                                 SfWAcc *acc)
{
    size_t n_dirty;
    void *const *dirty;

    sf_dirty_collect();
    dirty = sf_dirty_collected(&n_dirty);
    for (size_t i = 0; i < n_dirty; i++) {
        SfPageKey k;
        if (sf_host_to_key_safe(dirty[i], &k)) {
            sf_w_push(acc, k);
        }
    }
    sf_dirty_iter_hot(sf_w_push_host, acc);
    for (SfSnapNode *n = src; n != L; n = n->parent) {
        sf_w_push_index(acc, &n->ram);
    }
    for (SfSnapNode *n = dst; n != L; n = n->parent) {
        sf_w_push_index(acc, &n->ram);
    }
    /* W -= NO_RESTORE 排除区 (plan 06; table empty → no-op). */
    return sf_w_filter_excluded(acc, sf_w_sort_uniq(acc));
}

typedef struct SfApplyPage {
    uint8_t *host;
    uint8_t *src;
} SfApplyPage;

typedef struct SfHotCache {
    SfSnapNode *dst;
    GHashTable *src_by_key; /* SfPageKey -> src page */
} SfHotCache;

static SfHotCache g_hot_cache;

void sf_snap_hot_cache_invalidate(void)
{
    if (g_hot_cache.src_by_key) {
        g_hash_table_remove_all(g_hot_cache.src_by_key);
    }
    g_hot_cache.dst = NULL;
}

static void sf_hot_cache_reset(SfSnapNode *dst)
{
    if (!g_hot_cache.src_by_key) {
        g_hot_cache.src_by_key = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    if (g_hot_cache.dst != dst) {
        g_hash_table_remove_all(g_hot_cache.src_by_key);
        g_hot_cache.dst = dst;
    }
}

static uint8_t *sf_hot_cache_lookup(SfSnapNode *dst, SfPageKey key)
{
    if (!g_hot_cache.src_by_key || g_hot_cache.dst != dst) {
        return NULL;
    }
    return g_hash_table_lookup(g_hot_cache.src_by_key,
                               (gpointer)(uintptr_t)key);
}

static void sf_hot_cache_put(SfSnapNode *dst, SfPageKey key, uint8_t *src)
{
    sf_hot_cache_reset(dst);
    g_hash_table_insert(g_hot_cache.src_by_key, (gpointer)(uintptr_t)key, src);
}

static void sf_apply_resolve(SfSnapNode *dst, const SfPageKey *keys,
                             SfApplyPage *pages, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t *host = sf_key_to_host(keys[i]);
        uint8_t *src = NULL;

        if (host && sf_dirty_is_hot(host)) {
            src = sf_hot_cache_lookup(dst, keys[i]);
        }
        if (host && !src) {
            src = sf_resolve(dst, keys[i]);
            if (src && sf_dirty_is_hot(host)) {
                sf_hot_cache_put(dst, keys[i], src);
            }
        }
        pages[i].host = host;
        pages[i].src = src;
    }
}

/* Copy a pre-resolved slice [start,end). Each key maps to a distinct host page
 * (W is sort_uniq'd), so slices run concurrently unlocked. */
static void sf_copy_slice(const SfApplyPage *pages, size_t start, size_t end,
                          size_t psize)
{
    for (size_t i = start; i < end; i++) {
        if (pages[i].host && pages[i].src) {
            memcpy(pages[i].host, pages[i].src, psize);
        }
    }
}

/* One persistent background copy thread: main thread + it = 2-way memcpy (the
 * measured sweet spot, ~×2; more threads saturate memory bandwidth — archive
 * 2026-06-21-08). Created lazily on first parallel apply so there's no per-restore
 * spawn cost. ram= is 80–90% of restore, so this ~halves the dominant phase. */
typedef struct {
    QemuThread thread;
    QemuMutex  mtx;
    QemuCond   cond_work;   /* main → worker: a slice is ready */
    QemuCond   cond_done;   /* worker → main: slice finished */
    const SfApplyPage *pages;
    size_t psize;
    size_t start, end;
    bool have_work, done, started;
} SfApplyWorker;

static SfApplyWorker g_apply_worker;

/* Below this W it's not worth the handoff — just run it on the caller. */
#define SF_APPLY_PARALLEL_MIN 2048

static void *sf_apply_worker_fn(void *opaque)
{
    SfApplyWorker *w = opaque;
    qemu_mutex_lock(&w->mtx);
    for (;;) {
        while (!w->have_work) {
            qemu_cond_wait(&w->cond_work, &w->mtx);
        }
        const SfApplyPage *pages = w->pages;
        size_t psize = w->psize;
        size_t s = w->start, e = w->end;
        qemu_mutex_unlock(&w->mtx);

        sf_copy_slice(pages, s, e, psize);

        qemu_mutex_lock(&w->mtx);
        w->have_work = false;
        w->done = true;
        qemu_cond_signal(&w->cond_done);
    }
    /* ponytail: never signalled to exit; the thread lives for the process and is
     * reaped at exit (blocked in cond_wait). Add teardown only if a clean
     * shutdown path ever needs it. */
}

/* Apply W: resolve all (host,src) pairs first, then split memcpy into two
 * contiguous halves. The background worker takes the upper half, the caller
 * runs the lower half, then waits for the worker. */
static void sf_apply_w(SfSnapNode *dst, const SfPageKey *keys, size_t n)
{
    size_t psize = qemu_real_host_page_size();
    SfApplyPage *pages;
    bool split = getenv("SF_APPLY_SPLIT") != NULL;
    uint64_t t0 = 0, t1 = 0, t2 = 0;

    if (!n) {
        return;
    }
    pages = g_new(SfApplyPage, n);
    if (split) { t0 = sf_now_ns(); }
    sf_apply_resolve(dst, keys, pages, n);
    if (split) { t1 = sf_now_ns(); }

    if (n < SF_APPLY_PARALLEL_MIN) {
        sf_copy_slice(pages, 0, n, psize);
        if (split) { t2 = sf_now_ns(); }
        goto out;
    }

    {
        SfApplyWorker *w = &g_apply_worker;
        if (!w->started) {
            qemu_mutex_init(&w->mtx);
            qemu_cond_init(&w->cond_work);
            qemu_cond_init(&w->cond_done);
            qemu_thread_create(&w->thread, "sf-apply", sf_apply_worker_fn, w,
                               QEMU_THREAD_JOINABLE);
            w->started = true;
        }

        size_t mid = n / 2;
        qemu_mutex_lock(&w->mtx);
        w->pages = pages; w->psize = psize; w->start = mid; w->end = n;
        w->done = false; w->have_work = true;
        qemu_cond_signal(&w->cond_work);
        qemu_mutex_unlock(&w->mtx);

        sf_copy_slice(pages, 0, mid, psize);   /* caller does the lower half */

        qemu_mutex_lock(&w->mtx);
        while (!w->done) {
            qemu_cond_wait(&w->cond_done, &w->mtx);
        }
        qemu_mutex_unlock(&w->mtx);
        if (split) { t2 = sf_now_ns(); }
    }

out:
    if (split) {
        fprintf(stderr, "sf-time: apply-split resolve=%.1fus copy=%.1fus "
                "(n=%zu, %.3f+%.3f us/page)\n",
                (t1 - t0) / 1000.0, (t2 - t1) / 1000.0, n,
                (t1 - t0) / 1000.0 / n, (t2 - t1) / 1000.0 / n);
    }
    g_free(pages);
}

/*
 * RAM-only delta-restore (no device, no cpu/clock tail): build W, apply via
 * resolve, reset (INV-B), set sf_active=dst. For selftest + as the RAM core the
 * production restore wraps (production interleaves device replay between
 * sf_build_restore_w and sf_apply_w — plan §3 step 3).
 */
int sf_snap_delta_restore(uint32_t dst_id, Error **errp)
{
    SfSnapNode *src = sf_active, *dst, *L;
    SfWAcc acc = { 0 };
    size_t n;

    if (!src) {
        error_setg(errp, "sf_snap_delta_restore: no active snapshot");
        return -EINVAL;
    }
    dst = (dst_id == src->id) ? src : sf_node_find(dst_id);
    if (!dst) {
        error_setg(errp, "sf_snap_delta_restore: node id %u not found", dst_id);
        return -ENOENT;
    }

    L = sf_node_lca(src, dst);
    n = sf_build_restore_w(src, dst, L, &acc);
    sf_apply_w(dst, acc.keys, n);
    g_free(acc.keys);

    sf_dirty_clear_collected();
    if (src == dst) {
        sf_dirty_reset_ring();
    } else {
        sf_dirty_force_reset_ring();
    }
    sf_active = dst;
    return 0;
}

/*
 * Snapshot core — ROOT (full RAM shadow + device preparse) or non-root (eager
 * diff save + device preparse), at ONE coherent instant. Caller owns quiescence.
 * Does NOT touch clocks (path-specific; see file header). Sets sf_active.
 *
 * T2 device capture = re-preparse into the node (correct, pays the preparse cost
 * per save). T4 (plan 2026-07-06-05) evolves non-root capture into the cheap
 * reverse-memcpy from live; root stays preparse (one-time table-build cost).
 *
 * 方案 B (plan 07): when @keep_stream, the captured stock vmstate stream is
 * retained in node->dev.stream so sf_snap_persist can write <id>.dev. The
 * control-channel plan makes retention the default for every snapshot, including
 * RUN: promotion/cold-start may happen after creation, and the stream is only
 * KB-scale. A future GC/promote API may explicitly drop it and mark the subtree
 * non-promotable.
 */
static int sf_snap_dev_capture(SfSnapNode *node, bool keep_stream)
{
    Error *err = NULL;
    uint8_t *bytes;
    size_t len;

    if (sf_device_stream_capture(&bytes, &len, &err) < 0) {
        monitor_printf(NULL, "sf: WARNING device stream capture failed: %s "
                       "(RAM snapshot still taken)\n", error_get_pretty(err));
        error_free(err);
        node->dev.have = false;
        return 0;
    }
    if (sf_preparse_stream(bytes, len, &node->dev.tables, &err) < 0) {
        monitor_printf(NULL, "sf: WARNING device preparse failed: %s "
                       "(RAM snapshot still taken)\n", error_get_pretty(err));
        error_free(err);
        g_free(bytes);
        node->dev.have = false;
        return 0;
    }
    if (!sf_validate_hot_profile(NULL, &node->dev.tables)) {
        sf_replay_tables_destroy(&node->dev.tables);
        g_free(bytes);
        node->dev.have = false;
        return -EIO;
    }
    if (keep_stream) {
        node->dev.stream = bytes;
        node->dev.stream_len = len;
    } else {
        g_free(bytes);
    }
    node->dev.have = true;
    return 0;
}

int sf_snap_save(SfSnapKind kind, Error **errp)
{
    Error *err = NULL;
    SfSnapNode *node;
    bool timing = sf_timing();
    uint64_t ta = 0, tb = 0, tc = 0;

    /*
     * T8: the tree is no longer restricted to a chain — save() may branch off
     * the active node (build a sibling of an existing child). The data
     * structure, LCA, and delta-restore have been tree-shaped since T1; the
     * first-version chain check (plan -04 §4) is dropped now that tree selftest
     * E covers cross-sibling restore. delete() still protects the active node
     * and its ancestors.
     */

    if (kind == SF_SNAP_ROOT) {
        if (timing) { ta = sf_now_ns(); }
        node = sf_snap_ram_root(&err);
        if (!node) {
            error_propagate(errp, err);
            return -EIO;
        }
        if (timing) { tb = sf_now_ns(); }
        if (sf_snap_dev_capture(node, true) < 0) {   /* root keeps its stream */
            sf_node_destroy(node);
            sf_dirty_destroy();
            sf_blocks_destroy();
            sf_active = NULL;
            error_setg(errp, "sf_snap_save: hot-profile guard failed");
            return -EIO;
        }
        if (sf_timing() && sf_root_selfcheck(NULL) < 0) {
            error_setg(errp, "sf_snap_save: root selfcheck failed");
            return -EIO;
        }
        if (timing) {
            tc = sf_now_ns();
            size_t mbytes = 0;
            for (size_t i = 0; i < node->dev.tables.n_mblocks; i++) {
                mbytes += node->dev.tables.mblocks[i].size;
            }
            fprintf(stderr,
                    "sf-time: snapshot root ram-shadow=%.1fus device=%.1fus "
                    "(mblocks=%zu/%zuB gets=%zu posts=%zu)\n",
                    (tb - ta) / 1000.0, (tc - tb) / 1000.0,
                    node->dev.tables.n_mblocks, mbytes,
                    node->dev.tables.n_gets, node->dev.tables.n_posts);
        }
        monitor_printf(NULL, "sf: snapshot ok: root id=%u RAM shadowed; device %s "
                       "(mblocks=%zu gets=%zu posts=%zu)\n", node->id,
                       node->dev.have ? "ok" : "SKIPPED",
                       node->dev.tables.n_mblocks, node->dev.tables.n_gets,
                       node->dev.tables.n_posts);
        return 0;
    }

    /* ---- non-root: eager diff save ---- */
    if (!sf_active) {
        error_setg(errp, "sf_snap_save: no active node (build root first)");
        return -EINVAL;
    }
    /* T0 (plan -04 §2 step 0): capture the boundary TSC before collect. The
     * terminal caller did cpu_synchronize_state so this reflects T0; stored for
     * T4's per-node refreeze. */
    uint64_t t0_tsc = (kvm_enabled() && current_cpu) ? sf_kvm_read_tsc(current_cpu) : 0;

    if (timing) { ta = sf_now_ns(); }
    node = sf_snap_build_diff(sf_active, kind, &err);
    if (!node) {
        error_propagate(errp, err);
        return -EIO;
    }
    node->kvm.tsc = t0_tsc;
    if (timing) { tb = sf_now_ns(); }
    /* Keep the stock vmstate stream for every snapshot. It is the only data
     * needed to re-preparse this node after a later host promote/cold-start. */
    if (sf_snap_dev_capture(node, true) < 0) {
        sf_node_destroy(node);
        error_setg(errp, "sf_snap_save: hot-profile guard failed");
        return -EIO;
    }
    sf_active = node;
    if (timing) {
        tc = sf_now_ns();
        fprintf(stderr,
                "sf-time: snapshot diff ram=%.1fus device=%.1fus "
                "(diff=%u pages, device mblocks=%zu gets=%zu posts=%zu)\n",
                (tb - ta) / 1000.0, (tc - tb) / 1000.0,
                node->ram.n_pages, node->dev.tables.n_mblocks,
                node->dev.tables.n_gets, node->dev.tables.n_posts);
    }
    monitor_printf(NULL, "sf: snapshot ok: %s id=%u diff=%u pages; device %s "
                   "(mblocks=%zu gets=%zu posts=%zu)\n",
                   node->kind == SF_SNAP_RUN ? "run" : "layer", node->id,
                   node->ram.n_pages, node->dev.have ? "ok" : "SKIPPED",
                   node->dev.tables.n_mblocks, node->dev.tables.n_gets,
                   node->dev.tables.n_posts);
    return 0;
}

/*
 * Restore core — delta-restore (plan -04 §3): build W (collect ∪ HOT ∪ src/dst
 * path diffs), device replay, apply W via owner resolution, push CPU regs +
 * forced TSC rewind, reset (INV-B). Caller owns quiescence + sets sf_active.
 * Does NOT do the kvmclock/vapic tail (HMP via vm_start; terminal via
 * sf_apply_clock_tail). @debug optional.
 */
static void sf_snap_restore_core(SfSnapNode *dst, SfReplayDebug *debug)
{
    SfSnapNode *src = sf_active, *L;
    SfWAcc acc = { 0 };
    size_t n;
    bool timing = sf_timing();
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;

    if (timing) { t0 = sf_now_ns(); }

    /* Step 1-2: LCA + build the restore set W (collect ∪ HOT ∪ path(src→L] ∪
     * path(dst→L]). collect() is called inside sf_build_restore_w. */
    L = sf_node_lca(src, dst);
    n = sf_build_restore_w(src, dst, L, &acc);
    if (timing) { t1 = sf_now_ns(); }

    /* Step 3: device replay (registers; restores env->tsc etc. for step 5). */
    if (dst->dev.have) {
        if (debug) {
            sf_replay_with_debug(&dst->dev.tables, debug);
        } else {
            sf_replay(&dst->dev.tables);
        }
    }
    if (timing) { t2 = sf_now_ns(); }

    /* Step 4: RAM delta-restore — copy each W page from the ≤dst nearest owner. */
    sf_apply_w(dst, acc.keys, n);
    g_free(acc.keys);
    if (timing) { t3 = sf_now_ns(); }

    /* Step 5: push the replayed CPUState into the KVM vCPU + force the TSC
     * rewind. CPU_FOREACH future-proofs for multi-vCPU (DP-A). */
    {
        CPUState *cpu;
        CPU_FOREACH(cpu) {
            cpu_synchronize_post_init(cpu);
            if (kvm_enabled() && !sf_skip_tsc()) {
                sf_kvm_refreeze_tsc(cpu);
            }
        }
    }

    /* Step 7: INV-B — clear the vector + reset the ring for the next generation. */
    sf_dirty_clear_collected();
    if (src == dst) {
        sf_dirty_reset_ring();
    } else {
        sf_dirty_force_reset_ring();
    }

    if (timing) {
        t4 = sf_now_ns();
        fprintf(stderr,
                "sf-time: restore build_w=%.1fus device=%.1fus ram=%.1fus "
                "cpusync+reset=%.1fus total=%.1fus (W=%zu)\n",
                (t1 - t0) / 1000.0, (t2 - t1) / 1000.0, (t3 - t2) / 1000.0,
                (t4 - t3) / 1000.0, (t4 - t0) / 1000.0, n);
    }
    monitor_printf(NULL, "sf: restore ok: dst=%u device=%s ram W=%zu\n",
                   dst->id, dst->dev.have ? "replayed" : "SKIPPED", n);
}

/*
 * Minimal-set tail (ARCHITECTURE §4.4) that vm_start's handlers used to provide.
 * Terminal path only (no vm_start here): re-anchor kvmclock (KVM_SET_CLOCK +
 * KVMCLOCK_CTRL) + reactivate vapic (TPR acceleration). After RAM rollback
 * (kvmclock re-derives from the rolled-back pvclock page). SF_CP_SKIP_KVMCLOCK
 * omits the kvmclock re-anchor so the T-CLK gate proves teeth.
 */
static void sf_apply_clock_tail(SfSnapNode *dst)
{
    void *kc, *vp;

    if (!dst->dev.have) {
        return;
    }
    kc = sf_find_opaque(&dst->dev.tables, "kvmclock");
    vp = sf_find_opaque(&dst->dev.tables, "kvm-tpr-opt");
    if (kc && !sf_skip_kvmclock()) {
        kvmclock_sf_restore(kc);
    }
    if (vp) {
        vapic_sf_reactivate(vp);
    }
}

/* @debug (optional, NULL = normal) injects a device-replay skip so a phase1.5
 * gate can prove teeth. dst may be any node in the tree (delta-restore). */
int sf_snap_restore(uint32_t dst_id, const SfReplayDebug *debug, Error **errp)
{
    SfSnapNode *dst;

    if (!sf_active) {
        error_setg(errp, "sf_snap_restore: no snapshot (run sf_snapshot first)");
        return -EINVAL;
    }
    dst = (dst_id == sf_active->id) ? sf_active : sf_node_find(dst_id);
    if (!dst) {
        error_setg(errp, "sf_snap_restore: node id %u not found", dst_id);
        return -ENOENT;
    }

    sf_snap_restore_core(dst, (SfReplayDebug *)debug);
    sf_apply_clock_tail(dst);
    sf_active = dst;
    return 0;
}

int sf_snap_delete(uint32_t id, Error **errp)
{
    SfSnapNode *n, *root;

    if (!sf_active) {
        error_setg(errp, "sf_snap_delete: no snapshot tree");
        return -EINVAL;
    }
    root = sf_active;
    while (root->parent) { root = root->parent; }
    if (id == root->id) {
        error_setg(errp, "sf_snap_delete: refusing to delete root");
        return -EPERM;
    }
    n = sf_node_find(id);
    if (!n) {
        error_setg(errp, "sf_snap_delete: node id %u not found", id);
        return -ENOENT;
    }
    /* active and its ancestors are undeletable (plan -04 §4). */
    for (SfSnapNode *a = sf_active; a; a = a->parent) {
        if (a == n) {
            error_setg(errp, "sf_snap_delete: refusing to delete active node "
                       "or an ancestor (id %u)", id);
            return -EPERM;
        }
    }
    sf_node_destroy(n);
    return 0;
}

static void sf_snap_tree_rec(Monitor *mon, SfSnapNode *n)
{
    SfSnapNode *child;

    monitor_printf(mon, "sf: node id=%u kind=%d state=%d depth=%u dev=%s%s\n",
                   n->id, n->kind, n->state, n->depth,
                   n->dev.have ? "yes" : "no",
                   (n == sf_active) ? " (ACTIVE)" : "");
    QLIST_FOREACH(child, &n->children, sibling) {
        sf_snap_tree_rec(mon, child);   /* full DFS: branches, not just leftmost */
    }
}

void sf_snap_tree(Monitor *mon)
{
    SfSnapNode *root;
    if (!sf_active) {
        monitor_printf(mon, "sf: no snapshot tree\n");
        return;
    }
    root = sf_active;
    while (root->parent) { root = root->parent; }
    sf_snap_tree_rec(mon, root);
}
