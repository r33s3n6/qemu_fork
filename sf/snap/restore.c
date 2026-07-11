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
#include "sf/track/tracker.h"
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
/* Thread CPU clock: advances only while this thread is on-CPU. Concurrent
 * oversubscription: wall includes preemption; thread-cputime is the cost
 * attribution mirror of guest_active_cpu (see arch/perf-metrics.md §1). */
static uint64_t sf_now_thread_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
/* Pure guest-mode CPU time summed over vCPU threads, in ns. Reads gtime
 * (field 43 of /proc/self/task/<tid>/stat) — the kernel's separate accounting
 * of non-root guest execution. Within a KVM_RUN bracket, guest_active_cpu =
 * gtime(pure guest) + in-kernel KVM exit handling (npf/dirty/mmu) + halt-poll
 * spin; so guest_active_cpu - guest_only - halt_poll isolates the "kvm 相关逻辑".
 * Tick-resolution (USER_HZ): noisy per-round, exact once aggregated over a wave.
 * ponytail: /proc read on the restore boundary (not the guest hot path); returns
 * 0 if unreadable, which the runner surfaces as "gtime not populated". */
static uint64_t sf_restore_guest_time_ns(void)
{
    static long hz;
    if (hz == 0) {
        hz = sysconf(_SC_CLK_TCK);
    }
    if (hz <= 0) {
        return 0;
    }
    uint64_t ticks = 0;
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        char path[64], buf[1024];
        snprintf(path, sizeof(path), "/proc/self/task/%d/stat", cpu->thread_id);
        FILE *f = fopen(path, "re");
        if (!f) {
            continue;
        }
        size_t got = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        if (got == 0) {
            continue;
        }
        buf[got] = '\0';
        /* comm (field 2) may hold spaces/parens; skip past its closing ')'. */
        char *p = strrchr(buf, ')');
        if (!p) {
            continue;
        }
        int field = 2;  /* ')' closed comm; next token is field 3 (state) */
        char *save = NULL;
        for (char *tok = strtok_r(p + 1, " ", &save); tok;
             tok = strtok_r(NULL, " ", &save)) {
            if (++field == 43) {  /* guest_time */
                ticks += strtoull(tok, NULL, 10);
                break;
            }
        }
    }
    return ticks * (1000000000ULL / (uint64_t)hz);
}

static bool sf_restore_exec_base_valid;
static uint64_t sf_restore_last_guest_active_wall_ns;
static uint64_t sf_restore_last_guest_active_cpu_ns;
static uint64_t sf_restore_last_pf_taken;
static uint64_t sf_restore_last_halt_wait_ns;
static uint64_t sf_restore_last_halt_poll_ns;
static uint64_t sf_restore_last_guest_time_ns;

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
 * Root-creation self-check (teeth for the block-table / key / resolve machinery):
 * for every registered block, the host<->key round-trip must hold and root
 * owner-resolution must land on the root backing page for that host page. Cheap
 * (O(blocks)); runs only under SF_TIME so it never weighs on a real run.
 * Failures abort the snapshot.
 */
static int sf_root_selfcheck(Monitor *mon)
{
    SfSnapNode *root = sf_active;
    while (root && root->parent) { root = root->parent; }

    for (size_t i = 0; i < sf_n_blocks; i++) {
        SfBlockDesc *b = &sf_blocks[i];
        uint8_t *host = (uint8_t *)b->host;
        SfPageKey key;
        uint8_t *back, *page;

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
        /* resolve(root, key) must land on the root backing for this host page. */
        page = sf_rootstore_page(root ? &root->ram : NULL, key);
        if (!page || sf_resolve(sf_active, key) != page) {
            monitor_printf(mon, "sf: selfcheck FAIL block %zu resolve != root "
                           "backing\n", i);
            return -EIO;
        }
    }
    return 0;
}

/* ---- restore-tracker session (plan 2026-07-08-03 R4) --------------------- *
 * One flat restore-store per snapshot tree, armed over the block registry. The
 * store holds the persistent collect∪HOT set; the snap layer adds cross-node
 * path pages at restore time. Resolve is injected: host → key → sf_resolve, with
 * NO_RESTORE pages resolving to NULL (never rolled back). */

static SfRestoreStore *g_snap_store;
static SfBlockReg     *g_snap_blockregs;   /* borrowed by g_snap_store */

static void sf_snap_set_active_node(SfSnapNode *node)
{
    sf_active = node;
    if (sf_track_active()) {
        sf_track_set_active(node);
    }
}

static uint8_t *sf_snap_resolve_cb(void *target, void *host, void *user)
{
    SfPageKey key;
    (void)user;
    if (sf_excluded(host)) {
        return NULL;   /* NO_RESTORE: not saved, not rolled back */
    }
    if (!sf_host_to_key_safe(host, &key)) {
        return NULL;
    }
    return sf_resolve((SfSnapNode *)target, key);
}

static SfFlatPolicy sf_snap_flat_policy(void)
{
    const char *s = getenv("SF_BLIND");
    return (s && *s) ? SF_FLAT_BLIND : SF_FLAT_FULL;
}

void sf_snap_tracker_disarm(void)
{
    sf_track_end();
    if (g_snap_store) {
        g_snap_store->ops->free(g_snap_store);
        g_snap_store = NULL;
    }
    g_free(g_snap_blockregs);
    g_snap_blockregs = NULL;
}

int sf_snap_tracker_arm(SfSnapNode *active, Error **errp)
{
    if (!sf_kvm_dirty_ring_enabled()) {
        error_setg(errp, "KVM dirty ring not enabled "
                   "(need -accel kvm,dirty-ring-size=N)");
        return -ENOTSUP;
    }
    sf_snap_tracker_disarm();   /* idempotent: drop any prior session */

    g_snap_blockregs = g_new(SfBlockReg, sf_n_blocks);
    for (size_t i = 0; i < sf_n_blocks; i++) {
        g_snap_blockregs[i].host = sf_blocks[i].host;
        g_snap_blockregs[i].len  = sf_blocks[i].len;
    }
    g_snap_store = sf_flat_store_new(g_snap_blockregs, sf_n_blocks,
                                     sf_snap_resolve_cb, NULL,
                                     sf_snap_flat_policy());
    sf_track_begin(g_snap_blockregs, sf_n_blocks, sf_snap_resolve_cb, NULL,
                   g_snap_store);
    sf_track_set_active(active);
    return 0;
}

/* ---- RAM-only cores (selftest / building blocks; no device, no guard) ----
 * Production save/restore wrap these with device capture (T4) + clock tail.
 * Exposed so the RAM diff/delta mechanics are testable under pc KVM, where the
 * microvm hot-profile guard refuses the full preparse. */

/*
 * RAM-only root: full-shadow the live RAM into the root backing, arm the restore
 * tracker over the block registry, set sf_active. No device preparse, no
 * hot-profile guard. The selftest and the production ROOT save both build on this
 * (production adds preparse+guard+kvm.tsc).
 */
SfSnapNode *sf_snap_ram_root(Error **errp)
{
    Error *err = NULL;
    SfSnapNode *node;
    const char *root_dir = getenv("SF_ROOT_DIR");
    char *root_path = NULL;

    /* Drop any previous tree + tracker (root teardown disarms the tracker). */
    if (sf_active) {
        SfSnapNode *root = sf_active;
        while (root->parent) { root = root->parent; }
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

    /* The root backing IS the restore source (sf_resolve's root兜底 reads it). */
    for (size_t i = 0; i < sf_n_blocks; i++) {
        SfBlockDesc *b = &sf_blocks[i];
        memcpy(node->ram.data + b->root_off, b->host, b->len);
    }

    if (sf_snap_tracker_arm(node, &err) < 0) {
        error_propagate(errp, err);
        sf_node_destroy(node);
        sf_blocks_destroy();
        return NULL;
    }
    if (kvm_enabled() && current_cpu) {
        node->kvm.tsc = sf_kvm_read_tsc(current_cpu);
    }
    sf_snap_set_active_node(node);
    /* Arm the tripwire: a snapshot tree now exists, host writes to its RAM
     * must be caught. Stays armed until the tree is torn down (sf_node_destroy
     * on the root disarms). */
    sf_tripwire_arm(true);
    return node;
}

/*
 * RAM-only non-root diff: the dirtied set since the parent (the tracker's
 * persistent plan) becomes this node's diff. Copy the live pages into a fresh
 * diff store, keyed + sorted for bsearch.
 *
 * @activate (default true for the snapshot op): re-baseline the tracker to this
 * new node via set_active — reprotect + clear, so the next generation tracks dirt
 * relative to @node, not the parent. Pass false to build a diff WITHOUT switching
 * the tracked baseline (host-controlled). Does NOT set the global sf_active (the
 * caller decides — production save does, after device capture; selftest controls it).
 */
SfSnapNode *sf_snap_build_diff(SfSnapNode *parent, SfSnapKind kind, bool activate,
                               SfSnapDiffTiming *timing_out, Error **errp)
{
    size_t psize = qemu_real_host_page_size();
    /* Default: confirm the WHOLE tracked set against the parent (memcmp ≈0.2-0.3us/
     * page, cheaper than a page fault; drops ~9-26% write-same pages from the diff).
     * SF_DIFF_UNSURE_ONLY restricts the confirm to the carried/unsure prefix
     * [0,unsure_n) — the pos-split fast path for save-latency-sensitive workloads. */
    bool memcmp_all = getenv("SF_DIFF_UNSURE_ONLY") == NULL;
    bool timing = timing_out != NULL;
    SfSnapNode *node;
    const SfRestorePlan *plan;
    SfPageKey *keys;
    size_t nk = 0;
    /* Buckets: plan | memcmp | save | rebase (DIFF_STAT is outside all four). */
    uint64_t t_plan0 = 0, t_plan1 = 0, t_mc0 = 0, t_mc1 = 0;
    uint64_t t_save1 = 0, t_rebase1 = 0;

    if (timing_out) {
        memset(timing_out, 0, sizeof(*timing_out));
    }
    if (!parent) {
        error_setg(errp, "sf_snap_build_diff: parent required");
        return NULL;
    }
    if (!sf_track_active()) {
        error_setg(errp, "sf_snap_build_diff: no active tracker (build root first)");
        return NULL;
    }

    /* plan = drain + plan (dirty set vs parent). */
    if (timing) { t_plan0 = sf_now_ns(); }
    sf_track_drain();
    plan = sf_track_plan(parent);
    if (timing) { t_plan1 = sf_now_ns(); }

    /* SF_DIFF_STAT (debug, opt-in): outside the four save buckets. */
    if (getenv("SF_DIFF_STAT")) {
        uint64_t ts = sf_now_ns();
        size_t un_t = 0, un_s = 0, ni_t = 0, ni_s = 0;
        for (size_t i = 0; i < plan->n; i++) {
            const uint8_t *s = plan->pages[i].src;
            bool same = s && memcmp(plan->pages[i].dst, s, psize) == 0;
            if (i < plan->unsure_n) { un_t++; un_s += same; }
            else                    { ni_t++; ni_s += same; }
        }
        /* memcmp_all_us = cost of memcmp-ing the WHOLE set (what SF_DIFF_MEMCMP_ALL
         * would add to a save); dropped_same = pages it would remove from the diff. */
        fprintf(stderr, "sf-diff-stat: parent=%u n=%zu unsure_n=%zu "
                "unsure_same=%zu/%zu net_inc_same=%zu/%zu memcmp_all_us=%.1f\n",
                parent->id, plan->n, plan->unsure_n, un_s, un_t, ni_s, ni_t,
                (sf_now_ns() - ts) / 1000.0);
    }

    /* memcmp = key select (drop write-same) + qsort. The plan is already deduped
     * (membership bitmap), so a plain sort suffices — no uniq pass. */
    if (timing) { t_mc0 = sf_now_ns(); }
    keys = g_new(SfPageKey, plan->n ? plan->n : 1);
    for (size_t i = 0; i < plan->n; i++) {
        SfPageKey k;
        void *host = plan->pages[i].dst;
        const uint8_t *src = plan->pages[i].src;
        if (sf_excluded(host)) {
            continue;   /* NO_RESTORE: not diffed */
        }
        /* Diff dedup vs parent (plan 09-01 §4 D): drop pages that already equal the
         * parent — restore resolves through to the parent for them anyway, so they
         * only bloat the diff. KVM dirty = "written", not "changed", so even the
         * net-increment [unsure_n,n) holds write-same pages (~8-22% measured); the
         * default memcmps the whole set to catch them. SF_DIFF_UNSURE_ONLY limits it
         * to the carried prefix [0,unsure_n) (the ones restored back → most likely
         * ==parent) to save memcmp. Correctness identical (dropped pages == parent). */
        if ((memcmp_all || i < plan->unsure_n) && src &&
            memcmp(host, src, psize) == 0) {
            continue;
        }
        if (sf_host_to_key_safe(host, &k)) {
            keys[nk++] = k;
        }
    }
    qsort(keys, nk, sizeof(SfPageKey), sf_key_cmp);
    if (timing) { t_mc1 = sf_now_ns(); }

    /* save = ramstore create + page copies. */
    node = sf_node_new(parent, kind);
    if (sf_ramstore_create_anon(&node->ram, (uint32_t)nk) < 0) {
        error_setg(errp, "sf_snap_build_diff: ramstore oom");
        sf_node_destroy(node);
        g_free(keys);
        return NULL;
    }
    for (size_t i = 0; i < nk; i++) {
        uint8_t *host = sf_key_to_host(keys[i]);
        node->ram.index[i] = keys[i];
        if (host) {
            memcpy(node->ram.data + i * psize, host, psize);
        }
    }
    g_free(keys);
    if (timing) { t_save1 = sf_now_ns(); }

    /* Re-baseline the tracker to this new node (reprotect + clear) so the next
     * generation tracks dirt relative to @node. set_active (not after_restore) so
     * BLIND re-bases too. @activate=false leaves the tracked baseline on the parent. */
    if (activate) {
        sf_track_set_active(node);
    }
    if (timing) {
        t_rebase1 = sf_now_ns();
        timing_out->plan_ns = t_plan1 - t_plan0;
        timing_out->memcmp_ns = t_mc1 - t_mc0;
        timing_out->save_ns = t_save1 - t_mc1;
        timing_out->rebase_ns = t_rebase1 - t_save1;
    }
    return node;
}

/* ---- restore apply (RAM) -------------------------------------------------- *
 * The tracker's plan(dst) gives the live-dirty set already resolved to dst. For
 * a cross-node restore (src != dst) the src/dst-side path layers must also roll
 * to dst — append those pages (resolved to dst) into a scratch array.
 *
 * KNOWN COST (roadmap I.4, deferred — do NOT read this as "fine"): this appends
 * every path layer's whole index WITHOUT dedup, so a page appearing in several
 * layers (or in both plan and path) is resolved + copied once per occurrence.
 * Work is ∝ Σ(path-layer index sizes) × chain depth, NOT ∝ distinct divergent
 * pages — this drops the old sort_uniq dedup and thereby violates Agamotto
 * Delta-Restore (∝ divergent pages, depth-independent). Copies stay correct
 * (idempotent: same src for the same dst). Left unoptimized only because
 * cross-node is the non-hot rebuild path; its speed is UNMEASURED. Redesign per
 * roadmap I.4 (reference Agamotto) when it turns hot or R5 shows it drags
 * races/s — not with a bolt-on dedup. */
static size_t sf_push_path_pages(SfSnapNode *target, const SfRamStore *s,
                                 SfPlanPage *out)
{
    size_t k = 0;
    if (!s->index) {
        return 0;
    }
    for (uint32_t i = 0; i < s->n_pages; i++) {
        uint8_t *host = sf_key_to_host(s->index[i]);
        if (!host || sf_excluded(host)) {
            continue;
        }
        out[k].dst = host;
        out[k].src = sf_track_resolve(target, host);
        k++;
    }
    return k;
}

/*
 * A2 (plan 09-03): classify each restore page's owner layer by pointer range
 * into the node chain. Buckets:
 *   root     — root store (shared base ceiling under root-sharing)
 *   shared   — SCHEMA/PREFIX (sharing target under prefix-sharing)
 *   private  — CLEAN/RUN/other worker-private layers
 * Debug-gate only (caller gates on SF_TIME); not on the memcpy hot path.
 */
typedef struct {
    size_t root;
    size_t shared;
    size_t private;
    size_t null_src;
} SfRestoreSrcStat;

static void sf_src_stat_one(SfSnapNode *dst, const uint8_t *src,
                            SfRestoreSrcStat *st)
{
    size_t psize = qemu_real_host_page_size();

    if (!src) {
        st->null_src++;
        return;
    }
    for (SfSnapNode *n = dst; n; n = n->parent) {
        if (!n->parent) {
            /* root: flat rootstore; span = map_len */
            if (n->ram.data && n->ram.map_len &&
                src >= n->ram.data &&
                (size_t)(src - n->ram.data) < n->ram.map_len) {
                st->root++;
                return;
            }
        } else if (n->ram.data && n->ram.n_pages) {
            size_t span = (size_t)n->ram.n_pages * psize;
            if (src >= n->ram.data && (size_t)(src - n->ram.data) < span) {
                /* shared = SCHEMA/PREFIX kinds (intended labels) OR any
                 * FILE-backed layer (cold-start MAP_SHARED page-cache share;
                 * terminal path currently tags all non-root as RUN). */
                if (n->kind == SF_SNAP_SCHEMA || n->kind == SF_SNAP_PREFIX ||
                    n->ram.backing == SF_BACKING_FILE) {
                    st->shared++;
                } else {
                    st->private++;
                }
                return;
            }
        }
    }
    /* unmatched pointer: treat as private (unknown owner) so totals still sum */
    st->private++;
}

static void sf_src_stat_pages(SfSnapNode *dst, const SfPlanPage *pages, size_t n,
                              SfRestoreSrcStat *st)
{
    for (size_t i = 0; i < n; i++) {
        sf_src_stat_one(dst, pages[i].src, st);
    }
}

/* Apply the plan (+ cross-node path pages) rolling live RAM back to dst; returns
 * the number of pages applied. */
static size_t sf_restore_apply_ram(SfSnapNode *dst, SfSnapNode *src,
                                   const SfRestorePlan *plan)
{
    SfSnapNode *L;
    SfPlanPage *scratch;
    size_t cap, ns;

    if (src == dst) {
        sf_track_apply(plan->pages, plan->n);   /* in-place fast path */
        return plan->n;
    }

    L = sf_node_lca(src, dst);
    cap = plan->n;
    for (SfSnapNode *n = src; n != L; n = n->parent) { cap += n->ram.n_pages; }
    for (SfSnapNode *n = dst; n != L; n = n->parent) { cap += n->ram.n_pages; }

    scratch = g_new(SfPlanPage, cap ? cap : 1);
    memcpy(scratch, plan->pages, plan->n * sizeof(SfPlanPage));
    ns = plan->n;
    for (SfSnapNode *n = src; n != L; n = n->parent) {
        ns += sf_push_path_pages(dst, &n->ram, scratch + ns);
    }
    for (SfSnapNode *n = dst; n != L; n = n->parent) {
        ns += sf_push_path_pages(dst, &n->ram, scratch + ns);
    }
    sf_track_apply(scratch, ns);
    g_free(scratch);
    return ns;
}

/*
 * A2 source split for the page set apply just used. Outside the ram timing
 * window (call after t3). In-place = plan only; cross = rebuild plan∪path
 * (setup path, rare vs steady inplace).
 */
static void sf_src_stat_for_restore(SfSnapNode *dst, SfSnapNode *src,
                                    const SfRestorePlan *plan,
                                    SfRestoreSrcStat *st)
{
    memset(st, 0, sizeof(*st));
    if (src == dst) {
        sf_src_stat_pages(dst, plan->pages, plan->n, st);
        return;
    }
    {
        SfSnapNode *L = sf_node_lca(src, dst);
        size_t cap = plan->n, ns;
        SfPlanPage *scratch;

        for (SfSnapNode *n = src; n != L; n = n->parent) {
            cap += n->ram.n_pages;
        }
        for (SfSnapNode *n = dst; n != L; n = n->parent) {
            cap += n->ram.n_pages;
        }
        scratch = g_new(SfPlanPage, cap ? cap : 1);
        memcpy(scratch, plan->pages, plan->n * sizeof(SfPlanPage));
        ns = plan->n;
        for (SfSnapNode *n = src; n != L; n = n->parent) {
            ns += sf_push_path_pages(dst, &n->ram, scratch + ns);
        }
        for (SfSnapNode *n = dst; n != L; n = n->parent) {
            ns += sf_push_path_pages(dst, &n->ram, scratch + ns);
        }
        sf_src_stat_pages(dst, scratch, ns, st);
        g_free(scratch);
    }
}

/*
 * RAM-only delta-restore (no device, no cpu/clock tail): drain, plan, apply,
 * re-baseline, set sf_active=dst. For selftest + as the RAM core the production
 * restore wraps (production interleaves device replay between plan and apply).
 */
int sf_snap_delta_restore(uint32_t dst_id, Error **errp)
{
    SfSnapNode *src = sf_active, *dst;
    const SfRestorePlan *plan;

    if (!src) {
        error_setg(errp, "sf_snap_delta_restore: no active snapshot");
        return -EINVAL;
    }
    dst = (dst_id == src->id) ? src : sf_node_find(dst_id);
    if (!dst) {
        error_setg(errp, "sf_snap_delta_restore: node id %u not found", dst_id);
        return -ENOENT;
    }

    sf_track_drain();
    plan = sf_track_plan(dst);
    sf_restore_apply_ram(dst, src, plan);
    sf_track_after_restore(dst);
    sf_snap_set_active_node(dst);
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
            sf_node_destroy(node);   /* root teardown disarms the tracker */
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

    SfSnapDiffTiming diff_t = {0};
    node = sf_snap_build_diff(sf_active, kind, true, timing ? &diff_t : NULL, &err);
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
    sf_snap_set_active_node(node);
    if (timing) {
        tc = sf_now_ns();
        fprintf(stderr,
                "sf-time: snapshot diff plan=%.1fus memcmp=%.1fus save=%.1fus "
                "rebase=%.1fus device=%.1fus "
                "(diff=%u pages, device mblocks=%zu gets=%zu posts=%zu)\n",
                diff_t.plan_ns / 1000.0, diff_t.memcmp_ns / 1000.0,
                diff_t.save_ns / 1000.0, diff_t.rebase_ns / 1000.0,
                (tc - tb) / 1000.0,
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
 * Restore core — delta-restore (plan 2026-07-08-03 R4b): drain + persistent plan
 * (resolved to dst), device replay, apply RAM (in-place fast path, or plan ∪
 * cross-node path pages), push CPU regs + forced TSC rewind, re-baseline. Caller
 * owns quiescence + sets sf_active. Does NOT do the kvmclock/vapic tail (HMP via
 * vm_start; terminal via sf_apply_clock_tail). @debug optional.
 */
static void sf_snap_restore_core(SfSnapNode *dst, SfReplayDebug *debug)
{
    SfSnapNode *src = sf_active;
    const SfRestorePlan *plan;
    size_t n;
    size_t reprotect_pages = 0;
    bool timing = sf_timing();
    /* Wall buckets (throughput). Thread-CPU siblings for plan/ram/reprotect/total
     * (cost attribution under preemption — plan 09-03 A1). device/cpusync/tsc
     * stay wall-only: short ioctl paths, not the bandwidth/contention story. */
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
    uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0;
    uint64_t t_cpusync = 0, t_tsc = 0, t_reprotect = 0;  /* cpusync/tsc = accum durations */
    uint64_t c_reprotect = 0;
    uint64_t guest_active_wall_us = 0, guest_active_cpu_us = 0, pf_taken = 0;
    uint64_t halt_wait_us = 0, halt_poll_us = 0, guest_only_cpu_us = 0;
    SfRestoreSrcStat src_stat = {0};

    if (timing) {
        t0 = sf_now_ns();
        c0 = sf_now_thread_ns();
    }

    /* Step 1: drain the ring + get the persistent plan, resolved to dst. */
    if (timing) {
        uint64_t wall_now = sf_kvm_guest_active_wall_ns();
        uint64_t cpu_now = sf_kvm_guest_active_cpu_ns();
        uint64_t pf_now = sf_kvm_vcpu_stat_sum("pf_taken");
        uint64_t halt_now = sf_kvm_vcpu_stat_sum("halt_wait_ns");
        uint64_t poll_now = sf_kvm_vcpu_stat_sum("halt_poll_success_ns")
                          + sf_kvm_vcpu_stat_sum("halt_poll_fail_ns");
        uint64_t gtime_now = sf_restore_guest_time_ns();

        if (sf_restore_exec_base_valid) {
            guest_active_wall_us =
                (wall_now - sf_restore_last_guest_active_wall_ns) / 1000;
            guest_active_cpu_us =
                (cpu_now - sf_restore_last_guest_active_cpu_ns) / 1000;
            pf_taken = pf_now - sf_restore_last_pf_taken;
            halt_wait_us = (halt_now - sf_restore_last_halt_wait_ns) / 1000;
            halt_poll_us = (poll_now - sf_restore_last_halt_poll_ns) / 1000;
            guest_only_cpu_us = (gtime_now - sf_restore_last_guest_time_ns) / 1000;
        }
        sf_restore_last_guest_active_wall_ns = wall_now;
        sf_restore_last_guest_active_cpu_ns = cpu_now;
        sf_restore_last_pf_taken = pf_now;
        sf_restore_last_halt_wait_ns = halt_now;
        sf_restore_last_halt_poll_ns = poll_now;
        sf_restore_last_guest_time_ns = gtime_now;
        sf_restore_exec_base_valid = true;
    }
    sf_track_drain();
    plan = sf_track_plan(dst);
    if (timing) {
        t1 = sf_now_ns();
        c1 = sf_now_thread_ns();
    }

    /* Step 2: device replay (registers; restores env->tsc etc. for step 4). */
    if (dst->dev.have) {
        if (debug) {
            sf_replay_with_debug(&dst->dev.tables, debug);
        } else {
            sf_replay(&dst->dev.tables);
        }
    }
    if (timing) {
        t2 = sf_now_ns();
        c2 = sf_now_thread_ns();  /* anchors ram_cpu start (device wall-only) */
    }

    /* Step 3: RAM delta-restore — plan (+ cross-node path pages) → live guest. */
    n = sf_restore_apply_ram(dst, src, plan);
    if (timing) {
        t3 = sf_now_ns();
        c3 = sf_now_thread_ns();
        /* A2: outside ram bucket — does not pollute ram/ram_cpu. */
        sf_src_stat_for_restore(dst, src, plan, &src_stat);
    }

    /* Step 4: push the replayed CPUState into the KVM vCPU, then force the TSC
     * rewind — per-cpu order preserved (post_init writes the TSC up, refreeze
     * pulls it back). cpusync/tsc split by per-cpu accumulation so multi-vCPU
     * interleaving is unchanged vs a single loop. CPU_FOREACH (DP-A). */
    {
        CPUState *cpu;
        CPU_FOREACH(cpu) {
            uint64_t ca = timing ? sf_now_ns() : 0;
            cpu_synchronize_post_init(cpu);
            uint64_t cb = timing ? sf_now_ns() : 0;
            if (kvm_enabled() && !sf_skip_tsc()) {
                sf_kvm_refreeze_tsc(cpu);
            }
            if (timing) {
                t_cpusync += cb - ca;
                t_tsc += sf_now_ns() - cb;
            }
        }
    }
    if (timing) {
        t4 = sf_now_ns();
        c4 = sf_now_thread_ns();
    }

    /* Step 5: re-baseline for the next generation (FULL: reset ring + clear;
     * BLIND: keep pages writable). */
    reprotect_pages = sf_track_after_restore(dst);

    if (timing) {
        t_reprotect = sf_now_ns();
        c_reprotect = sf_now_thread_ns();
        fprintf(stderr,
                "sf-time: restore dst=%u kind=%s plan=%.1fus plan_cpu=%.1fus "
                "device=%.1fus ram=%.1fus ram_cpu=%.1fus "
                "cpusync=%.1fus tsc_refreeze=%.1fus "
                "reprotect=%.1fus reprotect_cpu=%.1fus "
                "total=%.1fus total_cpu=%.1fus (W=%zu) reprotect_pages=%zu "
                "src_root=%zu src_shared=%zu src_private=%zu src_null=%zu "
                "guest_active_wall=%" PRIu64 "us guest_active_cpu=%" PRIu64 "us "
                "pf_taken=%" PRIu64 " "
                "halt_wait=%" PRIu64 "us halt_poll=%" PRIu64 "us "
                "guest_only_cpu=%" PRIu64 "us\n",
                dst->id, src == dst ? "inplace" : "cross",
                (t1 - t0) / 1000.0, (c1 - c0) / 1000.0,
                (t2 - t1) / 1000.0,
                (t3 - t2) / 1000.0, (c3 - c2) / 1000.0,
                t_cpusync / 1000.0, t_tsc / 1000.0,
                (t_reprotect - t4) / 1000.0, (c_reprotect - c4) / 1000.0,
                (t_reprotect - t0) / 1000.0, (c_reprotect - c0) / 1000.0,
                n, reprotect_pages,
                src_stat.root, src_stat.shared, src_stat.private, src_stat.null_src,
                guest_active_wall_us, guest_active_cpu_us, pf_taken,
                halt_wait_us, halt_poll_us, guest_only_cpu_us);
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
    sf_snap_set_active_node(dst);
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
    /* Drop any cached src the store resolved to n, so a later node reusing n's
     * address can't collide with a stale plan_target. */
    sf_track_invalidate(n);
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
