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
    size_t psize = qemu_real_host_page_size();

    for (size_t i = 0; i < sf_n_blocks; i++) {
        SfBlockDesc *b = &sf_blocks[i];
        uint8_t *host = (uint8_t *)b->host;
        uint64_t remain = 0;
        SfPageKey key;
        uint8_t *back, *shadow;

        key = sf_host_to_key(host);
        if (SF_KEY_BLOCK(key) != i || SF_KEY_PFN(key) != 0) {
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
        (void)psize;
    }
    return 0;
}

/*
 * Snapshot core — RAM shadow (engine) + device three-table preparse (into the
 * node) + hot-profile guard, at ONE coherent instant. Caller owns quiescence.
 * Does NOT touch clocks (path-specific; see file header). Creates the node and
 * sets sf_active. @mon may be NULL (terminal path).
 */
int sf_snap_save(SfSnapKind kind, Error **errp)
{
    Error *err = NULL;
    SfSnapNode *node;
    bool timing = sf_timing();
    uint64_t ta = 0, tb = 0, tc = 0;
    int ret;

    /* T1: only ROOT creation is wired (non-root diff save lands in T2). */
    if (kind != SF_SNAP_ROOT) {
        error_setg(errp, "sf_snap_save: non-root save not implemented yet (T2)");
        return -ENOTSUP;
    }
    /* First-version chain policy (plan -04 §4): active already has a child ->
     * refuse; caller must delete the old leaf first. Root has no parent. */
    if (sf_active && !QLIST_EMPTY(&sf_active->children)) {
        error_setg(errp, "sf_snap_save: active node already has a child; "
                   "delete the old leaf first (chain policy)");
        return -EPERM;
    }

    /* Drop any previous tree (engine's sf_dirty_snapshot also drops the old
     * shadow; we drop the node tree + block table). */
    if (sf_active) {
        SfSnapNode *root = sf_active;
        while (root->parent) { root = root->parent; }
        sf_node_destroy(root);
        sf_active = NULL;
    }
    sf_blocks_destroy();

    if (timing) { ta = sf_now_ns(); }

    node = sf_node_new(NULL, SF_SNAP_ROOT);
    ret = sf_blocks_enumerate(&err);
    if (ret < 0) {
        error_propagate(errp, err);
        sf_node_destroy(node);
        return ret;
    }

    /* Boundary T0 (target-agnostic): read the vcpu TSC for the node's kvm
     * capture. The terminal caller does cpu_synchronize_state first so this
     * reflects the boundary value; stored for T4's per-node refreeze. */
    if (kvm_enabled() && current_cpu) {
        node->kvm.tsc = sf_kvm_read_tsc(current_cpu);
    }

    /* RAM side — must succeed. */
    if (sf_dirty_snapshot(&err) < 0) {
        error_propagate(errp, err);
        sf_node_destroy(node);
        sf_blocks_destroy();
        return -EIO;
    }
    if (timing) { tb = sf_now_ns(); }

    /* Device side — best-effort (a preparse gap surfaces loudly without masking
     * RAM). Restore replays only if dev.have. */
    if (sf_preparse(&node->dev.tables, &err) < 0) {
        monitor_printf(NULL, "sf: WARNING device preparse failed: %s "
                       "(RAM snapshot still taken)\n", error_get_pretty(err));
        error_free(err);
        node->dev.have = false;
    } else {
        if (!sf_validate_hot_profile(NULL, &node->dev.tables)) {
            sf_node_destroy(node);
            sf_dirty_destroy();
            sf_blocks_destroy();
            error_setg(errp, "sf_snap_save: hot-profile guard failed");
            return -EIO;
        }
        node->dev.have = true;
    }

    sf_active = node;

    /* T1 teeth: exercise the block-table/key/resolve machinery (SF_TIME only). */
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
                "sf-time: snapshot ram-shadow=%.1fus device-preparse=%.1fus "
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

/*
 * Restore core — device replay + RAM rollback + push CPU regs (incl. forced TSC
 * rewind). Caller owns quiescence. Does NOT do the kvmclock/vapic tail (HMP gets
 * those via vm_start; terminal calls sf_apply_clock_tail). @debug optional.
 */
static void sf_snap_restore_core(SfSnapNode *dst, SfReplayDebug *debug)
{
    bool timing = sf_timing();
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
    uint64_t collected;
    uint32_t copied;

    if (timing) { t0 = sf_now_ns(); }

    /* Device state first (registers), then RAM contents. Order mirrors the
     * M0-S verified path (sf.c:406-455): replay restores env->tsc etc., then
     * post_init pushes into the vcpu. */
    if (dst->dev.have) {
        if (debug) {
            sf_replay_with_debug(&dst->dev.tables, debug);
        } else {
            sf_replay(&dst->dev.tables);
        }
    }
    if (timing) { t1 = sf_now_ns(); }

    /* T1: RAM rollback delegates to the dirty engine (collect ∪ HOT → memcpy
     * from the root shadow). T3 replaces this with delta-restore via sf_resolve
     * over the restore-set union (plan -04 §3). */
    collected = sf_dirty_collect();
    if (timing) { t2 = sf_now_ns(); }
    copied = sf_dirty_restore();
    sf_dirty_reset_ring();
    if (timing) { t3 = sf_now_ns(); }

    /* Push the replayed CPUState back into the KVM vCPU + force the TSC rewind.
     * CPU_FOREACH future-proofs for multi-vCPU (DP-A). */
    {
        CPUState *cpu;
        CPU_FOREACH(cpu) {
            cpu_synchronize_post_init(cpu);
            if (kvm_enabled() && !sf_skip_tsc()) {
                sf_kvm_refreeze_tsc(cpu);
            }
        }
    }

    if (timing) {
        t4 = sf_now_ns();
        fprintf(stderr,
                "sf-time: restore device=%.1fus collect=%.1fus copy+reset=%.1fus "
                "cpusync=%.1fus total=%.1fus (collected=%" PRIu64 " copied=%" PRIu32 ")\n",
                (t1 - t0) / 1000.0, (t2 - t1) / 1000.0, (t3 - t2) / 1000.0,
                (t4 - t3) / 1000.0, (t4 - t0) / 1000.0, collected, copied);
    }
    monitor_printf(NULL, "sf: restore ok: dst=%u device=%s ram collected=%" PRIu64
                   " copied-back=%" PRIu32 "\n", dst->id,
                   dst->dev.have ? "replayed" : "SKIPPED", collected, copied);
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

int sf_snap_restore(uint32_t dst_id, Error **errp)
{
    SfSnapNode *dst;

    if (!sf_active) {
        error_setg(errp, "sf_snap_restore: no snapshot (run sf_snapshot first)");
        return -EINVAL;
    }
    /* T1: only the root/active node exists. T3 will accept any id (delta). */
    dst = (dst_id == sf_active->id) ? sf_active : sf_node_find(dst_id);
    if (!dst) {
        error_setg(errp, "sf_snap_restore: node id %u not found", dst_id);
        return -ENOENT;
    }

    sf_snap_restore_core(dst, NULL);
    sf_apply_clock_tail(dst);
    sf_active = dst;
    return 0;
}

/* Restore with a debug skip-knob (HMP debug=/terminal SF_CP_SKIP). Finds dst by
 * id (root/active for T1) and injects the skip into the device replay. */
int sf_snap_restore_debug(uint32_t dst_id, const SfReplayDebug *debug, Error **errp)
{
    SfSnapNode *dst;

    if (!sf_active) {
        error_setg(errp, "sf_snap_restore: no snapshot");
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

void sf_snap_tree(Monitor *mon)
{
    SfSnapNode *root, *n;
    if (!sf_active) {
        monitor_printf(mon, "sf: no snapshot tree\n");
        return;
    }
    root = sf_active;
    while (root->parent) { root = root->parent; }
    /* flat DFS dump (T1: chain only; real tree print can come later). */
    n = root;
    while (n) {
        monitor_printf(mon, "sf: node id=%u kind=%d state=%d depth=%u "
                       "dev=%s%s\n", n->id, n->kind, n->state, n->depth,
                       n->dev.have ? "yes" : "no",
                       (n == sf_active) ? " (ACTIVE)" : "");
        n = QLIST_FIRST(&n->children);
    }
}