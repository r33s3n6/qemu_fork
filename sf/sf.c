/*
 * sf/ — stalefuzz fresh-backend restore engine.
 * HMP + terminal entry points. Thin glue over the snap layer (sf/snap/) which
 * owns the multi-level snapshot tree; RAM mechanism stays in sf/dirty/, device
 * replay in sf/vmstate_replay/. See ../ARCHITECTURE.md (vendor/qemu/) + sf/snap/node.h.
 *
 * Clean-room: does NOT include or copy QEMU-Nyx code; Nyx is read only as
 * design reference.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qobject/qdict.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"
#include "system/hw_accel.h"
#include "system/kvm.h"
#include "system/runstate.h"
#include "hw/core/cpu.h"
#include "hw/i386/kvm/clock.h"
#include "sf/sf.h"
#include "sf/checkpoint.h"
#include "sf/kvm_tsc.h"
#include "sf/vmstate_replay/preparse.h"
#include "sf/vmstate_replay/replay.h"
#include "sf/snap/node.h"
#include "sf/snap/cold.h"
#include "sf/snap/persist.h"
#include "sf/selftest/selftest.h"

/* ---- device-replay debug skip-knob parsing (HMP debug=/terminal SF_CP_SKIP) ---- */

static bool sf_parse_index(const char *arg, const char *prefix, size_t *out)
{
    const char *s;
    char *end = NULL;
    guint64 v;

    if (!g_str_has_prefix(arg, prefix)) {
        return false;
    }
    s = arg + strlen(prefix);
    if (!*s) {
        return false;
    }
    v = g_ascii_strtoull(s, &end, 10);
    if (*end) {
        return false;
    }
    *out = v;
    return true;
}

static size_t sf_count_pre_posts(const SfReplayTables *t, bool is_pre)
{
    size_t n = 0;
    for (size_t i = 0; i < t->n_posts; i++) {
        if (t->posts[i].is_pre == is_pre) {
            n++;
        }
    }
    return n;
}

static bool sf_parse_restore_debug(Monitor *mon, const char *arg,
                                   const SfReplayTables *t,
                                   SfReplayDebug *debug)
{
    size_t idx = 0;

    memset(debug, 0, sizeof(*debug));
    if (!arg || !*arg) {
        return true;
    }

    if (sf_parse_index(arg, "skip-mblock=", &idx)) {
        if (idx >= t->n_mblocks) {
            monitor_printf(mon, "sf: debug skip-mblock index %zu out of range "
                           "(n=%zu)\n", idx, t->n_mblocks);
            return false;
        }
        debug->skip_mblock = true;
        debug->skip_mblock_index = idx;
        return true;
    }
    if (sf_parse_index(arg, "skip-get=", &idx)) {
        if (idx >= t->n_gets) {
            monitor_printf(mon, "sf: debug skip-get index %zu out of range "
                           "(n=%zu)\n", idx, t->n_gets);
            return false;
        }
        debug->skip_get = true;
        debug->skip_get_index = idx;
        return true;
    }
    if (sf_parse_index(arg, "skip-pre=", &idx)) {
        size_t n_pre = sf_count_pre_posts(t, true);
        if (idx >= n_pre) {
            monitor_printf(mon, "sf: debug skip-pre index %zu out of range "
                           "(n=%zu)\n", idx, n_pre);
            return false;
        }
        debug->skip_pre = true;
        debug->skip_pre_index = idx;
        return true;
    }
    if (sf_parse_index(arg, "skip-post=", &idx)) {
        size_t n_post = sf_count_pre_posts(t, false);
        if (idx >= n_post) {
            monitor_printf(mon, "sf: debug skip-post index %zu out of range "
                           "(n=%zu)\n", idx, n_post);
            return false;
        }
        debug->skip_post = true;
        debug->skip_post_index = idx;
        return true;
    }

    monitor_printf(mon, "sf: unknown debug restore knob '%s'\n", arg);
    return false;
}

/* ---- HMP entries (crutch baseline: vm_stop/vm_start around the core) ---- */

void hmp_sf_snapshot(Monitor *mon, const QDict *qdict)
{
    /*
     * HMP crutch baseline: the vCPU is running on another thread, so quiesce
     * the whole VM around the capture. vm_stop(SAVE_VM) also
     * cpu_synchronize_all_states so CPUState reflects the live KVM vCPU. The
     * terminal path (sf_checkpoint_snapshot) drops this — the vcpu boundary is
     * quiescent — and adds the explicit TSC/kvmclock freeze.
     */
    Error *err = NULL;
    bool was_running = runstate_is_running();
    SfSnapKind kind = sf_active ? SF_SNAP_RUN : SF_SNAP_ROOT;

    if (was_running) {
        vm_stop(RUN_STATE_SAVE_VM);
    }
    if (sf_snap_save(kind, &err) < 0) {
        monitor_printf(mon, "sf: snapshot failed: %s\n", error_get_pretty(err));
        error_free(err);
    }
    if (was_running) {
        vm_start();
    }
}

void hmp_sf_restore(Monitor *mon, const QDict *qdict)
{
    const char *debug_arg = qdict_get_try_str(qdict, "debug");
    SfReplayDebug debug;
    bool have_debug = debug_arg && *debug_arg;
    Error *err = NULL;

    if (!sf_snap_have_snapshot()) {
        monitor_printf(mon, "sf: no snapshot; run sf_snapshot first\n");
        return;
    }
    /* T1: only root/active exists, so the restore target is the active node. */
    if (have_debug && sf_active && sf_active->dev.have) {
        if (!sf_parse_restore_debug(mon, debug_arg, &sf_active->dev.tables,
                                    &debug)) {
            return;
        }
    }

    /*
     * HMP crutch: quiesce across the rollback (mutates guest RAM + device state
     * in place; racing a live vCPU tears RAM/regs). vm_start fires the runstate
     * handlers (kvmclock KVM_SET_CLOCK, vapic) — the terminal path applies those
     * explicitly via sf_snap_restore's clock tail.
     */
    bool was_running = runstate_is_running();
    if (was_running) {
        vm_stop(RUN_STATE_RESTORE_VM);
    }
    sf_snap_restore(sf_active ? sf_active->id : 0,
                    have_debug ? &debug : NULL, &err);
    if (err) {
        monitor_printf(mon, "sf: restore failed: %s\n", error_get_pretty(err));
        error_free(err);
    }
    if (was_running) {
        vm_start();
    }
    if (have_debug) {
        monitor_printf(mon, "sf: (debug=%s)\n", debug_arg);
    }
}

void hmp_sf_selftest(Monitor *mon, const QDict *qdict)
{
    Error *err = NULL;

    /* Self-contained: preparse/snapshot as each case needs (no prior sf_snapshot
     * required). Aggregates restore-correctness cases ①–⑤ (see sf/selftest/). */
    if (!sf_selftest_all(mon, &err)) {
        if (err) {
            monitor_printf(mon, "sf: selftest error: %s\n", error_get_pretty(err));
            error_free(err);
        }
    }
}

void hmp_sf_tree(Monitor *mon, const QDict *qdict)
{
    sf_snap_tree(mon);
}

void hmp_sf_cold_start(Monitor *mon, const QDict *qdict)
{
    const char *dir = qdict_get_str(qdict, "dir");
    int64_t id = qdict_get_try_int(qdict, "id", 0);
    bool restore_nr = qdict_get_try_bool(qdict, "restore-nr", false);
    Error *err = NULL;
    bool was_running = runstate_is_running();

    if (was_running) {
        vm_stop(RUN_STATE_RESTORE_VM);
    }
    if (sf_cold_start(dir, (uint32_t)id, restore_nr, true, &err) < 0) {
        monitor_printf(mon, "sf: cold-start failed: %s\n", error_get_pretty(err));
        error_free(err);
    } else {
        /* Guest resumes at the original snapshot site. The restored CPU state
         * already contains that outl's reply; only advance host generation.
         * Requested NO_RESTORE content was copied back while the VM was stopped. */
        sf_cp_generation_inc();
        monitor_printf(mon, "sf: cold-start ok: dir=%s id=%" PRId64 "\n", dir, id);
    }
    if (was_running) {
        vm_start();
    }
}

void hmp_sf_persist(Monitor *mon, const QDict *qdict)
{
    const char *dir = qdict_get_str(qdict, "dir");
    bool save_nr = qdict_get_try_bool(qdict, "save-nr", false);
    SfSnapNode *root = sf_active;
    Error *err = NULL;

    if (!root) {
        monitor_printf(mon, "sf: persist failed: no snapshot tree\n");
        return;
    }
    while (root->parent) {
        root = root->parent;
    }
    if (sf_snap_persist(root, dir, save_nr, &err) < 0) {
        monitor_printf(mon, "sf: persist failed: %s\n", error_get_pretty(err));
        error_free(err);
        return;
    }
    monitor_printf(mon, "sf: persist ok: dir=%s\n", dir);
}

void hmp_sf_promote(Monitor *mon, const QDict *qdict)
{
    const char *dir = qdict_get_str(qdict, "dir");
    int64_t id = qdict_get_try_int(qdict, "id", -1);
    SfSnapNode *node;
    Error *err = NULL;

    if (!sf_active) {
        monitor_printf(mon, "sf: promote failed: no snapshot tree\n");
        return;
    }
    node = id >= 0 ? sf_node_find((uint32_t)id) : sf_active;
    if (!node) {
        monitor_printf(mon, "sf: promote failed: node id %" PRId64 " not found\n",
                       id);
        return;
    }
    if (sf_snap_promote(node, dir, &err) < 0) {
        monitor_printf(mon, "sf: promote failed: %s\n", error_get_pretty(err));
        error_free(err);
        return;
    }
    monitor_printf(mon, "sf: promote ok: dir=%s id=%u\n", dir, node->id);
}

/* R3 spike (plan 2026-07-06-07 §3): research-only — verify EPT rebuild after a
 * MAP_PRIVATE|MAP_FIXED remap of a guest RAM page. Run under KVM with a guest
 * that writes @gpa (e.g. `sf_r3_spike 0x300000` with the sf-rig dirty workload).
 * A process crash means the mmu-notifier did NOT fire (R3 fails). */
void hmp_sf_r3_spike(Monitor *mon, const QDict *qdict)
{
    const char *arg = qdict_get_try_str(qdict, "gpa");
    uint64_t gpa = 0x300000;
    if (arg && *arg) {
        gpa = (uint64_t)g_ascii_strtoull(arg, NULL, 0);
    }
    sf_r3_spike_run(mon, (hwaddr)gpa);
}

/* R3-full (plan 2026-07-06-07 §3): whole-RAM scale-up of the R3 spike — remap
 * every guest RAM block to a dump file (MAP_PRIVATE|MAP_FIXED), the Nyx
 * shadow_memory.c:299-306 cold-start loop. Run under KVM + dirty ring with the
 * sf-rig dirty workload. Destructive (leaves guest RAM file-mapped); research. */
void hmp_sf_remap_all(Monitor *mon, const QDict *qdict)
{
    sf_remap_all_run(mon);
}

/* ---- Terminal CHECKPOINT entries (vcpu thread, no vm_stop) ---- */

/*
 * Terminal snapshot — called from the CHECKPOINT ioport handler on the vcpu
 * thread (sf/checkpoint.c). No vm_stop: the single vCPU is parked out of KVM_RUN
 * at the outl boundary. Freeze guest time across the RAM shadow so the guest
 * resumes at T0 instead of perceiving the shadow as a stall (crashes
 * lease-sensitive workloads). The TSC refreeze uses sf_skip_tsc() so the
 * phase1.5 T-TSC gate proves teeth.
 */
void sf_checkpoint_snapshot(void)
{
    Error *err = NULL;
    uint64_t clock0 = 0;
    bool ok;

    if (kvm_enabled()) {
        clock0 = kvmclock_sf_clock_get();
    }
    if (current_cpu) {
        cpu_synchronize_state(current_cpu);   /* env->tsc = T0 for the node capture */
    }
    /* save() builds a child of the active node (plan -04 §2): the first
     * CHECKPOINT builds root, subsequent ones build RUN diff layers on top. */
    SfSnapKind kind = sf_active ? SF_SNAP_RUN : SF_SNAP_ROOT;
    ok = (sf_snap_save(kind, &err) == 0);
    if (!ok) {
        fprintf(stderr, "sf-cp: snapshot FAILED: %s\n", error_get_pretty(err));
        error_free(err);
        return;
    }
    if (current_cpu && kvm_enabled()) {
        cpu_synchronize_post_init(current_cpu);   /* re-put env (T0 back into vcpu) */
        if (!sf_skip_tsc()) {
            sf_kvm_refreeze_tsc(current_cpu);     /* force the TSC rewind */
        }
    }
    if (clock0) {
        kvmclock_sf_clock_set(clock0);            /* rewind kvmclock to T0 */
    }
    fprintf(stderr, "sf-cp: snapshot ok (id=%u %s)\n",
            sf_active ? sf_active->id : 0,
            sf_active && sf_active->kind == SF_SNAP_ROOT ? "root" : "layer");
}

/*
 * Terminal restore to an explicit node id — called from the CHECKPOINT ioport
 * handler on the vcpu thread. No vm_stop. The engine sf_snap_restore(dst_id)
 * already accepts any id; this wrapper just hands it through (the old form
 * hardcoded sf_active->id). sf_snap_restore applies device replay + RAM
 * rollback + CPU/TSC push + the explicit kvmclock/vapic tail (no vm_start
 * here). The SF_CP_SKIP env knob injects a device-replay skip to prove a gate
 * has teeth. Returns true on success, false on bad id / restore error so the
 * caller can surface a 0xFFFFFFFF readback (plan 2026-07-08 T1 §2.1).
 */
bool sf_checkpoint_restore(uint32_t id)
{
    Error *err = NULL;
    SfReplayDebug debug, *dbgp = NULL;
    const char *skip = getenv("SF_CP_SKIP");

    if (!sf_snap_have_snapshot()) {
        fprintf(stderr, "sf-cp: restore with no snapshot — ignored\n");
        return false;
    }
    if (sf_active == NULL || id != sf_active->id) {
        if (sf_node_find(id) == NULL) {
            fprintf(stderr, "sf-cp: restore bad id=%u — not found\n", id);
            return false;
        }
    }
    if (skip && *skip && sf_active && sf_active->dev.have) {
        if (sf_parse_restore_debug(NULL, skip, &sf_active->dev.tables, &debug)) {
            dbgp = &debug;
        } else {
            fprintf(stderr, "sf-cp: bad SF_CP_SKIP='%s' — ignored\n", skip);
        }
    }
    sf_snap_restore(id, dbgp, &err);
    if (err) {
        fprintf(stderr, "sf-cp: restore failed: %s\n", error_get_pretty(err));
        error_free(err);
        return false;
    }
    fprintf(stderr, "sf-cp: restore applied id=%u%s%s\n", id,
            dbgp ? " skip=" : "", dbgp ? skip : "");
    return true;
}
