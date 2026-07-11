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
#include "sf/control/config.h"
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

/* ---- HMP entries (debug + low-freq config only) --------------------------
 * Framework control (snapshot/restore/cold-start/persist/promote) left HMP for
 * the binary pipe + startup config in control-plane v2 (plan 2026-07-11-04 §2.1,
 * S4); only these debug/config knobs remain. */

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

void hmp_sf_config(Monitor *mon, const QDict *qdict)
{
    const char *key = qdict_get_try_str(qdict, "key");
    const char *val = qdict_get_try_str(qdict, "val");

    if (!key) {
        const SfConfig *c = sf_config();
        static const char *gm[] = { "allow", "disable", "strict" };
        monitor_printf(mon,
            "sf config: common_dir=%s private_dir=%s resume_timeout_ms=%" PRId64
            " gate=%s cold_start_on_boot=%d initial_node=%u\n",
            c->common_dir[0] ? c->common_dir : "(none)",
            c->private_dir[0] ? c->private_dir : "(none)",
            c->resume_timeout_ms, gm[c->gate_mode],
            c->cold_start_on_boot, c->initial_node);
        return;
    }
    if (!val) {
        monitor_printf(mon, "sf: sf_config <key> <val> (or no args to show)\n");
        return;
    }
    Error *err = NULL;
    if (sf_config_set(key, val, &err) < 0) {
        monitor_printf(mon, "sf: config set failed: %s\n", error_get_pretty(err));
        error_free(err);
    } else {
        monitor_printf(mon, "sf: config %s=%s\n", key, val);
    }
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
