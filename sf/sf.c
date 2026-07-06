/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 * HMP entry points. Wires pre-parse (snapshot) + replay (restore) + selftest.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qobject/qdict.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"
#include "migration/vmstate.h"
#include "system/hw_accel.h"
#include "system/kvm.h"
#include "system/runstate.h"
#include "hw/core/cpu.h"
#include "hw/i386/kvm/clock.h"
#include "hw/i386/vapic.h"
#include "hw/nvram/fw_cfg.h"
#include "sf/sf.h"
#include "sf/kvm_tsc.h"
#include "sf/vmstate_replay/preparse.h"
#include "sf/vmstate_replay/replay.h"
#include "sf/dirty/engine.h"
#include "sf/selftest/selftest.h"

/* Single snapshot slot for the M0-S spike (one snapshot, many restores). */
static SfReplayTables g_sf_tables;
static bool g_sf_have_snapshot;

/* Machinery-latency probe (gated on SF_TIME=<non-empty>): prints per-phase ns of
 * snapshot/restore to stderr so the M0-S 止损闸 and snapshot-opt priority get real
 * numbers instead of guesses. Zero overhead when off. See sf ARCHITECTURE §6. */
static bool sf_timing(void)
{
    const char *s = getenv("SF_TIME");
    return s && *s;
}
static inline uint64_t sf_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Test knob: SF_CP_SKIP_TSC=<non-empty> omits the forced TSC refreeze so the
 * phase1.5 gate can prove the T-TSC probe has teeth. Empty/unset -> fix active. */
static bool sf_skip_tsc(void)
{
    const char *s = getenv("SF_CP_SKIP_TSC");
    return s && *s;
}

/* Test knob: SF_CP_SKIP_KVMCLOCK=<non-empty> omits the restore-tail kvmclock
 * re-anchor (KVM_SET_CLOCK + KVMCLOCK_CTRL) so the gate can prove T-CLK teeth. */
static bool sf_skip_kvmclock(void)
{
    const char *s = getenv("SF_CP_SKIP_KVMCLOCK");
    return s && *s;
}

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

/* Opaque of the named vmstate entry (pre or post) in the replay table, or NULL.
 * Used to reach a device instance for restore side effects that have no
 * post_load (kvmclock KVM_SET_CLOCK) or live outside the migration stream. */
static void *sf_find_opaque(const SfReplayTables *t, const char *name)
{
    for (size_t i = 0; i < t->n_posts; i++) {
        if (!strcmp(t->posts[i].vmsd->name, name)) {
            return t->posts[i].opaque;
        }
    }
    return NULL;
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

static bool sf_name_in(const char *name, const char * const *allowed)
{
    for (size_t i = 0; allowed[i]; i++) {
        if (!strcmp(name, allowed[i])) {
            return true;
        }
    }
    return false;
}

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
 * Snapshot core — RAM shadow + device three-table preparse + hot-profile guard,
 * at ONE coherent instant. The caller owns quiescence: it must be called while
 * the guest is stopped, either under HMP vm_stop (crutch baseline) or at the
 * vcpu I/O-exit CHECKPOINT boundary (terminal, single vCPU already out of
 * KVM_RUN with the BQL held). Does NOT itself stop/start the VM. mon may be NULL
 * (checkpoint path) — monitor_printf is NULL-safe, so all output just no-ops.
 * Returns true iff a usable snapshot was taken (RAM always; device best-effort).
 */
static bool sf_snapshot_core(Monitor *mon)
{
    Error *err = NULL;
    bool timing = sf_timing();
    uint64_t ta = 0, tb = 0, tc = 0;

    if (timing) {
        ta = sf_now_ns();
    }
    /* RAM side (Task 6) — the subject of this task; must succeed. */
    if (sf_dirty_snapshot(&err) < 0) {
        monitor_printf(mon, "sf: snapshot failed (RAM): %s\n",
                       error_get_pretty(err));
        error_free(err);
        return false;
    }

    /*
     * Device side (Task 4/5) — best-effort so a device-preparse gap (e.g. an
     * unhandled vmstate field only present under KVM) surfaces loudly without
     * masking the RAM result. Restore replays the device table only if present.
     */
    if (g_sf_have_snapshot) {
        sf_replay_tables_destroy(&g_sf_tables);
        g_sf_have_snapshot = false;
    }
    if (timing) {
        tb = sf_now_ns();
    }
    if (sf_preparse(&g_sf_tables, &err) < 0) {
        monitor_printf(mon, "sf: WARNING device preparse failed: %s "
                       "(RAM snapshot still taken)\n", error_get_pretty(err));
        error_free(err);
        err = NULL;
    } else {
        if (!sf_validate_hot_profile(mon, &g_sf_tables)) {
            sf_replay_tables_destroy(&g_sf_tables);
            sf_dirty_destroy();
            return false;
        }
        g_sf_have_snapshot = true;
    }

    if (timing) {
        tc = sf_now_ns();
        fprintf(stderr,
                "sf-time: snapshot ram-shadow=%.1fus device-preparse=%.1fus "
                "(this is the per-snapshot serialize+discovery cost we could reuse)\n",
                (tb - ta) / 1000.0, (tc - tb) / 1000.0);
    }

    size_t mbytes = 0;
    for (size_t i = 0; i < g_sf_tables.n_mblocks; i++) {
        mbytes += g_sf_tables.mblocks[i].size;
    }
    monitor_printf(mon, "sf: snapshot ok: RAM shadowed; device %s "
                   "(mblocks=%zu (%zu bytes) gets=%zu posts=%zu)\n",
                   g_sf_have_snapshot ? "ok" : "SKIPPED",
                   g_sf_tables.n_mblocks, mbytes,
                   g_sf_tables.n_gets, g_sf_tables.n_posts);

    /* Name-level dump: gets/posts are the audit-critical tables (which side
     * effects exist in this device set) — print identities, not just counts. */
    for (size_t i = 0; i < g_sf_tables.n_gets; i++) {
        const SfGet *g = &g_sf_tables.gets[i];
        monitor_printf(mon, "sf:   get[%zu] %s/%s info=%s size=%zu\n",
                       i, g->vmsd_name, g->field->name, g->info->name, g->size);
    }
    for (size_t i = 0; i < g_sf_tables.n_posts; i++) {
        const SfPost *p = &g_sf_tables.posts[i];
        monitor_printf(mon, "sf:   %s[%zu] %s\n",
                       p->is_pre ? "pre" : "post", i, p->vmsd->name);
    }

    return true;
}

void hmp_sf_snapshot(Monitor *mon, const QDict *qdict)
{
    /*
     * HMP crutch baseline: the vCPU is running on another thread, so quiesce the
     * whole VM around the capture. vm_stop(SAVE_VM) also cpu_synchronize_all_states
     * so CPUState reflects the live KVM vCPU before we serialize it. The terminal
     * path (sf_checkpoint_snapshot) drops this — the vcpu boundary is quiescent.
     */
    bool was_running = runstate_is_running();
    if (was_running) {
        vm_stop(RUN_STATE_SAVE_VM);
    }
    sf_snapshot_core(mon);
    if (was_running) {
        vm_start();
    }
}

/*
 * Terminal snapshot entry — called from the CHECKPOINT ioport handler on the
 * vcpu thread (checkpoint.c). No vm_stop: the single vCPU is already parked out
 * of KVM_RUN at the outl boundary. Pull its live registers into CPUState first
 * so the serialized snapshot reflects the exact boundary RIP/regs.
 */
void sf_checkpoint_snapshot(void)
{
    uint64_t clock0 = 0;
    bool ok;

    /*
     * Freeze guest time across the shadow so the guest resumes at the snapshot
     * instant T0 instead of perceiving the (multi-second, RAM-proportional) shadow
     * as a stall — which crashes lease-sensitive workloads (TiKV/PD). This is what
     * vm_stop provided; the terminal path has no vm_stop, so do it explicitly, both
     * clocks together:
     *   - kvmclock: read master clock at T0, write it back after the shadow.
     *   - TSC: cpu_synchronize_state captures env->tsc=T0 now; after the shadow
     *     sf_kvm_refreeze_tsc() forces the vcpu TSC back to T0. A plain post_init
     *     KVM_SET_MSRS(TSC) is NOT enough — KVM's sync heuristic swallows it (see
     *     sf/kvm_tsc.h); the guest was frozen (never read the TSC mid-shadow), so
     *     the forced rewind stays monotonic. kvmclock alone is not enough either:
     *     the guest derives it from the (jumped) TSC.
     * The restore path rewinds both the same way (sf_replay restores env->tsc,
     * then sf_restore_core forces the TSC; sf_apply_clock_tail's KVM_SET_CLOCK
     * re-anchors kvmclock).
     */
    if (kvm_enabled()) {
        clock0 = kvmclock_sf_clock_get();
    }
    if (current_cpu) {
        cpu_synchronize_state(current_cpu);
    }
    ok = sf_snapshot_core(NULL);
    if (current_cpu && kvm_enabled()) {
        cpu_synchronize_post_init(current_cpu);   /* re-put env (T0 back into vcpu) */
        if (!sf_skip_tsc()) {
            sf_kvm_refreeze_tsc(current_cpu);     /* force the TSC rewind (post_init's
                                                     plain MSR write is unreliable; see
                                                     sf/kvm_tsc.h) */
        }
    }
    if (clock0) {
        kvmclock_sf_clock_set(clock0);            /* rewind kvmclock to T0 */
    }
    if (ok) {
        fprintf(stderr, "sf-cp: snapshot ok (mblocks=%zu gets=%zu posts=%zu)\n",
                g_sf_tables.n_mblocks, g_sf_tables.n_gets, g_sf_tables.n_posts);
    } else {
        fprintf(stderr, "sf-cp: snapshot FAILED\n");
    }
}

/*
 * Restore core — device replay + RAM rollback + push CPU regs into the vcpu.
 * Caller owns quiescence (HMP vm_stop crutch, or the vcpu CHECKPOINT boundary).
 * @debug optional (NULL = no skip-knob injection). mon may be NULL.
 */
static void sf_restore_core(Monitor *mon, SfReplayDebug *debug)
{
    uint64_t collected;
    uint32_t copied;
    bool timing = sf_timing();
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;

    if (timing) {
        t0 = sf_now_ns();
    }
    /* Device state first (registers), then RAM contents. */
    if (g_sf_have_snapshot) {
        if (debug) {
            sf_replay_with_debug(&g_sf_tables, debug);
        } else {
            sf_replay(&g_sf_tables);
        }
    }
    if (timing) {
        t1 = sf_now_ns();
    }

    collected = sf_dirty_collect();
    if (timing) {
        t2 = sf_now_ns();
    }
    copied = sf_dirty_restore();
    sf_dirty_reset_ring();
    if (timing) {
        t3 = sf_now_ns();
    }

    /*
     * Push the replayed CPUState back into the KVM vCPU. sf_replay only touched
     * QEMU-side structs. Generic hw_accel wrapper -> kvm_arch_put_registers
     * (KVM_PUT_FULL_STATE). CPU_FOREACH is future-proof for multi-vCPU (DP-A).
     */
    {
        CPUState *cpu;
        CPU_FOREACH(cpu) {
            cpu_synchronize_post_init(cpu);
            /*
             * Force the TSC rewind. post_init's plain KVM_SET_MSRS(MSR_IA32_TSC)
             * can be silently swallowed by KVM's kvm_synchronize_tsc sync
             * heuristic, leaving the guest TSC at wall clock while kvmclock
             * freezes -> clocksource skew. See sf/kvm_tsc.h. SF_CP_SKIP_TSC omits
             * the force so the phase1.5 gate can prove the T-TSC probe has teeth.
             */
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

    monitor_printf(mon, "sf: restore ok: device=%s ram collected=%" PRIu64
                   " copied-back=%" PRIu32 "\n",
                   g_sf_have_snapshot ? "replayed" : "SKIPPED",
                   collected, copied);
}

/*
 * Minimal-set tail (ARCHITECTURE §4.4) that vm_start's vm_change_state_handlers
 * used to provide. The HMP crutch path still calls vm_start and gets these for
 * free; the terminal vcpu-boundary path has no vm_start, so it must apply them
 * explicitly here — AFTER sf_restore_core has rolled back RAM (kvmclock re-derives
 * the clock from the rolled-back pvclock page). kvmclock has no post_load: without
 * KVM_SET_CLOCK the KVM master clock keeps advancing past the snapshot and the
 * guest's time jumps on the next pvclock refresh. vapic re-activation preserves
 * TPR acceleration (inert while G-VAPIC keeps vapic inactive at capture).
 */
static void sf_apply_clock_tail(void)
{
    void *kc, *vp;

    if (!g_sf_have_snapshot) {
        return;
    }
    kc = sf_find_opaque(&g_sf_tables, "kvmclock");
    vp = sf_find_opaque(&g_sf_tables, "kvm-tpr-opt");
    /* SF_CP_SKIP_KVMCLOCK=<non-empty> omits the KVM_SET_CLOCK/KVMCLOCK_CTRL so the
     * phase1.5 gate can prove the T-CLK probe has teeth (guest clock jumps). */
    if (kc && !sf_skip_kvmclock()) {
        kvmclock_sf_restore(kc);
    }
    if (vp) {
        vapic_sf_reactivate(vp);
    }
}

void hmp_sf_restore(Monitor *mon, const QDict *qdict)
{
    const char *debug_arg = qdict_get_try_str(qdict, "debug");
    SfReplayDebug debug;
    bool have_debug = debug_arg && *debug_arg;

    if (!sf_dirty_have_snapshot()) {
        monitor_printf(mon, "sf: no snapshot; run sf_snapshot first\n");
        return;
    }
    if (g_sf_have_snapshot &&
        !sf_parse_restore_debug(mon, debug_arg, &g_sf_tables, &debug)) {
        return;
    }

    /*
     * HMP crutch baseline: the vCPU is running on another thread, so quiesce it
     * across the rollback (sf_restore mutates guest RAM + device state in place;
     * racing a live vCPU tears RAM/regs -> #PF at a random RIP). Stock loadvm
     * restores stopped, then vm_start() fires every vm_change_state_handler
     * (kvmclock KVM_SET_CLOCK, ...). Mirror that: stop -> restore -> put -> start.
     * The terminal path (sf_checkpoint_restore) drops this — the vcpu boundary is
     * already quiescent and re-enters KVM directly.
     */
    bool was_running = runstate_is_running();
    if (was_running) {
        vm_stop(RUN_STATE_RESTORE_VM);
    }
    sf_restore_core(mon, have_debug ? &debug : NULL);
    if (was_running) {
        vm_start(); /* resume vCPUs + fire change handlers (incl. kvmclock) */
    }
    if (have_debug) {
        monitor_printf(mon, "sf: (debug=%s)\n", debug_arg);
    }
}

/*
 * Terminal restore entry — called from the CHECKPOINT ioport handler on the vcpu
 * thread. No vm_stop. cpu_synchronize_post_init pushes the replayed regs (incl.
 * RIP = the snapshot's outl site) into the vcpu; on return KVM re-enters and the
 * pending fast-PIO completion advances RIP consistently — but only because
 * SNAPSHOT and RESTORE are issued from the identical outl address (single-site
 * rule, design doc §CHECKPOINT). Empirically validated in Step C.
 */
void sf_checkpoint_restore(void)
{
    SfReplayDebug debug;
    SfReplayDebug *dbgp = NULL;
    /* M3 skip-knob for the terminal path: run.sh sets SF_CP_SKIP=<knob> to force
     * one restore path to be omitted, proving the guest probe goes RED (teeth).
     * Same knob grammar as HMP sf_restore debug= (skip-mblock/get/pre/post=N). */
    const char *skip = getenv("SF_CP_SKIP");

    if (!sf_dirty_have_snapshot()) {
        fprintf(stderr, "sf-cp: restore with no snapshot — ignored\n");
        return;
    }
    if (skip && *skip && g_sf_have_snapshot) {
        if (sf_parse_restore_debug(NULL, skip, &g_sf_tables, &debug)) {
            dbgp = &debug;
        } else {
            fprintf(stderr, "sf-cp: bad SF_CP_SKIP='%s' — ignored\n", skip);
        }
    }
    sf_restore_core(NULL, dbgp);
    sf_apply_clock_tail();   /* explicit KVM_SET_CLOCK + vapic (no vm_start here) */
    fprintf(stderr, "sf-cp: restore applied%s%s\n",
            dbgp ? " skip=" : "", dbgp ? skip : "");
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
