/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 * HMP entry points. Wires pre-parse (snapshot) + replay (restore) + selftest.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"
#include "migration/vmstate.h"
#include "system/hw_accel.h"
#include "system/runstate.h"
#include "hw/core/cpu.h"
#include "sf/sf.h"
#include "sf/vmstate_replay/preparse.h"
#include "sf/vmstate_replay/replay.h"
#include "sf/dirty/engine.h"
#include "sf/selftest/selftest.h"

/* Single snapshot slot for the M0-S spike (one snapshot, many restores). */
static SfReplayTables g_sf_tables;
static bool g_sf_have_snapshot;

void hmp_sf_snapshot(Monitor *mon, const QDict *qdict)
{
    Error *err = NULL;

    /*
     * Quiesce the whole VM for the duration of the snapshot. The snapshot must
     * capture CPU + RAM + device state at ONE coherent instant: sf_dirty_snapshot
     * shadows all of guest RAM and sf_preparse serializes the CPU/device state.
     * Under a running vCPU those are captured at different moments (RAM smeared
     * across the multi-second shadow, CPU from its stale cache) — an internally
     * inconsistent snapshot that corrupts the guest when restored, regardless of
     * how clean the restore is. Nyx creates its in-memory root snapshot the same
     * way: vm_stop(RUN_STATE_SAVE_VM) -> fast_reload_create_in_memory -> vm_start
     * (QEMU-Nyx nyx/fast_vm_reload_sync.c). vm_stop also cpu_synchronize_all_states,
     * so QEMU's CPUState reflects the live KVM vCPU before we serialize it.
     */
    bool was_running = runstate_is_running();
    if (was_running) {
        vm_stop(RUN_STATE_SAVE_VM);
    }

    /* RAM side (Task 6) — the subject of this task; must succeed. */
    if (sf_dirty_snapshot(&err) < 0) {
        monitor_printf(mon, "sf: snapshot failed (RAM): %s\n",
                       error_get_pretty(err));
        error_free(err);
        if (was_running) {
            vm_start();
        }
        return;
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
    if (sf_preparse(&g_sf_tables, &err) < 0) {
        monitor_printf(mon, "sf: WARNING device preparse failed: %s "
                       "(RAM snapshot still taken)\n", error_get_pretty(err));
        error_free(err);
        err = NULL;
    } else {
        g_sf_have_snapshot = true;
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

    if (was_running) {
        vm_start();
    }
}

void hmp_sf_restore(Monitor *mon, const QDict *qdict)
{
    uint64_t collected;
    uint32_t copied;

    if (!sf_dirty_have_snapshot()) {
        monitor_printf(mon, "sf: no snapshot; run sf_snapshot first\n");
        return;
    }

    /*
     * Quiesce the vCPUs across the rollback. sf_restore mutates guest RAM +
     * device state in place; doing that under a running vCPU races the guest
     * (torn RAM / stale regs -> control-flow corruption -> #PF at a random RIP).
     * The vCPU is confirmed 'running' at restore time (HMP fires on the main-loop
     * thread, not a hypercall boundary). Stock loadvm restores with the VM
     * stopped, then vm_start() resumes AND fires every vm_change_state_handler
     * (kvmclock KVM_SET_CLOCK, cpu, ...) that our in-place restore otherwise
     * skips. Mirror that: stop -> restore -> put CPU regs -> start.
     */
    bool was_running = runstate_is_running();
    if (was_running) {
        vm_stop(RUN_STATE_RESTORE_VM);
    }

    /* Device state first (registers), then RAM contents. */
    if (g_sf_have_snapshot) {
        sf_replay(&g_sf_tables);
    }

    collected = sf_dirty_collect();
    copied = sf_dirty_restore();
    sf_dirty_reset_ring();

    /*
     * Push the replayed CPUState back into the KVM vCPU. sf_replay only touched
     * QEMU-side structs; vm_start() does not push registers (only cpu_update_state
     * / tsc invalidation). Generic hw_accel wrapper -> kvm_arch_put_registers
     * (KVM_PUT_FULL_STATE). CPU_FOREACH is future-proof for multi-vCPU (DP-A).
     */
    {
        CPUState *cpu;
        CPU_FOREACH(cpu) {
            cpu_synchronize_post_init(cpu);
        }
    }

    if (was_running) {
        vm_start(); /* resume vCPUs + fire change handlers (incl. kvmclock) */
    }

    monitor_printf(mon, "sf: restore ok: device=%s ram collected=%" PRIu64
                   " copied-back=%" PRIu32 "\n",
                   g_sf_have_snapshot ? "replayed" : "SKIPPED",
                   collected, copied);
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
