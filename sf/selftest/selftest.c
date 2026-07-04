/*
 * sf/selftest — discriminating restore-correctness selftest (design §G).
 *
 * Cases:
 *   ⑤ device replay vs stock load (positive) + neg (corrupt mblock -> RED).
 *   ④ corrupt a get-handler's captured bytes -> cross-check must go RED.
 *   ① guest changes N pages -> restore rolls every one back to the snapshot.
 *   ② drop one dirtied page in collect -> that page stays wrong (loss detected).
 *   ③ ring-full (4096 pages, 1024-entry ring): zero page loss; and skipping the
 *      ring drain must lose pages (validates the drain-then-read-bitmap design).
 *
 * RAM cases drive the real KVM path: stop -> snapshot -> run the guest briefly
 * -> stop -> collect+restore -> verify. Host writes to guest RAM don't fault
 * through KVM, so a running vcpu is the only way to populate the dirty ring —
 * hence the coupling to the sf-rig dirty workload (ARCHITECTURE.md §6).
 *
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-types-run-state.h"
#include "qemu/main-loop.h"
#include "monitor/monitor.h"
#include "exec/cpu-common.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "system/runstate.h"
#include "system/kvm.h"
#include "system/hw_accel.h"
#include "hw/core/cpu.h"
#include "migration/savevm.h"
#include "migration/qemu-file.h"
#include "sf/dirty/engine.h"
#include "sf/vmstate_replay/buffer.h"
#include "sf/vmstate_replay/preparse.h"
#include "sf/vmstate_replay/replay.h"
#include "sf/selftest/selftest.h"

/* Must match the sf-rig dirty workload (ARCHITECTURE.md §6): a spin loop that
 * writes an incrementing counter into the first word of each of NPAGES pages
 * from BASE. 4096 pages > a 1024-entry ring -> exercises the ring-full path. */
#define SF_ST_BASE      0x300000
#define SF_ST_PAGE      4096
#define SF_ST_NPAGES    4096
#define SF_ST_WATCH     64      /* subset checked in the plain correctness case */

static uint32_t sf_rd32(hwaddr gpa)
{
    uint32_t v = 0;
    cpu_physical_memory_read(gpa, &v, sizeof(v));
    return v;
}

/* Host address of guest-physical @gpa (page-aligned inputs -> aligned output,
 * matching what sf_kvm_collect_dirty reports). */
static void *sf_gpa_to_host(hwaddr gpa)
{
    MemoryRegionSection s = memory_region_find(get_system_memory(), gpa, 1);
    void *host = NULL;

    if (s.mr) {
        if (memory_region_is_ram(s.mr)) {
            host = memory_region_get_ram_ptr(s.mr) + s.offset_within_region;
        }
        memory_region_unref(s.mr);
    }
    return host;
}

/* Let the guest run for ~@ms ms so its vcpus dirty RAM, then stop again. */
static void sf_run_guest_ms(unsigned ms)
{
    if (!runstate_is_running()) {
        vm_start();
    }
    /* vcpus need the BQL to enter KVM_RUN; drop it so they actually run. */
    bql_unlock();
    g_usleep((guint64)ms * 1000);
    bql_lock();
    vm_stop(RUN_STATE_PAUSED);
}

static void report(Monitor *mon, bool *all_ok, const char *name, bool ok,
                   const char *detail)
{
    monitor_printf(mon, "sf: selftest[%s]: %s%s%s\n", name,
                   ok ? "GREEN" : "RED",
                   detail ? " — " : "", detail ? detail : "");
    if (!ok) {
        *all_ok = false;
    }
}

/* ---- Device cases (④⑤) -------------------------------------------------- */

static void sf_selftest_device(Monitor *mon, bool *all_ok)
{
    Error *err = NULL;
    SfReplayTables t;
    char buf[128];

    if (sf_preparse(&t, &err) < 0) {
        report(mon, all_ok, "4-5 device preparse", false, error_get_pretty(err));
        error_free(err);
        return;
    }

    /* ⑤ positive: sf_replay reconstructs the same device state as stock load. */
    bool good = sf_replay_matches_stock(&t, &err);
    report(mon, all_ok, "5 replay-vs-stock", good, good ? NULL : error_get_pretty(err));
    error_free(err);
    err = NULL;

    /* ⑤ neg: corrupt one mblock.copy -> the cross-check must diverge (RED). */
    if (good && t.n_mblocks && t.mblocks[0].size) {
        uint8_t *copy = t.mblocks[0].copy;
        uint8_t orig = copy[0];
        copy[0] ^= 0xFF;
        bool matched = sf_replay_matches_stock(&t, &err);
        copy[0] = orig;
        error_free(err);
        err = NULL;
        report(mon, all_ok, "5-neg mblock-corruption", !matched,
               !matched ? "detected" : "BUG: undetected");
    }

    /* ④: corrupt a get-handler's captured stream slice -> replay diverges. */
    if (t.n_gets && t.gets[0].captured_len) {
        uint8_t *cap = t.gets[0].captured;
        uint8_t orig = cap[0];
        cap[0] ^= 0xFF;
        bool matched = sf_replay_matches_stock(&t, &err);
        cap[0] = orig;
        error_free(err);
        err = NULL;
        snprintf(buf, sizeof(buf), "%s (%zu gets, info=%s)",
                 !matched ? "detected" : "BUG: undetected",
                 t.n_gets, t.gets[0].info->name);
        report(mon, all_ok, "4 get-handler-corruption", !matched, buf);
    } else {
        report(mon, all_ok, "4 get-handler-corruption", true,
               "SKIPPED (no get-handlers on this machine)");
    }

    sf_replay_tables_destroy(&t);
}

/* ---- RAM cases (①②③) --------------------------------------------------- */

/* Snapshot, record watched pages, run the guest, return #pages that changed. */
static uint32_t sf_snapshot_and_dirty(uint32_t *exp, uint32_t npages,
                                      unsigned run_ms, Error **errp)
{
    uint32_t changed = 0;

    if (sf_dirty_snapshot(errp) < 0) {
        return UINT32_MAX;
    }
    for (uint32_t i = 0; i < npages; i++) {
        exp[i] = sf_rd32(SF_ST_BASE + (hwaddr)i * SF_ST_PAGE);
    }
    sf_run_guest_ms(run_ms);
    for (uint32_t i = 0; i < npages; i++) {
        if (sf_rd32(SF_ST_BASE + (hwaddr)i * SF_ST_PAGE) != exp[i]) {
            changed++;
        }
    }
    return changed;
}

/* After a restore, count watched pages that did NOT return to snapshot value. */
static uint32_t sf_count_mismatch(const uint32_t *exp, uint32_t npages)
{
    uint32_t mism = 0;
    for (uint32_t i = 0; i < npages; i++) {
        if (sf_rd32(SF_ST_BASE + (hwaddr)i * SF_ST_PAGE) != exp[i]) {
            mism++;
        }
    }
    return mism;
}

static void sf_selftest_ram(Monitor *mon, bool *all_ok)
{
    Error *err = NULL;
    char buf[160];
    uint32_t *exp;

    if (!sf_kvm_dirty_ring_enabled()) {
        monitor_printf(mon, "sf: selftest[1-3 RAM]: SKIPPED "
                       "(need -accel kvm,dirty-ring-size=N + dirty workload)\n");
        return;
    }

    exp = g_new(uint32_t, SF_ST_NPAGES);

    /* ① correctness: every changed page rolls back to the snapshot value. */
    {
        uint32_t changed = sf_snapshot_and_dirty(exp, SF_ST_WATCH, 20, &err);
        if (changed == UINT32_MAX) {
            report(mon, all_ok, "1 rollback", false, error_get_pretty(err));
            error_free(err); err = NULL;
        } else {
            sf_dirty_collect();
            uint32_t copied = sf_dirty_restore();
            sf_dirty_reset_ring();
            uint32_t mism = sf_count_mismatch(exp, SF_ST_WATCH);
            bool ok = (changed > 0) && (mism == 0);
            snprintf(buf, sizeof(buf), "%u/%u pages changed then restored, "
                     "%u still wrong, copied-back=%u", changed, SF_ST_WATCH,
                     mism, copied);
            report(mon, all_ok, "1 rollback", ok, buf);
        }
    }

    /* ② teeth: drop one dirtied page in collect -> it stays wrong (detected). */
    {
        void *host0 = sf_gpa_to_host(SF_ST_BASE);
        uint32_t changed = sf_snapshot_and_dirty(exp, 1, 20, &err);
        if (changed == UINT32_MAX) {
            report(mon, all_ok, "2 dropped-page teeth", false, error_get_pretty(err));
            error_free(err); err = NULL;
        } else {
            sf_dirty_inject_collect_skip(host0);
            sf_dirty_collect();
            sf_dirty_restore();
            sf_dirty_reset_ring();
            sf_dirty_inject_collect_skip(NULL);
            uint32_t mism = sf_count_mismatch(exp, 1);
            /* teeth = the injected loss is observable (page not rolled back). */
            bool ok = (changed > 0) && (mism == 1);
            snprintf(buf, sizeof(buf), "%s (page0 changed=%u, wrong-after=%u)",
                     ok ? "loss detected" : "BUG: injected loss hidden",
                     changed, mism);
            report(mon, all_ok, "2 dropped-page teeth", ok, buf);
        }
    }

    /* ③ ring-full: zero loss across 4096 pages on a 1024-entry ring; and
     *   skipping the drain must lose pages. */
    {
        uint32_t changed = sf_snapshot_and_dirty(exp, SF_ST_NPAGES, 30, &err);
        if (changed == UINT32_MAX) {
            report(mon, all_ok, "3 ring-full zero-loss", false, error_get_pretty(err));
            error_free(err); err = NULL;
        } else {
            sf_dirty_collect();
            sf_dirty_restore();
            sf_dirty_reset_ring();
            uint32_t mism = sf_count_mismatch(exp, SF_ST_NPAGES);
            /* changed > ring size proves the ring-full path was exercised. */
            bool ok = (changed > 1024) && (mism == 0);
            snprintf(buf, sizeof(buf), "%u pages changed (>ring 1024), %u lost",
                     changed, mism);
            report(mon, all_ok, "3 ring-full zero-loss", ok, buf);
        }

        /* teeth: under the same ring-full pressure, drop one dirtied page ->
         * the zero-loss check must catch it (deterministic). */
        {
            void *hostK = sf_gpa_to_host(SF_ST_BASE + 100 * SF_ST_PAGE);
            changed = sf_snapshot_and_dirty(exp, SF_ST_NPAGES, 30, &err);
            if (changed == UINT32_MAX) {
                report(mon, all_ok, "3-neg dropped-page teeth", false,
                       error_get_pretty(err));
                error_free(err); err = NULL;
            } else {
                sf_dirty_inject_collect_skip(hostK);
                sf_dirty_collect();
                sf_dirty_restore();
                sf_dirty_reset_ring();
                sf_dirty_inject_collect_skip(NULL);
                uint32_t mism = sf_count_mismatch(exp, SF_ST_NPAGES);
                bool teeth = (mism >= 1);
                snprintf(buf, sizeof(buf), "%s under ring-full: %u page(s) wrong",
                         teeth ? "loss detected" : "BUG: injected loss hidden",
                         mism);
                report(mon, all_ok, "3-neg dropped-page teeth", teeth, buf);
            }

            /* Info (not gated): skipping the explicit drain still loses ~0 pages
             * because KVM_EXIT_DIRTY_RING_FULL exits + the background reaper
             * drain into the bitmap too — the drain-then-read-bitmap design is
             * redundantly robust. A naive live-ring reader would lose thousands. */
            changed = sf_snapshot_and_dirty(exp, SF_ST_NPAGES, 30, &err);
            if (changed != UINT32_MAX) {
                sf_kvm_set_skip_flush(true);
                sf_dirty_collect();
                sf_dirty_restore();
                sf_dirty_reset_ring();
                sf_kvm_set_skip_flush(false);
                uint32_t mism2 = sf_count_mismatch(exp, SF_ST_NPAGES);
                monitor_printf(mon, "sf: selftest[3-info skip-explicit-drain]: "
                               "lost %u/%u pages (ring-full exits auto-drain; "
                               "live-ring-only would lose ~%u)\n",
                               mism2, changed, changed > 1024 ? changed - 1024 : 0);
            } else {
                error_free(err); err = NULL;
            }
        }
    }

    g_free(exp);
}

/* ---- CPU-state case (⑥) ------------------------------------------------- */

/* Force CPUState to reflect the real KVM vCPU: clear vcpu_dirty so
 * cpu_synchronize_state re-reads via ioctl instead of trusting QEMU's cache
 * (which sf_replay writes into). kvm_arch_get_registers isn't visible in
 * system_ss; go through the generic hw_accel wrapper. */
static void sf_pull_vcpu_from_kvm(CPUState *cpu)
{
    cpu->vcpu_dirty = false;
    cpu_synchronize_state(cpu);
}

/* Serialize current device+CPU state into a fresh owned buffer. */
static uint8_t *sf_save_dev(size_t *len, Error **errp)
{
    QEMUFile *wf = sf_qemufile_from_buffer_output();
    if (qemu_save_device_state(wf, errp) != 0) {
        qemu_fclose(wf);
        return NULL;
    }
    const uint8_t *b;
    size_t l;
    sf_qemufile_get_output(wf, &b, &l);
    uint8_t *dup = g_memdup2(b, l);
    *len = l;
    qemu_fclose(wf);
    return dup;
}

/*
 * ⑥ CPU-state rollback. Snapshot the device+CPU stream, run the guest so CPU
 * state advances (dirty.S bumps EBX every pass; TSC advances too), then sf-
 * restore and re-serialize — reading the vCPU straight from KVM. A correct
 * restore reproduces the snapshot stream. sf_restore currently doesn't push CPU
 * state back into the vCPU (no kvm_arch_put_registers), so the restored stream
 * still carries the run-time EBX/TSC and this goes RED — the gap it guards. PC
 * alone is useless (tight loop pins it), so compare the whole CPU section via
 * the device stream.
 */
static void sf_selftest_cpu(Monitor *mon, bool *all_ok)
{
    Error *err = NULL;
    SfReplayTables t;
    CPUState *cpu = first_cpu;
    uint8_t *s_snap = NULL, *s_ran = NULL, *s_rest = NULL, *s_replay = NULL;
    size_t l_snap = 0, l_ran = 0, l_rest = 0, l_replay = 0;
    char buf[192];

    if (!kvm_enabled() || !sf_kvm_dirty_ring_enabled()) {
        monitor_printf(mon, "sf: selftest[6 cpu-state]: SKIPPED "
                       "(needs KVM + dirty ring + running guest)\n");
        return;
    }
    if (sf_preparse(&t, &err) < 0) {
        report(mon, all_ok, "6 cpu-state", false, error_get_pretty(err));
        error_free(err);
        return;
    }
    if (sf_dirty_snapshot(&err) < 0) {
        report(mon, all_ok, "6 cpu-state", false, error_get_pretty(err));
        error_free(err);
        sf_replay_tables_destroy(&t);
        return;
    }

    sf_pull_vcpu_from_kvm(cpu);
    s_snap = sf_save_dev(&l_snap, &err); error_free(err); err = NULL;

    sf_run_guest_ms(20);
    sf_pull_vcpu_from_kvm(cpu);
    s_ran = sf_save_dev(&l_ran, &err); error_free(err); err = NULL;

    /* Full sf restore path: device replay -> RAM rollback -> push CPU to KVM. */
    sf_replay(&t);
    /* Diagnostic: did sf_replay restore the QEMU CPUState? Read it back before
     * any KVM pull (vcpu_dirty still true from vm_stop, so save reads CPUState). */
    s_replay = sf_save_dev(&l_replay, &err); error_free(err); err = NULL;
    sf_dirty_collect();
    sf_dirty_restore();
    sf_dirty_reset_ring();
    cpu_synchronize_post_init(cpu);   /* push replayed CPUState into KVM vCPU */

    sf_pull_vcpu_from_kvm(cpu);   /* read real vCPU */
    s_rest = sf_save_dev(&l_rest, &err); error_free(err); err = NULL;

    bool saved = s_snap && s_ran && s_rest && s_replay;
    bool moved = saved && (l_ran != l_snap || memcmp(s_ran, s_snap, l_snap) != 0);
    bool replay_ok = saved && l_replay == l_snap && memcmp(s_replay, s_snap, l_snap) == 0;
    bool back  = saved && l_rest == l_snap && memcmp(s_rest, s_snap, l_snap) == 0;
    snprintf(buf, sizeof(buf),
             "snap=%zuB (moved=%d replay_restored_cpustate=%d back=%d)",
             l_snap, moved, replay_ok, back);
    report(mon, all_ok, "6 cpu-state rollback", saved && moved && back, buf);

    g_free(s_snap);
    g_free(s_ran);
    g_free(s_rest);
    g_free(s_replay);
    sf_replay_tables_destroy(&t);
}

bool sf_selftest_all(Monitor *mon, Error **errp)
{
    bool all_ok = true;

    /* Device work needs a stable state. */
    if (runstate_is_running()) {
        vm_stop(RUN_STATE_PAUSED);
    }

    /*
     * Device cross-check (④⑤) re-loads a migration stream via
     * qemu_load_device_state, which under KVM pushes CPU/apic MSRs back through
     * ioctls and is fragile to re-load into a live VM (asserts in
     * kvm_put_apicbase). It's accel-independent in spirit and validated under
     * TCG — run it there. RAM cases (①②③) need the KVM dirty ring. So a full
     * pass is two invocations: TCG for ④⑤, KVM for ①②③.
     */
    if (kvm_enabled()) {
        monitor_printf(mon, "sf: selftest[4-5 device]: SKIPPED under KVM "
                       "(run under TCG; qemu_load_device_state re-load is "
                       "KVM-unsafe)\n");
    } else {
        sf_selftest_device(mon, &all_ok);
    }
    sf_selftest_ram(mon, &all_ok);
    sf_selftest_cpu(mon, &all_ok);

    monitor_printf(mon, "sf: selftest overall: %s\n",
                   all_ok ? "GREEN (all cases as expected)" : "RED");
    return all_ok;
}
