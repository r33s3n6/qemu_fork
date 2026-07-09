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
#include "system/ramblock.h"
#include "system/ramlist.h"      /* RAMBLOCK_FOREACH (sf_remap_all) */
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "system/runstate.h"
#include <glib/gstdio.h>   /* GDir for persist-test cleanup */
#include "system/kvm.h"
#include "system/hw_accel.h"
#include "hw/core/cpu.h"
#include "migration/savevm.h"
#include "migration/qemu-file.h"
#include "sf/track/tracker.h"
#include "sf/kvm_tsc.h"
#include "sf/vmstate_replay/buffer.h"
#include "sf/vmstate_replay/preparse.h"
#include "sf/vmstate_replay/replay.h"
#include "sf/snap/node.h"
#include "sf/snap/exclude.h"
#include "sf/snap/tripwire.h"
#include "sf/snap/persist.h"
#include "sf/snap/cold.h"
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

/* Host address of guest-physical @gpa — shared impl in sf/snap/node.c
 * (sf_gpa_to_host). Page-aligned inputs -> aligned output, matching what
 * sf_kvm_collect_dirty reports. */

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

/* Harness precheck (防呆): does the guest actively dirty the watched pages?
 * Pure read/run/read — no snapshot, no dirty tracking, leaves no state behind.
 * Tells "guest runs the sf-rig dirty workload (dirty.elf)" from "idle guest",
 * so the dirty-dependent cases can abort with a clear message instead of a
 * screen of false RED when someone points sf_selftest at the wrong guest. */
static bool sf_st_guest_dirties(unsigned ms)
{
    uint32_t before[SF_ST_WATCH];

    for (uint32_t i = 0; i < SF_ST_WATCH; i++) {
        before[i] = sf_rd32(SF_ST_BASE + (hwaddr)i * SF_ST_PAGE);
    }
    sf_run_guest_ms(ms);
    for (uint32_t i = 0; i < SF_ST_WATCH; i++) {
        if (sf_rd32(SF_ST_BASE + (hwaddr)i * SF_ST_PAGE) != before[i]) {
            return true;
        }
    }
    return false;
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

/* ---- R3: flat restore-store logic (plan 2026-07-08-03 §4) ----------------- *
 * KVM-free: drives the store ops directly with synthetic dirty pages + a
 * counting shadow resolve. Proves dedup, lazy+incremental src cache (resolve
 * called once per page), BLIND keeps the plan across after_restore, FULL clears.
 * BLIND path touches no KVM (runs both passes); FULL's after_restore calls
 * sf_kvm_reset_ring so its sub-check is gated to the TCG pass. */
struct sf_tst_rctx { uint8_t *region, *shadow; int calls; };
static uint8_t *sf_tst_resolve(void *target, void *host, void *user)
{
    struct sf_tst_rctx *c = user;
    (void)target;
    c->calls++;
    return c->shadow + ((uint8_t *)host - c->region);
}

static void sf_selftest_track(Monitor *mon, bool *all_ok)
{
    size_t psize = qemu_real_host_page_size();
    size_t N = 8;
    uint8_t *region = g_malloc(N * psize);
    uint8_t *shadow = g_malloc(N * psize);
    struct sf_tst_rctx c = { region, shadow, 0 };
    SfBlockReg blk = { region, N * psize };
    void *tgt = (void *)0x1;
    char buf[160];
    bool ok, full = true;

    SfRestoreStore *st = sf_flat_store_new(&blk, 1, sf_tst_resolve, &c, SF_FLAT_BLIND);
    const SfRestoreStoreOps *o = st->ops;

    void *b1[] = { region + 0*psize, region + 1*psize, region + 0*psize };  /* p0 dup */
    o->note_batch(st, b1, 3);
    const SfRestorePlan *p = o->plan(st, tgt);
    ok = (p->n == 2) && (c.calls == 2) &&
         p->pages[0].dst == region && p->pages[0].src == shadow &&
         p->pages[1].dst == region + psize && p->pages[1].src == shadow + psize;

    void *b2[] = { region + 2*psize, region + 1*psize };   /* p2 new, p1 dup */
    o->note_batch(st, b2, 2);
    p = o->plan(st, tgt);
    ok = ok && (p->n == 3) && (c.calls == 3) &&            /* only +1 resolve (incremental) */
         p->pages[2].dst == region + 2*psize;

    o->after_restore(st, tgt);      /* BLIND: keep plan, no re-resolve */
    p = o->plan(st, tgt);
    ok = ok && (p->n == 3) && (c.calls == 3);
    o->free(st);

    if (!kvm_enabled()) {           /* FULL after_restore calls sf_kvm_reset_ring */
        struct sf_tst_rctx c2 = { region, shadow, 0 };
        st = sf_flat_store_new(&blk, 1, sf_tst_resolve, &c2, SF_FLAT_FULL);
        o = st->ops;
        o->note_batch(st, b1, 3);
        bool full1 = (o->plan(st, tgt)->n == 2);
        o->after_restore(st, tgt);  /* FULL: reset + clear */
        bool full0 = (o->plan(st, tgt)->n == 0);
        full = full1 && full0;
        o->free(st);
    }

    snprintf(buf, sizeof(buf), "dedup+incremental (resolves=%d) blind-keep%s",
             c.calls, kvm_enabled() ? "" : " + full-clear");
    report(mon, all_ok, "R3 flat-store logic", ok && full, buf);
    g_free(region);
    g_free(shadow);
}

/* ---- Device cases (④⑤) -------------------------------------------------- */

static bool sf_selftest_poke_mblocks(const SfReplayTables *t, bool skip_first)
{
    for (size_t i = 0; i < t->n_mblocks; i++) {
        memset(t->mblocks[i].ptr, 0xA5, t->mblocks[i].size);
    }
    for (size_t i = skip_first ? 1 : 0; i < t->n_mblocks; i++) {
        memcpy(t->mblocks[i].ptr, t->mblocks[i].copy, t->mblocks[i].size);
    }

    bool all_restored = true;
    for (size_t i = 0; i < t->n_mblocks; i++) {
        if (memcmp(t->mblocks[i].ptr, t->mblocks[i].copy,
                   t->mblocks[i].size) != 0) {
            all_restored = false;
        }
    }
    return all_restored;
}

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

    /* P1 positive: every recorded mblock can be poisoned and byte-restored. */
    if (good && t.n_mblocks) {
        bool restored = sf_selftest_poke_mblocks(&t, false);
        report(mon, all_ok, "P1 poke-rollback", restored,
               restored ? "all mblocks restored" : "BUG: poison remained");
    }

    /* P1 teeth: if one mblock is omitted, poison must remain observable. */
    if (good && t.n_mblocks) {
        bool restored = sf_selftest_poke_mblocks(&t, true);
        report(mon, all_ok, "P1-neg poke-skip", !restored,
               !restored ? "detected" : "BUG: omitted mblock hidden");
        sf_selftest_poke_mblocks(&t, false);
    }

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

    /* M3/P1 teeth: skip one recorded mblock -> stock cross-check must diverge. */
    if (good && t.n_mblocks) {
        SfReplayDebug dbg = {
            .skip_mblock = true,
            .skip_mblock_index = 0,
        };
        bool matched = sf_replay_matches_stock_with_debug(&t, &dbg, &err);
        error_free(err);
        err = NULL;
        report(mon, all_ok, "P1-neg skip-mblock", !matched,
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

    if (good && t.n_gets) {
        SfReplayDebug dbg = {
            .skip_get = true,
            .skip_get_index = 0,
        };
        bool matched = sf_replay_matches_stock_with_debug(&t, &dbg, &err);
        error_free(err);
        err = NULL;
        snprintf(buf, sizeof(buf), "%s (%zu gets, info=%s)",
                 !matched ? "detected" : "BUG: undetected",
                 t.n_gets, t.gets[0].info->name);
        report(mon, all_ok, "M3-neg skip-get", !matched, buf);
    } else {
        report(mon, all_ok, "M3-neg skip-get", true,
               "SKIPPED (no get-handlers on this machine)");
    }

    if (good && t.n_posts) {
        SfReplayDebug dbg = {
            .skip_post = true,
            .skip_post_index = 0,
        };
        bool matched = sf_replay_matches_stock_with_debug(&t, &dbg, &err);
        error_free(err);
        err = NULL;
        report(mon, all_ok, "M3-neg skip-post", !matched,
               !matched ? "detected" : "BUG: undetected");
    }

    sf_replay_tables_destroy(&t);
}

/* ---- RAM cases (①②③) --------------------------------------------------- */

/* Build a fresh RAM root (full shadow + armed tracker), record watched pages,
 * run the guest, return #pages that changed. */
static uint32_t sf_snapshot_and_dirty(uint32_t *exp, uint32_t npages,
                                      unsigned run_ms, Error **errp)
{
    uint32_t changed = 0;

    if (!sf_snap_ram_root(errp)) {
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

/* In-place RAM rollback to the active node via the tracker (drain → plan →
 * 2-thread apply → re-baseline). Returns pages copied back. No device/CPU tail. */
static size_t sf_tst_rollback(void)
{
    const SfRestorePlan *p;

    sf_track_drain();
    p = sf_track_plan(sf_active);
    sf_track_apply(p->pages, p->n);
    sf_track_after_restore(sf_active);
    return p->n;
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
            size_t copied = sf_tst_rollback();
            uint32_t mism = sf_count_mismatch(exp, SF_ST_WATCH);
            bool ok = (changed > 0) && (mism == 0);
            snprintf(buf, sizeof(buf), "%u/%u pages changed then restored, "
                     "%u still wrong, copied-back=%zu", changed, SF_ST_WATCH,
                     mism, copied);
            report(mon, all_ok, "1 rollback", ok, buf);
        }
    }

    /* ② teeth: drop one dirtied page from the drain -> it stays wrong. Inject
     * BEFORE the run so the ring-full auto-drains during it also skip the page
     * (else the page would sneak into the persistent set before the roll-back). */
    {
        void *host0 = sf_gpa_to_host(SF_ST_BASE);
        sf_track_inject_drop(host0);
        uint32_t changed = sf_snapshot_and_dirty(exp, 1, 20, &err);
        if (changed == UINT32_MAX) {
            sf_track_inject_drop(NULL);
            report(mon, all_ok, "2 dropped-page teeth", false, error_get_pretty(err));
            error_free(err); err = NULL;
        } else {
            sf_tst_rollback();
            sf_track_inject_drop(NULL);
            uint32_t mism = sf_count_mismatch(exp, 1);
            /* teeth = the injected loss is observable (page not rolled back). */
            bool ok = (changed > 0) && (mism == 1);
            snprintf(buf, sizeof(buf), "%s (page0 changed=%u, wrong-after=%u)",
                     ok ? "loss detected" : "BUG: injected loss hidden",
                     changed, mism);
            report(mon, all_ok, "2 dropped-page teeth", ok, buf);
        }
    }

    /* ③ ring-full: zero loss across 4096 pages on a 1024-entry ring. The
     *   ring-full exits during the run drain into the persistent store. */
    {
        uint32_t changed = sf_snapshot_and_dirty(exp, SF_ST_NPAGES, 30, &err);
        if (changed == UINT32_MAX) {
            report(mon, all_ok, "3 ring-full zero-loss", false, error_get_pretty(err));
            error_free(err); err = NULL;
        } else {
            sf_tst_rollback();
            uint32_t mism = sf_count_mismatch(exp, SF_ST_NPAGES);
            /* changed > ring size proves the ring-full path was exercised. */
            bool ok = (changed > 1024) && (mism == 0);
            snprintf(buf, sizeof(buf), "%u pages changed (>ring 1024), %u lost",
                     changed, mism);
            report(mon, all_ok, "3 ring-full zero-loss", ok, buf);
        }

        /* teeth: under the same ring-full pressure, drop one dirtied page ->
         * the zero-loss check must catch it (inject before the run so every
         * ring-full drain skips it too). */
        {
            void *hostK = sf_gpa_to_host(SF_ST_BASE + 100 * SF_ST_PAGE);
            sf_track_inject_drop(hostK);
            changed = sf_snapshot_and_dirty(exp, SF_ST_NPAGES, 30, &err);
            if (changed == UINT32_MAX) {
                sf_track_inject_drop(NULL);
                report(mon, all_ok, "3-neg dropped-page teeth", false,
                       error_get_pretty(err));
                error_free(err); err = NULL;
            } else {
                sf_tst_rollback();
                sf_track_inject_drop(NULL);
                uint32_t mism = sf_count_mismatch(exp, SF_ST_NPAGES);
                bool teeth = (mism >= 1);
                snprintf(buf, sizeof(buf), "%s under ring-full: %u page(s) wrong",
                         teeth ? "loss detected" : "BUG: injected loss hidden",
                         mism);
                report(mon, all_ok, "3-neg dropped-page teeth", teeth, buf);
            }

            /* Info (not gated): skipping the explicit drain flush still loses ~0
             * pages because the KVM_EXIT_DIRTY_RING_FULL exits during the run
             * already drained into the store. A naive live-ring reader would lose
             * thousands. */
            changed = sf_snapshot_and_dirty(exp, SF_ST_NPAGES, 30, &err);
            if (changed != UINT32_MAX) {
                sf_kvm_set_skip_flush(true);
                sf_tst_rollback();
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
    if (!sf_snap_ram_root(&err)) {
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
    sf_tst_rollback();
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

/* ---- TSC-freeze case (⑦) ----------------------------------------------- */

/*
 * ⑦ TSC frozen across the boundary. Snapshot T0, run the guest briefly so its
 * TSC free-runs, then restore. A plain cpu_synchronize_post_init writes
 * MSR_IA32_TSC=T0, but stock KVM's kvm_synchronize_tsc treats a host TSC write
 * within ~1s of the free-running value as a CPU sync-up and keeps the old offset
 * (see sf/kvm_tsc.h) — so at a sub-1s gap the plain write is SWALLOWED and the
 * guest TSC stays at wall clock while kvmclock (explicit KVM_SET_CLOCK) freezes,
 * which is the clocksource skew the guest reports (cs vs wd). This case measures
 * both: the plain read (must show the swallow = teeth) and the forced read after
 * sf_kvm_refreeze_tsc (must be back at T0 = the fix). Host-side gate; the
 * authoritative check is the guest reading its own TSC across the boundary.
 */
static void sf_selftest_tsc(Monitor *mon, bool *all_ok)
{
    Error *err = NULL;
    SfReplayTables t;
    CPUState *cpu = first_cpu;
    char buf[224];
    /* ~30-50ms of TSC cycles at 1-3GHz: a frozen TSC sits well under this, a
     * 500ms free-run sits well over — so the threshold cleanly separates the two
     * without needing the guest's exact tsc_khz. */
    const uint64_t tol = 100000000ULL;

    if (!kvm_enabled() || !sf_kvm_dirty_ring_enabled()) {
        monitor_printf(mon, "sf: selftest[7 tsc-freeze]: SKIPPED "
                       "(needs KVM + dirty ring + running guest)\n");
        return;
    }
    if (sf_preparse(&t, &err) < 0) {
        report(mon, all_ok, "7 tsc-freeze", false, error_get_pretty(err));
        error_free(err);
        return;
    }
    if (!sf_snap_ram_root(&err)) {
        report(mon, all_ok, "7 tsc-freeze", false, error_get_pretty(err));
        error_free(err);
        sf_replay_tables_destroy(&t);
        return;
    }

    uint64_t tsc_snap = sf_kvm_read_tsc(cpu);   /* T0 */

    sf_run_guest_ms(500);                        /* free-run the TSC (sub-1s gap) */

    /* Restore inline, plain path first (no forced rewind). */
    sf_replay(&t);
    sf_tst_rollback();
    cpu_synchronize_post_init(cpu);              /* plain KVM_SET_MSRS(TSC=T0) */
    uint64_t tsc_plain = sf_kvm_read_tsc(cpu);

    /* The fix: forced double-write. Aim at the same value we measured (tsc_snap)
     * so this isolates the KVM mechanism (does force_tsc make the guest read the
     * requested value?) from whether env->tsc was replayed exactly — the latter
     * is ⑥'s job. */
    sf_kvm_force_tsc(cpu, tsc_snap);
    uint64_t tsc_forced = sf_kvm_read_tsc(cpu);

    uint64_t d_plain = tsc_plain > tsc_snap ? tsc_plain - tsc_snap
                                            : tsc_snap - tsc_plain;
    uint64_t d_forced = tsc_forced > tsc_snap ? tsc_forced - tsc_snap
                                              : tsc_snap - tsc_forced;

    bool teeth = d_plain > tol;    /* plain post_init did NOT rewind (bug visible) */
    bool frozen = d_forced < tol;  /* forced write rewound the TSC to T0 (fix works) */

    snprintf(buf, sizeof(buf),
             "gap=500ms d_plain=%" PRIu64 " d_forced=%" PRIu64
             " (teeth=%d frozen=%d)", d_plain, d_forced, teeth, frozen);
    report(mon, all_ok, "7 tsc-freeze (forced rewind)", frozen, buf);
    report(mon, all_ok, "7-neg tsc-sync-teeth (plain swallowed)", teeth, buf);

    sf_replay_tables_destroy(&t);
}

/* ---- M3 multi-level snap cases (T2/T3, plan -04 §7 cases 1-4) ------------
 * RAM-only cores (sf_snap_ram_root / build_diff / delta_restore) — no device,
 * no hot-profile guard — so they run under pc KVM like ①②③. dirty.elf writes
 * every page each pass, so we watch P0 (0x300000) and rely on it changing.
 */

/* Build a RUN diff layer on top of sf_active and make it active. */
static SfSnapNode *sf_make_layer(Monitor *mon, bool *all_ok)
{
    Error *err = NULL;
    SfSnapNode *n = sf_snap_build_diff(sf_active, SF_SNAP_RUN, &err);
    if (!n) {
        monitor_printf(mon, "sf: selftest[snap] build_diff FAILED: %s\n",
                       error_get_pretty(err));
        error_free(err);
        *all_ok = false;
        return NULL;
    }
    sf_active = n;
    return n;
}

static bool sf_snap_root(Monitor *mon)
{
    Error *err = NULL;
    SfSnapNode *r = sf_snap_ram_root(&err);
    if (!r) {
        monitor_printf(mon, "sf: selftest[snap] ram_root FAILED: %s\n",
                       error_get_pretty(err));
        error_free(err);
        return false;
    }
    return true;
}

static void sf_selftest_snap(Monitor *mon, bool *all_ok)
{
    char buf[192];
    Error *err = NULL;

    if (!kvm_enabled() || !sf_kvm_dirty_ring_enabled()) {
        monitor_printf(mon, "sf: selftest[snap 1-4]: SKIPPED "
                       "(needs KVM + dirty ring + running guest)\n");
        return;
    }

    /* ---- Case A: cross-layer resolve + same-layer loop + resolve teeth ---- */
    {
        if (!sf_snap_root(mon)) { *all_ok = false; return; }
        uint32_t v0 = sf_rd32(SF_ST_BASE);
        sf_run_guest_ms(20);
        uint32_t v1 = sf_rd32(SF_ST_BASE);
        SfSnapNode *L1 = sf_make_layer(mon, all_ok);
        sf_run_guest_ms(20);
        uint32_t v2 = sf_rd32(SF_ST_BASE);
        SfSnapNode *L2 = sf_make_layer(mon, all_ok);
        if (!L1 || !L2) { return; }

        /* cross-layer: active=L2 → restore L1 ⇒ P0 must be L1's value v1. */
        sf_snap_delta_restore(L1->id, &err); error_free(err); err = NULL;
        bool cross = (sf_rd32(SF_ST_BASE) == v1);

        /* same-layer loop: active=L1, dirty, restore L1 ⇒ P0 stays v1. */
        sf_run_guest_ms(20);
        uint32_t v3 = sf_rd32(SF_ST_BASE);
        sf_snap_delta_restore(L1->id, &err); error_free(err); err = NULL;
        bool same = (sf_rd32(SF_ST_BASE) == v1) && (v3 != v1);
        (void)v0; (void)v2;

        snprintf(buf, sizeof(buf), "cross=%d same-layer=%d (v1=%u v3=%u -> %u)",
                 cross, same, v1, v3, sf_rd32(SF_ST_BASE));
        report(mon, all_ok, "A cross+same-layer resolve", cross && same, buf);

        /* teeth: resolve skips L1 → restore L1 gives root's v0, not v1. */
        sf_resolve_inject_skip_node(L1->id);
        /* re-run to rebuild a leaf above L1 so src != dst. */
        sf_run_guest_ms(20);
        SfSnapNode *L2b = sf_make_layer(mon, all_ok);
        if (L2b) {
            sf_snap_delta_restore(L1->id, &err); error_free(err); err = NULL;
            uint32_t got = sf_rd32(SF_ST_BASE);
            bool teeth = (got != v1);
            snprintf(buf, sizeof(buf), "%s (got=%u want=%u v0=%u)",
                     teeth ? "RED detected" : "BUG: resolve skip hidden",
                     got, v1, v0);
            report(mon, all_ok, "A-neg resolve-skip teeth", teeth, buf);
        }
        sf_resolve_inject_skip_node(0xFFFFFFFFU);
    }

    /* ---- Case B: save-integrity teeth (drop a diff page) ---- */
    {
        if (!sf_snap_root(mon)) { *all_ok = false; return; }
        uint32_t v0 = sf_rd32(SF_ST_BASE);
        void *host0 = sf_gpa_to_host(SF_ST_BASE);
        /* Drop P0 from every drain (incl. ring-full auto-drains during the run)
         * so build_diff never sees it → L1's diff omits P0. */
        sf_track_inject_drop(host0);
        sf_run_guest_ms(20);
        uint32_t v1 = sf_rd32(SF_ST_BASE);
        SfSnapNode *L1 = sf_make_layer(mon, all_ok);
        sf_track_inject_drop(NULL);
        if (!L1) { return; }
        sf_run_guest_ms(20);
        sf_snap_delta_restore(L1->id, &err); error_free(err); err = NULL;
        uint32_t got = sf_rd32(SF_ST_BASE);
        /* L1 missed P0 ⇒ restore resolves to root v0, not the saved v1. */
        bool teeth = (got != v1);
        snprintf(buf, sizeof(buf), "%s (got=%u v0=%u saved-v1=%u)",
                 teeth ? "RED detected" : "BUG: dropped page hidden",
                 got, v0, v1);
        report(mon, all_ok, "B save-integrity teeth", teeth, buf);
    }

    /* ---- Case C: multi-level undo (chain → root) ---- */
    {
        if (!sf_snap_root(mon)) { *all_ok = false; return; }
        uint32_t v0 = sf_rd32(SF_ST_BASE);
        sf_run_guest_ms(20); sf_make_layer(mon, all_ok);
        sf_run_guest_ms(20); sf_make_layer(mon, all_ok);
        sf_run_guest_ms(20); SfSnapNode *L3 = sf_make_layer(mon, all_ok);
        if (!L3) { return; }
        sf_run_guest_ms(20);
        /* restore all the way back to root ⇒ P0 == v0. */
        SfSnapNode *root = sf_active;
        while (root->parent) { root = root->parent; }
        sf_snap_delta_restore(root->id, &err); error_free(err); err = NULL;
        uint32_t got = sf_rd32(SF_ST_BASE);
        bool ok = (got == v0);
        snprintf(buf, sizeof(buf), "%s (got=%u v0=%u)",
                 ok ? "rolled back to root" : "BUG: not root value", got, v0);
        report(mon, all_ok, "C multi-level undo", ok, buf);
    }

    /* Case D (per-page HOT blind-spot) retired: HOT is subsumed by the flat
     * store's BLIND policy (whole plan kept), verified KVM-free by the R3
     * flat-store case; save-integrity teeth are Case B. */

    /* ---- Case E (T8): tree fork + cross-sibling restore + resolve teeth ---- */
    {
        if (!sf_snap_root(mon)) { *all_ok = false; return; }
        uint32_t v0 = sf_rd32(SF_ST_BASE);
        sf_run_guest_ms(20);
        uint32_t v1 = sf_rd32(SF_ST_BASE);
        SfSnapNode *L1 = sf_make_layer(mon, all_ok);   /* branch 1: P0 = v1 */
        if (!L1) { return; }
        SfSnapNode *root = sf_active;
        while (root->parent) { root = root->parent; }

        /* back to root, build a sibling L2 (fork). */
        sf_snap_delta_restore(root->id, &err); error_free(err); err = NULL;
        sf_run_guest_ms(20);
        uint32_t v2 = sf_rd32(SF_ST_BASE);
        SfSnapNode *L2 = sf_make_layer(mon, all_ok);   /* branch 2: P0 = v2 */
        if (!L2) { return; }

        /* cross-sibling: active=L2 → restore L1 ⇒ P0 must be L1's v1 (not L2's
         * v2, not root's v0). This exercises the dst-side path union + resolve
         * walking across the fork. */
        sf_snap_delta_restore(L1->id, &err); error_free(err); err = NULL;
        bool cross = (sf_rd32(SF_ST_BASE) == v1) && (v1 != v2) && (v1 != v0);

        /* teeth: resolve skips L1 → restore L1 yields root's v0, not v1. */
        sf_snap_delta_restore(L2->id, &err); error_free(err); err = NULL; /* active=L2 */
        sf_resolve_inject_skip_node(L1->id);
        sf_snap_delta_restore(L1->id, &err); error_free(err); err = NULL;
        uint32_t got = sf_rd32(SF_ST_BASE);
        bool teeth = (got != v1);
        sf_resolve_inject_skip_node(0xFFFFFFFFU);
        (void)v2;
        snprintf(buf, sizeof(buf), "cross-sibling=%d teeth=%s (got=%u want=%u v0=%u)",
                 cross, teeth ? "RED detected" : "BUG: resolve skip hidden",
                 got, v1, v0);
        report(mon, all_ok, "E tree fork cross-sibling", cross && teeth, buf);
    }
}

/* ---- M3 NO_RESTORE + tripwire (T5, plan 2026-07-06-06 §3 case 7) -------- */

static void sf_selftest_tripwire(Monitor *mon, bool *all_ok)
{
    char buf[192];
    Error *err = NULL;
    void *host0;
    uint32_t v0, h = 0xDEADBEEFu;

    if (!kvm_enabled() || !sf_kvm_dirty_ring_enabled()) {
        monitor_printf(mon, "sf: selftest[7 NO_RESTORE+tripwire]: SKIPPED "
                       "(needs KVM + dirty ring)\n");
        return;
    }

    host0 = sf_gpa_to_host(SF_ST_BASE);

    /* ---- (a) excluded page: host write does NOT trip; restore keeps host val ---- */
    {
        if (!sf_snap_root(mon)) { *all_ok = false; return; }
        v0 = sf_rd32(SF_ST_BASE);
        sf_exclude_clear();
        sf_exclude_add((uint64_t)(uintptr_t)host0, SF_ST_PAGE, 1);

        sf_tripwire_reset_count();
        cpu_physical_memory_write(SF_ST_BASE, &h, sizeof(h));   /* host write via API */
        bool no_trip = (sf_tripwire_count() == 0);              /* excluded → 放行 */

        sf_snap_delta_restore(sf_active->id, &err); error_free(err); err = NULL;
        uint32_t got = sf_rd32(SF_ST_BASE);
        bool kept = (got == h) && (h != v0);                    /* not rolled back */
        snprintf(buf, sizeof(buf), "no-trip=%d kept-host=%d (got=%u H=%u v0=%u)",
                 no_trip, kept, got, h, v0);
        report(mon, all_ok, "7a NO_RESTORE exempt+keep", no_trip && kept, buf);
        sf_exclude_clear();
    }

    /* ---- (b) host write to snapshot RAM trips;摘钩子 → 静默通过(牙齿) ---- */
    {
        if (!sf_snap_root(mon)) { *all_ok = false; return; }
        sf_exclude_clear();   /* P0 NOT excluded now */
        sf_tripwire_reset_count();
        cpu_physical_memory_write(SF_ST_BASE, &h, sizeof(h));
        bool tripped = (sf_tripwire_count() >= 1);

        /* teeth: disable the hook → the same write goes undetected (proves the
         * tripwire itself is what catches it). */
        sf_tripwire_inject_disable(true);
        sf_tripwire_reset_count();
        cpu_physical_memory_write(SF_ST_BASE, &h, sizeof(h));
        bool silent = (sf_tripwire_count() == 0);
        sf_tripwire_inject_disable(false);

        snprintf(buf, sizeof(buf), "tripped=%d silent-when-disabled=%d",
                 tripped, silent);
        report(mon, all_ok, "7b tripwire teeth", tripped && silent, buf);
    }

    /* ---- (c) exclude registered mid-chain: old diff has the page, restore
     *      still must NOT roll it back (接入点 2 牙齿) ---- */
    {
        if (!sf_snap_root(mon)) { *all_ok = false; return; }
        v0 = sf_rd32(SF_ST_BASE);
        sf_run_guest_ms(20);
        uint32_t v1 = sf_rd32(SF_ST_BASE);
        SfSnapNode *L1 = sf_make_layer(mon, all_ok);   /* L1's diff contains P0 */
        if (!L1) { return; }
        sf_exclude_clear();
        sf_exclude_add((uint64_t)(uintptr_t)host0, SF_ST_PAGE, 1); /* register mid-chain */

        sf_run_guest_ms(20);
        uint32_t v2 = sf_rd32(SF_ST_BASE);
        sf_snap_delta_restore(L1->id, &err); error_free(err); err = NULL;
        uint32_t got = sf_rd32(SF_ST_BASE);
        /* excluded ⇒ P0 not rolled back ⇒ stays live v2, not L1's v1. */
        bool kept = (got == v2) && (v2 != v1);
        snprintf(buf, sizeof(buf), "%s (got=%u v2=%u v1=%u)",
                 kept ? "excluded overrides old diff" : "BUG: rolled back old diff",
                 got, v2, v1);
        report(mon, all_ok, "7c mid-chain exclude", kept, buf);
        sf_exclude_clear();
    }
}

/* ---- R3 spike (plan 2026-07-06-07 §3): EPT rebuild after RAM remap -------- */
bool sf_r3_spike_run(Monitor *mon, hwaddr gpa)
{
    size_t psize = qemu_real_host_page_size();
    Error *err = NULL;
    char buf[256];

    if (!kvm_enabled() || !sf_kvm_dirty_ring_enabled()) {
        monitor_printf(mon, "sf-r3: SKIPPED (needs KVM + dirty ring)\n");
        return false;
    }
    void *host = sf_gpa_to_host(gpa);
    if (!host) {
        monitor_printf(mon, "sf-r3: gpa 0x%" HWADDR_PRIx " not in RAM\n", gpa);
        return false;
    }

    /* Start dirty logging so the post-remap guest write is trackable. */
    if (!sf_snap_ram_root(&err)) {
        monitor_printf(mon, "sf-r3: snapshot failed: %s\n", error_get_pretty(err));
        error_free(err);
        return false;
    }
    /* Snapshot the page before remap (also what we write to the file). */
    g_autofree uint8_t *before = g_malloc(psize);
    memcpy(before, host, psize);

    /* File holding the page contents; remap it MAP_PRIVATE|MAP_FIXED over the
     * exact host page. This is the Nyx cold-start move (shadow_memory.c:299). */
    char tmpl[] = "/tmp/sf_r3_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        monitor_printf(mon, "sf-r3: mkstemp failed: %s\n", strerror(errno));
        return false;
    }
    unlink(tmpl);
    if (write(fd, before, psize) != (ssize_t)psize) {
        monitor_printf(mon, "sf-r3: write failed\n");
        close(fd);
        return false;
    }
    lseek(fd, 0, SEEK_SET);

    if (munmap(host, psize) != 0) {
        monitor_printf(mon, "sf-r3: munmap failed: %s\n", strerror(errno));
        close(fd);
        return false;
    }
    void *p = mmap(host, psize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_FIXED, fd, 0);
    if (p != host) {
        monitor_printf(mon, "sf-r3: mmap MAP_FIXED returned %p (want %p): %s\n",
                       p, host, strerror(errno));
        close(fd);
        return false;
    }

    /* QEMU's host view now sees the file mapping. If KVM's mmu-notifier fired,
     * the EPT entry for this GPA was invalidated; the next guest access rebuilds
     * it to the new physical page. Run the guest — if the notifier did NOT fire,
     * the guest access to this page hits a stale EPT → SIGSEGV/corruption → the
     * process crashes here (R3 FAIL, observed by the caller). */
    uint32_t pre = sf_rd32(gpa);
    sf_run_guest_ms(60);
    uint32_t post = sf_rd32(gpa);
    sf_track_drain();
    uint64_t collected = sf_track_plan(sf_active)->n;

    bool survived = true;   /* we're here → guest did not crash */
    bool advanced = (post != pre);          /* guest write reached the new page */
    bool tracked = (collected > 0);         /* dirty ring saw the write */
    snprintf(buf, sizeof(buf),
             "survived=%d advanced=%d tracked=%d (pre=%u post=%u collected=%llu)",
             survived, advanced, tracked, pre, post,
             (unsigned long long)collected);
    monitor_printf(mon, "sf-r3: %s\n", buf);
    report(mon, NULL, "R3 remap EPT-rebuild", survived && advanced && tracked, buf);

    close(fd);
    return survived && advanced && tracked;
}

/* ---- R3-full (plan 2026-07-06-07 §3): whole-RAM scale-up of the R3 spike ----
 * Cold-start step 2 at full scale: remap EVERY guest RAM block to a dump file
 * with munmap+mmap(MAP_PRIVATE|MAP_FIXED) — the Nyx shadow_memory.c:299-306
 * loop. R3 proved one page rebuilds EPT; this proves the whole-RAM loop. Pause
 * the guest, dump each block's live host memory to a tmp file (block-id order =
 * root.ram layout), enable dirty logging, swap every block to its file slice,
 * resume, and require the guest to survive + advance (a write reaches a
 * CoW-private page) + the dirty ring to track it. Destructive: leaves guest RAM
 * file-mapped (CoW); the VM keeps running on the mapping, but a later sf
 * snapshot/restore would mix file-backed live RAM with the pre-remap shadow —
 * reset the VM after spiking. */
bool sf_remap_all_run(Monitor *mon)
{
    Error *err = NULL;
    char buf[256];
    RAMBlock *block;
    struct { void *host; uint64_t len; uint64_t off; } *r;
    int n = 0;
    uint64_t total = 0, off = 0;
    char tmpl[] = "/tmp/sf_remap_all_XXXXXX";
    int fd;
    uint8_t *file_map;
    uint32_t pre, post;
    uint64_t collected;
    bool survived, advanced, tracked;

    if (!kvm_enabled() || !sf_kvm_dirty_ring_enabled()) {
        monitor_printf(mon, "sf-remap-all: SKIPPED (needs KVM + dirty ring)\n");
        return false;
    }

    /* Pause the guest before touching its RAM — a whole-RAM remap while running
     * would unmap the code the vcpu is executing. */
    if (runstate_is_running()) {
        vm_stop(RUN_STATE_PAUSED);
    }

    /* Collect blocks + file offsets (block-id order = root.ram layout, same as
     * sf_persist_root_ram / sf_blocks_enumerate). */
    RAMBLOCK_FOREACH(block) {
        if (!block->host || !block->used_length) {
            continue;
        }
        n++;
        total += block->used_length;
    }
    if (n == 0) {
        monitor_printf(mon, "sf-remap-all: no RAM blocks\n");
        return false;
    }
    r = g_new(typeof(*r), n);
    n = 0;
    RAMBLOCK_FOREACH(block) {
        if (!block->host || !block->used_length) {
            continue;
        }
        r[n].host = block->host;
        r[n].len = block->used_length;
        r[n].off = off;
        off += block->used_length;
        n++;
    }

    /* Dump live RAM → tmp file via a writable shared mapping, then drop it so
     * only the per-block MAP_PRIVATE remaps reference the file. */
    fd = mkstemp(tmpl);
    if (fd < 0) {
        monitor_printf(mon, "sf-remap-all: mkstemp failed: %s\n", strerror(errno));
        g_free(r);
        return false;
    }
    unlink(tmpl);
    if (ftruncate(fd, (off_t)total) != 0) {
        monitor_printf(mon, "sf-remap-all: ftruncate failed: %s\n", strerror(errno));
        close(fd);
        g_free(r);
        return false;
    }
    file_map = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (file_map == MAP_FAILED) {
        monitor_printf(mon, "sf-remap-all: dump mmap failed: %s\n", strerror(errno));
        close(fd);
        g_free(r);
        return false;
    }
    for (int i = 0; i < n; i++) {
        memcpy(file_map + r[i].off, r[i].host, r[i].len);
    }
    munmap(file_map, total);

    /* Enable KVM dirty logging so post-remap writes are tracked. The memslot's
     * userspace address is unchanged (MAP_FIXED keeps it); KVM logs by GPA. */
    if (!sf_snap_ram_root(&err)) {
        monitor_printf(mon, "sf-remap-all: snapshot failed: %s\n",
                       error_get_pretty(err));
        error_free(err);
        close(fd);
        g_free(r);
        return false;
    }

    /* The swap: each block's host range → its file slice, MAP_PRIVATE|MAP_FIXED.
     * KVM memslot is already registered; the mmu-notifier rebuilds EPT to the
     * file-backed pages on next guest access (R3 proved this for one page; this
     * loop is the whole-RAM version). */
    for (int i = 0; i < n; i++) {
        if (munmap(r[i].host, r[i].len) != 0) {
            monitor_printf(mon, "sf-remap-all: munmap block %d failed: %s\n",
                           i, strerror(errno));
            close(fd);
            g_free(r);
            return false;
        }
        void *p = mmap(r[i].host, r[i].len,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_FIXED, fd, r[i].off);
        if (p == MAP_FAILED) {
            monitor_printf(mon, "sf-remap-all: mmap block %d failed: %s\n",
                           i, strerror(errno));
            close(fd);
            g_free(r);
            return false;
        }
    }

    /* Reaching here means the remap didn't crash the process. Now run the guest:
     * if EPT did NOT rebuild for some block, the vcpu faults on a stale mapping
     * → SIGSEGV here (survived=false, observed by the caller as a crash). */
    pre = sf_rd32(SF_ST_BASE);
    sf_run_guest_ms(60);
    post = sf_rd32(SF_ST_BASE);
    sf_track_drain();
    collected = sf_track_plan(sf_active)->n;

    survived = true;            /* we're here → no stale-EPT crash */
    advanced = (post != pre);   /* guest write reached a CoW-private page */
    tracked = (collected > 0);  /* dirty ring saw the write(s) */
    snprintf(buf, sizeof(buf),
             "survived=%d advanced=%d tracked=%d (blocks=%d total=%lluB "
             "pre=%u post=%u collected=%llu)",
             survived, advanced, tracked, n, (unsigned long long)total,
             pre, post, (unsigned long long)collected);
    monitor_printf(mon, "sf-remap-all: %s\n", buf);
    report(mon, NULL, "R3-full remap all-blocks",
           survived && advanced && tracked, buf);

    close(fd);
    g_free(r);
    return survived && advanced && tracked;
}

/* ---- ramstore FILE backing round-trip (T6 persistence, plan 07 §2) ----
 * Pure host-side (no guest/KVM): create a file-backed store, fill index+data,
 * seal, reopen read-only, verify byte-for-byte + lookup. Teeth: a corrupted
 * payload byte on disk must be rejected by the crc check on open. */
static void sf_selftest_ramstore_file(Monitor *mon, bool *all_ok)
{
    char buf[192];
    Error *err = NULL;
    const uint32_t n = 4;
    size_t psize = qemu_real_host_page_size();
    SfPageKey keys[4] = { SF_KEY(0, 0), SF_KEY(0, 5), SF_KEY(1, 2), SF_KEY(2, 100) };
    SfRamStore w, r;
    char *dir = g_dir_make_tmp("sf-ramstore-XXXXXX", NULL);
    char *path;

    if (!dir) {
        report(mon, all_ok, "F ramstore-file", false, "g_dir_make_tmp failed");
        return;
    }
    path = g_build_filename(dir, "node.ram", NULL);

    if (sf_ramstore_create_file(&w, n, path, &err) < 0) {
        report(mon, all_ok, "F ramstore-file", false, error_get_pretty(err));
        error_free(err);
        goto out;
    }
    for (uint32_t i = 0; i < n; i++) {
        w.index[i] = keys[i];
        memset(w.data + (size_t)i * psize, 0xA0 + i, psize);
    }
    if (sf_ramstore_seal(&w, &err) < 0) {
        report(mon, all_ok, "F ramstore-file", false, error_get_pretty(err));
        error_free(err);
        sf_ramstore_destroy(&w);
        goto out;
    }
    sf_ramstore_destroy(&w);   /* drop the writable mapping; file persists */

    if (sf_ramstore_open_file(&r, path, &err) < 0) {
        report(mon, all_ok, "F ramstore-file", false, error_get_pretty(err));
        error_free(err);
        goto out;
    }
    bool ok = (r.n_pages == n);
    for (uint32_t i = 0; ok && i < n; i++) {
        ok = (r.index[i] == keys[i]) &&
             (r.data[(size_t)i * psize] == (uint8_t)(0xA0 + i)) &&
             (sf_ramstore_lookup(&r, keys[i]) == (int)i);
    }
    sf_ramstore_destroy(&r);
    snprintf(buf, sizeof(buf), "reopen n=%u index+data+lookup match=%d", n, ok);
    report(mon, all_ok, "F ramstore-file roundtrip", ok, buf);

    /* teeth: flip an index byte on disk (offset = 8-aligned after hdr) → crc rejects. */
    {
        int fd = open(path, O_RDWR);
        uint8_t bad = 0xFF;
        bool rejected = false;
        if (fd >= 0 && pwrite(fd, &bad, 1, ROUND_UP(sizeof(SfStoreHdr), 8)) == 1) {
            close(fd);
            SfRamStore bad_r;
            rejected = (sf_ramstore_open_file(&bad_r, path, &err) < 0);
            if (!rejected) {
                sf_ramstore_destroy(&bad_r);
            }
            error_free(err);
            err = NULL;
        } else if (fd >= 0) {
            close(fd);
        }
        snprintf(buf, sizeof(buf), "corrupt-byte rejected=%d", rejected);
        report(mon, all_ok, "F-neg ramstore-file crc teeth", rejected, buf);
    }

out:
    unlink(path);
    rmdir(dir);
    g_free(path);
    g_free(dir);
}

/* ---- tree persist/load round-trip (T6, plan 07 §1) ---- *
 * Build root→L1→L2 (dirtied pages), persist to a tmpdir, load into a fresh tree,
 * and require the loaded chain (ids/parents) + each diff store (index+data) to
 * match the live tree byte-for-byte. Teeth: a corrupted manifest is rejected.
 * Needs KVM + dirty ring (to build diffs). */
static bool sf_store_eq(const SfRamStore *a, const SfRamStore *b)
{
    size_t psize = qemu_real_host_page_size();
    if (a->n_pages != b->n_pages) {
        return false;
    }
    if (a->n_pages == 0) {
        return true;
    }
    return memcmp(a->index, b->index, (size_t)a->n_pages * sizeof(SfPageKey)) == 0
        && memcmp(a->data, b->data, (size_t)a->n_pages * psize) == 0;
}

static void sf_rmrf_persist_dir(const char *dir)
{
    char *nodes = g_build_filename(dir, "nodes", NULL);
    GDir *d = g_dir_open(nodes, 0, NULL);
    char *p;

    if (d) {
        const char *name;
        while ((name = g_dir_read_name(d))) {
            p = g_build_filename(nodes, name, NULL);
            unlink(p);
            g_free(p);
        }
        g_dir_close(d);
    }
    rmdir(nodes);
    g_free(nodes);
    p = g_build_filename(dir, "manifest.json", NULL); unlink(p); g_free(p);
    p = g_build_filename(dir, "nodes.log", NULL); unlink(p); g_free(p);
    p = g_build_filename(dir, "root.ram", NULL); unlink(p); g_free(p);
    p = g_build_filename(dir, "root.dev", NULL); unlink(p); g_free(p);
    p = g_build_filename(dir, "node.dev", NULL); unlink(p); g_free(p);
    rmdir(dir);
}

/* Count nodes in a loaded subtree (crash-tail teeth: verify the truncated tail
 * was dropped but the rest of the log survived). */
static size_t sf_count_nodes(SfSnapNode *n)
{
    size_t cnt = 1;
    SfSnapNode *c;
    QLIST_FOREACH(c, &n->children, sibling) {
        cnt += sf_count_nodes(c);
    }
    return cnt;
}

static void sf_selftest_persist(Monitor *mon, bool *all_ok)
{
    char buf[192];
    Error *err = NULL;
    SfSnapNode *L1, *L2, *root, *lroot = NULL, *lL1, *lL2;
    char *dir;

    if (!kvm_enabled() || !sf_kvm_dirty_ring_enabled()) {
        monitor_printf(mon, "sf: selftest[persist]: SKIPPED (needs KVM + dirty ring)\n");
        return;
    }

    dir = g_dir_make_tmp("sf-persist-XXXXXX", NULL);
    if (!dir) { report(mon, all_ok, "G persist", false, "g_dir_make_tmp failed"); return; }

    setenv("SF_ROOT_DIR", dir, 1);
    if (!sf_snap_root(mon)) {
        unsetenv("SF_ROOT_DIR");
        *all_ok = false;
        goto out;
    }
    unsetenv("SF_ROOT_DIR");

    sf_run_guest_ms(20); L1 = sf_make_layer(mon, all_ok);
    sf_run_guest_ms(20); L2 = sf_make_layer(mon, all_ok);
    if (!L1 || !L2) { goto out; }
    root = sf_active;
    while (root->parent) { root = root->parent; }

    if (sf_snap_persist(root, dir, &err) < 0) {
        report(mon, all_ok, "G persist", false, error_get_pretty(err));
        error_free(err); goto out;
    }
    if (sf_snap_load(dir, &lroot, &err) < 0) {
        report(mon, all_ok, "G persist", false, error_get_pretty(err));
        error_free(err); goto out;
    }

    lL1 = QLIST_FIRST(&lroot->children);
    lL2 = lL1 ? QLIST_FIRST(&lL1->children) : NULL;
    bool ok = lL1 && lL2 &&
              lroot->id == root->id && lL1->id == L1->id && lL2->id == L2->id &&
              lL1->parent == lroot && lL2->parent == lL1 &&
              sf_store_eq(&lL1->ram, &L1->ram) && sf_store_eq(&lL2->ram, &L2->ram);
    snprintf(buf, sizeof(buf), "chain+stores match=%d (L1=%up L2=%up)",
             ok, L1->ram.n_pages, L2->ram.n_pages);
    report(mon, all_ok, "G persist roundtrip", ok, buf);
    snprintf(buf, sizeof(buf), "root-file-backed=%d path=%s",
             root->ram.backing == SF_BACKING_FILE,
             root->ram.path ? root->ram.path : "(null)");
    report(mon, all_ok, "G root-file-backed", root->ram.backing == SF_BACKING_FILE,
           buf);
    sf_snap_free_loaded(lroot);
    lroot = NULL;

    {
        char *pdir = g_dir_make_tmp("sf-promote-XXXXXX", NULL);
        char *orphan_dir = g_dir_make_tmp("sf-promote-orphan-XXXXXX", NULL);
        SfSnapNode *pload = NULL;
        bool rejected, root_ok, orphan_rejected = false, promote_ok;

        if (!pdir || !orphan_dir) {
            report(mon, all_ok, "G promote", false, "g_dir_make_tmp failed");
        } else {
            rejected = (sf_snap_promote(L2, pdir, &err) < 0);
            error_free(err);
            err = NULL;
            root_ok = (sf_snap_promote(root, pdir, &err) == 0);
            error_free(err);
            err = NULL;
            orphan_rejected = (sf_snap_promote(L1, orphan_dir, &err) < 0);
            error_free(err);
            err = NULL;
            promote_ok = rejected &&
                 root_ok &&
                 orphan_rejected &&
                 sf_snap_promote(L1, pdir, &err) == 0 &&
                 sf_snap_promote(L2, pdir, &err) == 0 &&
                 sf_snap_load(pdir, &pload, &err) == 0;
            if (promote_ok) {
                SfSnapNode *pL1 = QLIST_FIRST(&pload->children);
                SfSnapNode *pL2 = pL1 ? QLIST_FIRST(&pL1->children) : NULL;
                promote_ok = pL1 && pL2 &&
                             QLIST_EMPTY(&pL2->children) &&
                             pload->id == root->id &&
                             pL1->id == L1->id &&
                             pL2->id == L2->id &&
                             root->state == SF_SNAP_PERSISTED &&
                             L1->state == SF_SNAP_PERSISTED &&
                             L2->state == SF_SNAP_PERSISTED &&
                             L1->ram.backing == SF_BACKING_FILE &&
                             L2->ram.backing == SF_BACKING_FILE;
            }
            snprintf(buf, sizeof(buf),
                     "disconnected=%d orphan-dir=%d chain-only+file-backed=%d",
                     rejected, orphan_rejected, promote_ok);
            report(mon, all_ok, "G promote connected-prefix", promote_ok, buf);
            if (pload) {
                sf_snap_free_loaded(pload);
            }
            error_free(err);
            err = NULL;
            sf_rmrf_persist_dir(pdir);
            sf_rmrf_persist_dir(orphan_dir);
            g_free(pdir);
            g_free(orphan_dir);
        }
    }

    /* teeth: clobber the manifest's first byte → load must fail. */
    {
        char *mpath = g_build_filename(dir, "manifest.json", NULL);
        int fd = open(mpath, O_RDWR);
        bool rejected = false;
        SfSnapNode *bad = NULL;
        if (fd >= 0 && pwrite(fd, "X", 1, 0) == 1) {
            close(fd);
            rejected = (sf_snap_load(dir, &bad, &err) < 0);
            if (!rejected) { sf_snap_free_loaded(bad); }
            error_free(err); err = NULL;
        } else if (fd >= 0) {
            close(fd);
        }
        g_free(mpath);
        snprintf(buf, sizeof(buf), "corrupt-manifest rejected=%d", rejected);
        report(mon, all_ok, "G-neg persist manifest teeth", rejected, buf);
    }

    /* G 加分叉牙齿: root→A→{B,C} 兄弟,promote A/B/C 后 cold-start(B)/(C) marker
     * 各命中、互不丢失。旧单路径 manifest 全量重写会丢兄弟 → cold-start(B) 找不
     * 到 B 节点而失败;append-log 每次只追加自己一行,兄弟俱在。 */
    {
        char *fdir = g_dir_make_tmp("sf-fork-XXXXXX", NULL);
        if (!fdir) {
            report(mon, all_ok, "G fork promote siblings", false,
                   "g_dir_make_tmp failed");
        } else {
            SfSnapNode *froot = NULL, *fA = NULL, *fB = NULL, *fC = NULL;
            uint32_t b_id = 0, c_id = 0, vB = 0, vC = 0;
            bool prom_ok = true, cold_b = false, cold_c = false, fok = true;
            do {
                setenv("SF_ROOT_DIR", fdir, 1);
                bool rok = sf_snap_root(mon);
                unsetenv("SF_ROOT_DIR");
                if (!rok) { *all_ok = false; fok = false; break; }
                sf_run_guest_ms(20);
                fA = sf_make_layer(mon, all_ok);
                if (!fA) { fok = false; break; }
                froot = sf_active;
                while (froot->parent) { froot = froot->parent; }
                /* B: child of A, marker = vB */
                sf_run_guest_ms(20);
                vB = sf_rd32(SF_ST_BASE);
                fB = sf_make_layer(mon, all_ok);
                if (!fB) { fok = false; break; }
                /* C: sibling of B under A, distinct marker vC */
                sf_snap_delta_restore(fA->id, &err); error_free(err); err = NULL;
                sf_run_guest_ms(20);
                vC = sf_rd32(SF_ST_BASE);
                fC = sf_make_layer(mon, all_ok);
                if (!fC) { fok = false; break; }
                b_id = fB->id; c_id = fC->id;

                if (sf_snap_promote(froot, fdir, &err) < 0) {
                    prom_ok = false; error_free(err); err = NULL; break;
                }
                if (sf_snap_promote(fA, fdir, &err) < 0) {
                    prom_ok = false; error_free(err); err = NULL; break;
                }
                if (sf_snap_promote(fB, fdir, &err) < 0) {
                    prom_ok = false; error_free(err); err = NULL; break;
                }
                if (sf_snap_promote(fC, fdir, &err) < 0) {
                    prom_ok = false; error_free(err); err = NULL; break;
                }
                if (sf_cold_start(fdir, b_id, &err) < 0) {
                    error_free(err); err = NULL; break;
                }
                cold_b = (sf_rd32(SF_ST_BASE) == vB);
                if (!cold_b) { break; }
                if (sf_cold_start(fdir, c_id, &err) < 0) {
                    error_free(err); err = NULL; break;
                }
                cold_c = (sf_rd32(SF_ST_BASE) == vC);
            } while (0);
            bool fteeth = fok && prom_ok && cold_b && cold_c && (vB != vC);
            snprintf(buf, sizeof(buf),
                     "prom=%d coldB=%d coldC=%d vB=%u vC=%u",
                     prom_ok, cold_b, cold_c, vB, vC);
            report(mon, all_ok, "G fork promote siblings (cold-start B/C)",
                   fteeth, buf);
            sf_rmrf_persist_dir(fdir);
            g_free(fdir);
        }
    }

    /* G 崩溃尾行丢弃: 往 nodes.log 追加半行(无换行)模拟 crash mid-append,load
     * 必须丢弃残缺尾行、其余节点完好(snapshot-tree.md §5.2)。 */
    {
        char *cdir = g_dir_make_tmp("sf-crash-XXXXXX", NULL);
        if (!cdir) {
            report(mon, all_ok, "G crash tail-drop", false,
                   "g_dir_make_tmp failed");
        } else {
            SfSnapNode *croot = NULL, *cL1 = NULL, *cL2 = NULL;
            bool cok = true, dropped = false;
            size_t cn = 0;
            do {
                setenv("SF_ROOT_DIR", cdir, 1);
                bool rok = sf_snap_root(mon);
                unsetenv("SF_ROOT_DIR");
                if (!rok) { *all_ok = false; cok = false; break; }
                sf_run_guest_ms(20); cL1 = sf_make_layer(mon, all_ok);
                if (!cL1) { cok = false; break; }
                sf_run_guest_ms(20); cL2 = sf_make_layer(mon, all_ok);
                if (!cL2) { cok = false; break; }
                croot = sf_active;
                while (croot->parent) { croot = croot->parent; }
                if (sf_snap_promote(croot, cdir, &err) < 0) {
                    cok = false; error_free(err); err = NULL; break;
                }
                if (sf_snap_promote(cL1, cdir, &err) < 0) {
                    cok = false; error_free(err); err = NULL; break;
                }
                if (sf_snap_promote(cL2, cdir, &err) < 0) {
                    cok = false; error_free(err); err = NULL; break;
                }
                /* Append a half line (no newline) — a crash mid-append. */
                char *lp = g_build_filename(cdir, "nodes.log", NULL);
                int lfd = open(lp, O_WRONLY | O_APPEND);
                g_free(lp);
                if (lfd < 0) { cok = false; break; }
                const char *half = "999 0 4 3 12345";
                if (write(lfd, half, strlen(half)) < 0) {
                    close(lfd); cok = false; break;
                }
                close(lfd);

                SfSnapNode *loaded = NULL;
                if (sf_snap_load(cdir, &loaded, &err) < 0) {
                    error_free(err); err = NULL; break;
                }
                cn = sf_count_nodes(loaded);
                sf_snap_free_loaded(loaded);
                dropped = (cn == 3);   /* root + L1 + L2; half-line tail dropped */
            } while (0);
            snprintf(buf, sizeof(buf), "loaded=%d nodes=%zu (want 3)", dropped, cn);
            report(mon, all_ok, "G crash tail-drop (half line dropped)",
                   cok && dropped, buf);
            sf_rmrf_persist_dir(cdir);
            g_free(cdir);
        }
    }

out:
    sf_rmrf_persist_dir(dir);
    g_free(dir);
}

/* ---- cold-start equivalence (selftest 8, HMP/debug-core path) ------------
 * RAM-visible half of the cold-start contract: persist a file-backed root tree,
 * compare hot restore(X) with sf_cold_start(dir, X). Device-stream end-to-end
 * is covered later by the microvm selftest-8 rig; this case exercises the
 * destructive core sequence: reset → root.ram MAP_PRIVATE remap → load manifest
 * and diff stores → restore target → restart dirty tracking.
 */
static void sf_selftest_cold_start(Monitor *mon, bool *all_ok)
{
    char buf[192];
    Error *err = NULL;
    SfSnapNode *L1, *L2, *root;
    char *dir;
    uint32_t v1, hot, cold, l2_id;

    if (!kvm_enabled() || !sf_kvm_dirty_ring_enabled()) {
        monitor_printf(mon, "sf: selftest[cold-start 8]: SKIPPED "
                       "(needs KVM + dirty ring)\n");
        return;
    }

    dir = g_dir_make_tmp("sf-cold-XXXXXX", NULL);
    if (!dir) {
        report(mon, all_ok, "8 cold-start", false, "g_dir_make_tmp failed");
        return;
    }

    setenv("SF_ROOT_DIR", dir, 1);
    if (!sf_snap_root(mon)) {
        unsetenv("SF_ROOT_DIR");
        *all_ok = false;
        goto out;
    }
    unsetenv("SF_ROOT_DIR");

    sf_run_guest_ms(20);
    v1 = sf_rd32(SF_ST_BASE);
    L1 = sf_make_layer(mon, all_ok);
    sf_run_guest_ms(20);
    L2 = sf_make_layer(mon, all_ok);
    if (!L1 || !L2) {
        goto out;
    }
    l2_id = L2->id;
    root = sf_active;
    while (root->parent) {
        root = root->parent;
    }
    /* §4.2-3 teeth: a NO_RESTORE range must survive persist → cold-start. Use a
     * page other than the marker page so it does not perturb the RAM
     * equivalence assert below. */
    sf_exclude_clear();
    {
        void *hx = sf_gpa_to_host(SF_ST_BASE + SF_ST_PAGE);
        if (hx) {
            sf_exclude_add((uint64_t)(uintptr_t)hx, SF_ST_PAGE, 7);
        }
    }
    if (sf_snap_persist(root, dir, &err) < 0) {
        report(mon, all_ok, "8 cold-start", false, error_get_pretty(err));
        error_free(err);
        goto out;
    }

    if (sf_snap_delta_restore(L1->id, &err) < 0) {
        report(mon, all_ok, "8 hot-restore baseline", false, error_get_pretty(err));
        error_free(err);
        goto out;
    }
    hot = sf_rd32(SF_ST_BASE);

    if (sf_cold_start(dir, L1->id, &err) < 0) {
        report(mon, all_ok, "8 cold-start", false, error_get_pretty(err));
        error_free(err);
        goto out;
    }
    cold = sf_rd32(SF_ST_BASE);
    snprintf(buf, sizeof(buf), "hot=%u cold=%u target=%u L2=%u",
             hot, cold, v1, l2_id);
    report(mon, all_ok, "8 cold-start equivalence",
           hot == v1 && cold == hot, buf);

    /* §4.2-3 teeth: cold-start rebuilt the NO_RESTORE table from the manifest
     * (block-relative → this process's live host base). */
    {
        void *hx = sf_gpa_to_host(SF_ST_BASE + SF_ST_PAGE);
        bool excl_ok = (sf_exclude_count() == 1) && hx && sf_excluded(hx);
        snprintf(buf, sizeof(buf), "count=%zu hit=%d",
                 sf_exclude_count(), (hx && sf_excluded(hx)));
        report(mon, all_ok, "8 exclude-zone rebuilt from manifest", excl_ok, buf);
    }

    {
        bool rejected = (sf_cold_start(dir, 0x7ffffffeU, &err) < 0);
        snprintf(buf, sizeof(buf), "invalid-id rejected=%d", rejected);
        report(mon, all_ok, "8-neg cold-start bad-id teeth", rejected, buf);
        error_free(err);
        err = NULL;
    }

out:
    sf_exclude_clear();
    sf_rmrf_persist_dir(dir);
    g_free(dir);
}

/* ---- device stream persist/reparse round-trip (T6 方案 B, plan 07 §1) --------
 * The pc-testable half of device-stream persistence: capture a stock vmstate
 * stream, persist it to a file, read it back, re-preparse, and require the
 * rebuilt replay tables to equal the originals ("流留住 + 重解析出的表 == 原表").
 * Teeth: a corrupted stream is rejected by sf_preparse_stream's framing check.
 *
 * Why this is TCG-only and tree-less: sf_preparse_stream re-loads device state
 * into the live VM, which under KVM asserts (kvm_put_apicbase) — same constraint
 * as ④⑤, so run under TCG. And sf_snap_persist needs the root RAM shadow
 * (sf_snap_ram_root → KVM dirty ring), unavailable under TCG. So the full
 * sf_snap_persist/load .dev integration is verified at microvm cold start
 * (selftest 8, deferred); this case verifies the stream+reparse mechanics that
 * underpin it, using the real sf_device_stream_capture + sf_preparse_stream.
 */
static bool sf_tables_eq(const SfReplayTables *a, const SfReplayTables *b)
{
    if (a->n_mblocks != b->n_mblocks || a->n_gets != b->n_gets ||
        a->n_posts != b->n_posts) {
        return false;
    }
    for (size_t i = 0; i < a->n_mblocks; i++) {
        const SfMblock *x = &a->mblocks[i], *y = &b->mblocks[i];
        if (x->size != y->size ||
            (x->size && memcmp(x->copy, y->copy, x->size) != 0)) {
            return false;
        }
    }
    for (size_t i = 0; i < a->n_gets; i++) {
        const SfGet *x = &a->gets[i], *y = &b->gets[i];
        if (x->info != y->info || x->field != y->field || x->size != y->size ||
            x->captured_len != y->captured_len ||
            strcmp(x->vmsd_name, y->vmsd_name) ||
            (x->captured_len && memcmp(x->captured, y->captured, x->captured_len))) {
            return false;
        }
    }
    for (size_t i = 0; i < a->n_posts; i++) {
        const SfPost *x = &a->posts[i], *y = &b->posts[i];
        if (x->vmsd != y->vmsd || x->is_pre != y->is_pre ||
            x->version_id != y->version_id) {
            return false;
        }
    }
    return true;
}

static void sf_selftest_dev_stream(Monitor *mon, bool *all_ok)
{
    char buf[192];
    Error *err = NULL;
    char *dir, *path;
    uint8_t *S = NULL;
    size_t Slen = 0;
    gchar *Sback = NULL;
    gsize Sback_len = 0;
    SfReplayTables A, B;
    GError *gerr = NULL;
    bool ok;

    if (kvm_enabled()) {
        monitor_printf(mon, "sf: selftest[dev-stream]: SKIPPED under KVM "
                       "(preparse_stream re-load is KVM-unsafe; run under TCG)\n");
        return;
    }

    if (sf_device_stream_capture(&S, &Slen, &err) < 0) {
        report(mon, all_ok, "H dev-stream", false, error_get_pretty(err));
        error_free(err);
        return;
    }
    if (sf_preparse_stream(S, Slen, &A, &err) < 0) {
        report(mon, all_ok, "H dev-stream", false, error_get_pretty(err));
        error_free(err);
        g_free(S);
        return;
    }

    dir = g_dir_make_tmp("sf-devstream-XXXXXX", NULL);
    if (!dir) {
        report(mon, all_ok, "H dev-stream", false, "g_dir_make_tmp failed");
        sf_replay_tables_destroy(&A);
        g_free(S);
        return;
    }
    path = g_build_filename(dir, "node.dev", NULL);
    if (!g_file_set_contents(path, (gchar *)S, Slen, &gerr)) {
        report(mon, all_ok, "H dev-stream", false, gerr->message);
        g_error_free(gerr);
        goto out;
    }
    if (!g_file_get_contents(path, &Sback, &Sback_len, &gerr)) {
        report(mon, all_ok, "H dev-stream", false, gerr->message);
        g_error_free(gerr);
        goto out;
    }
    if (Sback_len != Slen || memcmp(Sback, S, Slen) != 0) {
        report(mon, all_ok, "H dev-stream", false, "file round-trip bytes differ");
        goto out;
    }

    if (sf_preparse_stream((const uint8_t *)Sback, Sback_len, &B, &err) < 0) {
        report(mon, all_ok, "H dev-stream", false, error_get_pretty(err));
        error_free(err);
        err = NULL;
        goto out;
    }
    ok = sf_tables_eq(&A, &B);
    snprintf(buf, sizeof(buf), "tables match=%d (mblocks=%zu gets=%zu "
             "posts=%zu stream=%zuB)", ok, A.n_mblocks, A.n_gets, A.n_posts,
             Slen);
    report(mon, all_ok, "H dev-stream reparse-eq", ok, buf);
    sf_replay_tables_destroy(&B);

    /* teeth: clobber the first stream byte to an invalid section type →
     * sf_preparse_stream must reject it (framing), proving the reparse has
     * teeth rather than silently accepting garbage. */
    {
        int fd = open(path, O_RDWR);
        bool rejected = false;
        if (fd >= 0) {
            uint8_t bad = 0xFF;  /* not QEMU_VM_EOF(0) nor QEMU_VM_SECTION_FULL(1) */
            if (pwrite(fd, &bad, 1, 0) == 1) {
                gchar *clob = NULL;
                gsize clen = 0;
                if (g_file_get_contents(path, &clob, &clen, NULL)) {
                    SfReplayTables T;
                    rejected = (sf_preparse_stream((const uint8_t *)clob, clen,
                                                   &T, &err) < 0);
                    if (!rejected) {
                        sf_replay_tables_destroy(&T);
                    }
                    error_free(err);
                    err = NULL;
                }
                g_free(clob);
            }
            close(fd);
        }
        snprintf(buf, sizeof(buf), "corrupt-stream rejected=%d", rejected);
        report(mon, all_ok, "H-neg dev-stream teeth", rejected, buf);
    }

out:
    g_free(Sback);
    g_free(path);
    sf_rmrf_persist_dir(dir);
    g_free(dir);
    sf_replay_tables_destroy(&A);
    g_free(S);
}

/* Compound id (worker_id, local_id) encoding — snapshot-tree.md §6 id 契约.
 * Pure allocator check, no RAM/KVM, runs before any active tree exists: root is
 * the reserved id 0 regardless of the worker slot; a non-root node carries the
 * injected worker_id in the high bits and a per-worker local_id in the low bits;
 * two different workers never collide. Teeth: if worker_id weren't encoded, the
 * worker-7 child's high bits would read 0, not 7. */
static void sf_selftest_compound_id(Monitor *mon, bool *all_ok)
{
    char buf[192];
    SfSnapNode *r0, *c0, *r1, *c1;
    uint32_t i_r0, i_c0, i_r1, i_c1;
    bool ok;

    sf_node_set_worker_id(0);
    r0 = sf_node_new(NULL, SF_SNAP_ROOT);     /* reserved id 0 */
    c0 = sf_node_new(r0, SF_SNAP_RUN);        /* SF_ID(0, 1) */
    sf_node_set_worker_id(7);
    r1 = sf_node_new(NULL, SF_SNAP_ROOT);     /* still reserved id 0 */
    c1 = sf_node_new(r1, SF_SNAP_RUN);        /* SF_ID(7, 0) */
    i_r0 = r0->id; i_c0 = c0->id; i_r1 = r1->id; i_c1 = c1->id;

    ok = i_r0 == SF_ROOT_ID && i_c0 == SF_ID(0, 1) &&
         i_r1 == SF_ROOT_ID &&
         SF_ID_WORKER(i_c1) == 7 && SF_ID_LOCAL(i_c1) == 0 &&
         i_c1 != i_c0 && i_c1 != SF_ROOT_ID;

    /* Free bare nodes without sf_node_destroy (no RAM store, no tripwire/dirty
     * side effects — safe only because no active tree exists yet). */
    g_free(c1); g_free(r1); g_free(c0); g_free(r0);
    sf_node_set_worker_id(0);

    snprintf(buf, sizeof(buf),
             "r0=%u c0=%u r1=%u c1=%u (worker=%u local=%u)",
             i_r0, i_c0, i_r1, i_c1, SF_ID_WORKER(i_c1), SF_ID_LOCAL(i_c1));
    report(mon, all_ok, "G+ compound-id encoding", ok, buf);
}

bool sf_selftest_all(Monitor *mon, Error **errp)
{
    bool all_ok = true;

    /* Tripwire: run in count mode for the whole selftest so a stray trigger
     * never aborts the process; case 7 reads the counter. */
    sf_tripwire_set_mode(false);
    sf_tripwire_reset_count();

    /* Compound-id encoding (snapshot-tree.md §6): pure allocator check, runs
     * before any active tree exists and needs no accel. */
    sf_selftest_compound_id(mon, &all_ok);

    /* Harness guard (防呆): the RAM/resolve/save/persist/cold-start cases below
     * need a guest actively dirtying SF_ST_BASE — the sf-rig dirty.elf workload.
     * Under KVM+dirty-ring an idle guest dirties 0 pages, so those cases would
     * ALL go RED for a harness reason (wrong guest), not a real bug — misleading.
     * Detect it once and abort with a pointer to the runner instead. A real
     * restore/save bug still surfaces: with the workload present pages do change,
     * the guard passes, and the cases run and catch it. TCG (④⑤ device pass, no
     * dirty ring) is unaffected. */
    if (kvm_enabled() && sf_kvm_dirty_ring_enabled()
        && !sf_st_guest_dirties(30)) {
        monitor_printf(mon, "sf: selftest: ABORT — KVM dirty ring is on but the "
                       "guest dirtied 0 pages at 0x%x in 30ms. The RAM/resolve/"
                       "save/persist cases need the sf-rig dirty workload; run via "
                       "tools/sf-rig/microvm/sf-selftest.sh (binds dirty.elf). "
                       "Refusing to emit misleading RED.\n", SF_ST_BASE);
        return false;
    }

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
    sf_selftest_tsc(mon, &all_ok);
    sf_selftest_snap(mon, &all_ok);
    sf_selftest_tripwire(mon, &all_ok);
    sf_selftest_track(mon, &all_ok);            /* R3 flat store logic; host-only */
    sf_selftest_ramstore_file(mon, &all_ok);   /* host-only; runs under TCG + KVM */
    sf_selftest_persist(mon, &all_ok);          /* needs KVM + dirty ring */
    sf_selftest_cold_start(mon, &all_ok);       /* needs KVM + dirty ring; destructive */
    sf_selftest_dev_stream(mon, &all_ok);       /* TCG only (reparse re-load) */

    monitor_printf(mon, "sf: selftest overall: %s\n",
                   all_ok ? "GREEN (all cases as expected)" : "RED");
    return all_ok;
}
