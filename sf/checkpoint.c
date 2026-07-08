/*
 * sf/checkpoint — guest→host CHECKPOINT channel (design: research/plans/
 * 2026-07-05-03-restore-semantics-implementation-progress.md §CHECKPOINT 通道
 * + 2026-07-07-m3-control-channel.md §5 slice 7).
 *
 * Terminal coherence mechanism (ARCHITECTURE.md §4.4/§5): snapshot AND restore
 * execute on the vcpu thread at an I/O-exit boundary — the guest is naturally
 * quiescent there (single vCPU, out of KVM_RUN, BQL held), so no vm_stop crutch.
 *
 * ABI (single-site rule, see design doc): the guest issues both SNAPSHOT and
 * RESTORE from ONE outl instruction address (an inline sf_cp() helper). Writing
 * a command to SF_CP_PORT triggers it; reading returns the restore generation
 * counter (kept host-side, outside guest RAM, so restore does not roll it back).
 *
 * Slice 6: when a control channel is attached, a guest port write parks the
 * guest and lets the host drive. Slice 7: the guest's port-write value now
 * carries intent routed through the gate (ALLOW/DISABLE/STRICT), and a QEMU-
 * internal timeout timer can stop the guest mid-flight; the brain (state machine,
 * gate, timer, both dispatch contexts) is in sf/control/gate.c. This file is the
 * vcpu-thread entry: it hands the guest cmd value to sf_gate_boundary_enter and
 * runs the parked command loop via sf_gate_recv / sf_gate_boundary_cmd.
 *
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/main-loop.h"   /* bql_lock/bql_unlock */
#include "qemu/notify.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "system/system.h"
#include "hw/core/cpu.h"
#include "sf/sf.h"
#include "sf/checkpoint.h"
#include "sf/control/gate.h"

/* Host-side restore generation: 0 after snapshot, +1 per restore. Lives outside
 * guest RAM so a RAM rollback does not reset it — this is how the guest probe
 * tells "just snapshotted" (gen 0) from "just restored" (gen k) at the one site. */
static uint32_t g_sf_cp_generation;

void sf_cp_generation_reset(void)  { g_sf_cp_generation = 0; }
void sf_cp_generation_inc(void)   { g_sf_cp_generation++; }

static uint64_t sf_cp_read(void *opaque, hwaddr addr, unsigned size)
{
    return g_sf_cp_generation;
}

/*
 * Control-channel boundary (slice 6b/7). When a channel is attached, a guest
 * port write means "reached a boundary": park the guest and let the host drive.
 * sf_gate_boundary_enter blocks on a condvar with the main loop free to receive
 * commands (gate.c), so it MUST run BQL-free; the BQL is taken only around
 * save/restore inside gate.c. Under KVM the boundary is already BQL-free
 * (lockless_io, slice 6a); under TCG the I/O path enters with the BQL held
 * (cputlb BQL_LOCK_GUARD), so drop it for the duration and restore it on exit —
 * the caller's invariant is preserved either way. The guest cmd value routes
 * through the gate; continue/restore/cold-start resume, snapshot replies and
 * loops. The generation counter is kept in sync with the standalone path so the
 * single-site probe still tells snapshot (gen 0) from restore (gen k).
 */
static void sf_control_boundary(uint64_t val)
{
    bool had_bql = bql_locked();

    if (had_bql) {
        bql_unlock();
    }
    if (sf_gate_boundary_enter(val)) {
        /* Resume without parking: either ALLOW self-restore (run to next
         * boundary), or the timeout timer already won the race (state is
         * STOPPED_TIMEOUT; return so the in-flight vm_stop parks the vcpu and
         * the timer's 't' stands). */
        goto out;
    }
    for (;;) {
        SfCtlCmd cmd;
        sf_gate_recv(&cmd);             /* blocks; BQL not held */
        if (sf_gate_boundary_cmd(&cmd)) {
            break;                      /* c/r/C: resume to the next boundary */
        }
        /* else: stay parked, wait for the next command */
    }
out:
    if (had_bql) {
        bql_lock();   /* restore the caller's BQL state (TCG path) */
    }
}

static void sf_cp_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    /* current_cpu is non-NULL only on a vcpu thread inside its exit handler —
     * the boundary property the whole mechanism depends on. */
    if (!current_cpu) {
        fprintf(stderr, "sf-cp: cmd=%" PRIu64 " on NON-VCPU-THREAD — ignored\n",
                val);
        return;
    }

    /* Channel attached → host-driven boundary (slice 6b/7); the guest command
     * value routes through the gate. Otherwise fall through to the standalone
     * guest-driven path. */
    if (sf_control_active()) {
        sf_control_boundary(val);
        return;
    }

    /* The region is lockless_io (see sf_cp_machine_done): under KVM this handler runs
     * WITHOUT the BQL, so the boundary can later block waiting for a control-channel
     * command without freezing the main loop (plan 2026-07-07-m3-control-channel §5.6,
     * Nyx model). save/restore still need the BQL, so take it just around them. But
     * the TCG I/O path already holds the BQL (cputlb BQL_LOCK_GUARD), so only take it
     * when not already held — an unconditional bql_lock would recurse. Mirrors
     * prepare_mmio_access's own release_lock logic. The generation counter is a plain
     * host word, no lock needed. */
    bool take_bql = !bql_locked();

    switch (val) {
    case SF_CP_SNAPSHOT:
        if (take_bql) { bql_lock(); }
        sf_checkpoint_snapshot();
        if (take_bql) { bql_unlock(); }
        g_sf_cp_generation = 0;
        break;
    case SF_CP_RESTORE:
        /* Restore rolls the vcpu (incl. RIP) back to the snapshot's outl site;
         * bump the generation the guest reads via inl so it can tell it was
         * restored (gen k) apart from the first snapshot (gen 0). */
        g_sf_cp_generation++;
        if (take_bql) { bql_lock(); }
        sf_checkpoint_restore();
        if (take_bql) { bql_unlock(); }
        break;
    default:
        fprintf(stderr, "sf-cp: unknown cmd %" PRIu64 "\n", val);
        break;
    }
}

static const MemoryRegionOps sf_cp_ops = {
    .read = sf_cp_read,
    .write = sf_cp_write,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static MemoryRegion sf_cp_io;

static void sf_cp_machine_done(Notifier *n, void *unused)
{
    memory_region_init_io(&sf_cp_io, NULL, &sf_cp_ops, NULL,
                          "sf-checkpoint", SF_CP_PORT_SIZE);
    /* BQL-free dispatch: without this, prepare_mmio_access() would auto-take the
     * BQL around sf_cp_write for the duration of the access. We want the boundary
     * to run lock-free (so a control-channel wait doesn't hold the BQL) and take
     * the BQL ourselves only around save/restore (plan §5.6). */
    memory_region_enable_lockless_io(&sf_cp_io);
    memory_region_add_subregion(get_system_io(), SF_CP_PORT, &sf_cp_io);
    fprintf(stderr, "sf-cp: channel registered at port 0x%x (size %d)\n",
            SF_CP_PORT, SF_CP_PORT_SIZE);
    /* Attach the host control channel if a -chardev id "sfctl" is present; when
     * absent the port keeps its standalone guest-driven behavior. */
    sf_control_init();
}

static Notifier sf_cp_notifier = { .notify = sf_cp_machine_done };

static void sf_cp_register(void)
{
    qemu_add_machine_init_done_notifier(&sf_cp_notifier);
}

type_init(sf_cp_register)