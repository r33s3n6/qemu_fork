/*
 * sf/checkpoint — guest→host CHECKPOINT channel (design: research/plans/
 * 2026-07-05-03-restore-semantics-implementation-progress.md §CHECKPOINT 通道).
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
 * Step A: this file only proves the channel fires on the vcpu thread. Snapshot
 * and restore wiring land in Steps B/C.
 *
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/notify.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "system/system.h"
#include "hw/core/cpu.h"
#include "sf/sf.h"
#include "sf/checkpoint.h"

/* Host-side restore generation: 0 after snapshot, +1 per restore. Lives outside
 * guest RAM so a RAM rollback does not reset it — this is how the guest probe
 * tells "just snapshotted" (gen 0) from "just restored" (gen k) at the one site. */
static uint32_t g_sf_cp_generation;

static uint64_t sf_cp_read(void *opaque, hwaddr addr, unsigned size)
{
    return g_sf_cp_generation;
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

    switch (val) {
    case SF_CP_SNAPSHOT:
        sf_checkpoint_snapshot();
        g_sf_cp_generation = 0;
        break;
    case SF_CP_RESTORE:
        /* Restore rolls the vcpu (incl. RIP) back to the snapshot's outl site;
         * bump the generation the guest reads via inl so it can tell it was
         * restored (gen k) apart from the first snapshot (gen 0). */
        g_sf_cp_generation++;
        sf_checkpoint_restore();
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
    memory_region_add_subregion(get_system_io(), SF_CP_PORT, &sf_cp_io);
    fprintf(stderr, "sf-cp: channel registered at port 0x%x (size %d)\n",
            SF_CP_PORT, SF_CP_PORT_SIZE);
}

static Notifier sf_cp_notifier = { .notify = sf_cp_machine_done };

static void sf_cp_register(void)
{
    qemu_add_machine_init_done_notifier(&sf_cp_notifier);
}

type_init(sf_cp_register)
