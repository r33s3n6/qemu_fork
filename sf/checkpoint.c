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
#include "system/kvm.h"         /* kvm_enabled() */
#include "system/memory.h"
#include "system/address-spaces.h"
#include "system/system.h"
#include "hw/core/cpu.h"
#include "qemu/error-report.h"
#include "system/runstate.h"     /* vm_stop/vm_start/runstate_is_running */
#include "sf/sf.h"
#include "sf/checkpoint.h"
#include "sf/control/gate.h"
#include "sf/control/config.h"   /* sf_config: startup config + boot cold-start */
#include "sf/snap/cold.h"        /* sf_cold_start (boot cold-start) */
#include "sf/kvm_tsc.h"        /* sf_kvm_put_rax (outl reply in %rax, Nyx-style) */
#include "sf/snap/node.h"      /* sf_gpa_to_host */
#include "sf/snap/exclude.h"   /* sf_exclude_add / sf_exclude_count */

/* Host-side restore generation: 0 after snapshot, +1 per restore. Lives outside
 * guest RAM so a RAM rollback does not reset it — this is how the guest probe
 * tells "just snapshotted" (gen 0) from "just restored" (gen k) at the one site.
 * The standalone read path (sf_cp_read) returns g_sf_cp_reply, which carries the
 * new node id after a SNAPSHOT and the generation after a RESTORE; the channel
 * path does not read the port, so g_sf_cp_generation is what gate.c keeps in sync
 * for its own (unread) bookkeeping. */
static uint32_t g_sf_cp_generation;
static uint32_t g_sf_cp_reply;   /* last inl readback value (standalone path only) */

void sf_cp_generation_reset(void)  { g_sf_cp_generation = 0; }
void sf_cp_generation_inc(void)   { g_sf_cp_generation++; }

static uint64_t sf_cp_read(void *opaque, hwaddr addr, unsigned size)
{
    return g_sf_cp_reply;
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

    /* Standalone ABI: eax = command, ebx = the full 32-bit composite node id.
     * The reply is returned in %eax on the SAME outl (Nyx-style; pushed to
     * KVM below): SNAPSHOT → new node id, RESTORE → generation (0xFFFFFFFF on
     * bad id), NOP → generation. No inl needed. */
    uint32_t cmd = val;
    uint32_t id = (current_cpu && kvm_enabled()) ?
                  (uint32_t)sf_kvm_get_rbx(current_cpu) : 0;

    switch (cmd) {
    case SF_CP_SNAPSHOT:
        if (take_bql) { bql_lock(); }
        sf_checkpoint_snapshot();
        if (take_bql) { bql_unlock(); }
        g_sf_cp_generation = 0;
        /* Reply = the just-created node's id (sf_active was updated inside
         * sf_snap_save); the driver learns the id it must later restore to. */
        g_sf_cp_reply = sf_active ? sf_active->id : 0;
        break;
    case SF_CP_RESTORE: {
        /* Restore rolls the vcpu (incl. RIP) back to the snapshot's outl site;
         * bump the generation the guest reads via inl so it can tell it was
         * restored (gen k) apart from the first snapshot (gen 0 / new id). */
        g_sf_cp_generation++;
        if (take_bql) { bql_lock(); }
        bool ok = sf_checkpoint_restore(id);
        if (take_bql) { bql_unlock(); }
        g_sf_cp_reply = ok ? g_sf_cp_generation : 0xFFFFFFFFu;
        break;
    }
    case SF_CP_NOP:
        /* boundary only (channel-mode uses this); no save/restore, no id. */
        g_sf_cp_reply = g_sf_cp_generation;
        break;
    default:
        fprintf(stderr, "sf-cp: unknown cmd %" PRIu64 "\n", val);
        g_sf_cp_reply = 0xFFFFFFFFu;
        break;
    }

    /* Return the reply in %RAX on the SAME outl that carried the command (Nyx
     * NO_PT_NYX model): the guest reads it back via a `+a` outl constraint, no
     * inl, no second vmexit. Push directly (KVM_GET_REGS→rax→KVM_SET_REGS) so it
     * sticks regardless of the lazy dirty path — for restore, post_init already
     * pushed the snapshot CPU; this overwrites only rax. Under KVM only (TCG
     * reads g_sf_cp_reply via the inl read handler if it ever does one). */
    if (kvm_enabled()) {
        sf_kvm_put_rax(current_cpu, g_sf_cp_reply);
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

/* ---- NO_RESTORE register ABI (plan 2026-07-08 T1 §2.2) ----------------------
 * A guest outl to SF_NR_PORT carries the GPA of a 24-byte request struct in
 * guest RAM:
 *   struct { uint64_t gpa; uint64_t size; uint32_t flags; } __attribute__((packed));
 * QEMU reads it, translates gpa→host (sf_gpa_to_host — the same host pointer
 * save/restore walks), and registers an excluded range so the buffer survives
 * restore (not diffed, not rolled back). inl returns sf_exclude_count() so the
 * guest can confirm the range landed. This is the guest→QEMU trigger path the
 * exclude table previously lacked (it was host-internal only). */
typedef struct __attribute__((packed)) SfNrReq {
    uint64_t gpa;
    uint64_t size;
    uint32_t flags;
} SfNrReq;

static void sf_nr_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    SfNrReq req;
    /* 64-bit request-struct GPA: low 32 in %eax (the outl data @val), high 32 in
     * %rbx (the guest sets it before the outl). One outl only carries 32 bits,
     * and a >4GB guest (phase2 6GB) can have the req page above 4GB. */
    uint64_t hi = (current_cpu && kvm_enabled()) ? sf_kvm_get_rbx(current_cpu) : 0;
    hwaddr req_gpa = ((hwaddr)hi << 32) | (uint32_t)val;

    /* The request struct lives in guest RAM; read it via its host pointer
     * (sf_gpa_to_host returns the same host address save/restore walks). A
     * bogus struct GPA just won't resolve — drop it. */
    void *req_host = sf_gpa_to_host(req_gpa);
    if (!req_host) {
        fprintf(stderr, "sf-nr: req gpa 0x%" HWADDR_PRIx " not in RAM — ignored\n",
                req_gpa);
        return;
    }
    memcpy(&req, req_host, sizeof(req));

    /* Translate the target range's GPA → host and register it as excluded. The
     * gpa must be page-aligned by the guest; size is page-aligned by the guest
     * (sf_exclude_add rejects unaligned). flags low 16 bits → buf_id (0→1). */
    void *host = sf_gpa_to_host((hwaddr)req.gpa);
    if (!host) {
        fprintf(stderr, "sf-nr: target gpa 0x%" PRIx64 " not in RAM — ignored\n",
                (uint64_t)req.gpa);
        return;
    }
    uint32_t buf_id = req.flags & 0xffffu;
    if (buf_id == 0) {
        buf_id = 1;
    }
    sf_exclude_add((uint64_t)(uintptr_t)host, req.size, buf_id);
    uint32_t cnt = (uint32_t)sf_exclude_count();
    fprintf(stderr, "sf-nr: registered gpa=0x%" PRIx64 " size=%" PRIu64
            " → host=%p buf_id=%u (count=%u)\n",
            (uint64_t)req.gpa, (uint64_t)req.size, host, buf_id, cnt);
    /* Return the new exclude count in %eax on the same outl (Nyx-style), so the
     * guest confirms the range landed without an inl. */
    if (kvm_enabled() && current_cpu) {
        sf_kvm_put_rax(current_cpu, cnt);
    }
}

static uint64_t sf_nr_read(void *opaque, hwaddr addr, unsigned size)
{
    return (uint64_t)sf_exclude_count();
}

static const MemoryRegionOps sf_nr_ops = {
    .read = sf_nr_read,
    .write = sf_nr_write,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static MemoryRegion sf_nr_io;

/* One-shot main-loop BH (aio_bh_schedule_oneshot auto-frees it): perform the
 * configured boot cold-start once machine creation is complete (see the
 * scheduling site for why a BH, not inline). Mirrors hmp_sf_cold_start
 * (vm_stop while restoring, generation bump, vm_start). */
static void sf_boot_cold_start_bh(void *opaque)
{
    const SfConfig *c = sf_config();
    Error *err = NULL;
    bool was_running = runstate_is_running();

    if (c->common_dir[0] == '\0' && c->private_dir[0] == '\0') {
        error_report("sf-config: cold_start_on_boot set but no "
                     "SF_COMMON_DIR/SF_PRIVATE_DIR");
        exit(1);
    }
    if (was_running) {
        vm_stop(RUN_STATE_RESTORE_VM);
    }
    if (sf_cold_start(c->common_dir, c->private_dir, c->initial_node,
                      true, true, &err) < 0) {
        error_report("sf-config: boot cold-start failed: %s",
                     error_get_pretty(err));
        exit(1);
    }
    sf_cp_generation_inc();
    fprintf(stderr, "sf-config: boot cold-start ok common=%s private=%s node=%u\n",
            c->common_dir[0] ? c->common_dir : "(none)",
            c->private_dir[0] ? c->private_dir : "(none)", c->initial_node);
    if (was_running) {
        vm_start();
    }
}

static void sf_cp_machine_done(Notifier *n, void *unused)
{
    /* Read startup config first: sf_control_init()->sf_gate_init() seeds gate
     * mode + resume timeout from it, and the boot cold-start below reads it. */
    sf_config_load();

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

    /* NO_RESTORE register port: a guest outl carrying a request-struct GPA.
     * Not lockless (sf_exclude_add touches a glib table; register is a one-off
     * cold path, not a per-boundary hot path) — the default BQL-by-prepare_mmio
     * is fine here. */
    memory_region_init_io(&sf_nr_io, NULL, &sf_nr_ops, NULL,
                          "sf-no-restore", SF_NR_PORT_SIZE);
    memory_region_add_subregion(get_system_io(), SF_NR_PORT, &sf_nr_io);
    fprintf(stderr, "sf-nr: NO_RESTORE register port at 0x%x (size %d)\n",
            SF_NR_PORT, SF_NR_PORT_SIZE);

    /* Attach the host control channel if a -chardev id "sfctl" is present; when
     * absent the port keeps its standalone guest-driven behavior. */
    sf_control_init();

    /* Boot cold-start (§2.3): schedule it on a main-loop BH rather than inline.
     * This notifier fires from qdev_machine_creation_done() BEFORE
     * register_global_state() (hw/core/machine.c) — inline cold-start would
     * re-preparse the .dev stream with the 'globalstate' VMSD not yet
     * registered ("no VMSD for section globalstate"). The BH runs after machine
     * creation completes (globalstate registered) and after autostart's vm_start,
     * so it mirrors the proven hmp_sf_cold_start path (vm_stop→cold_start→
     * vm_start). A few instructions of -kernel boot before the BH are discarded
     * by cold_start's RAM remap; that's the intended "resume restored guest, not
     * the kernel". Single-dir in S1; two-dir common/private lands in S3. */
    if (sf_config()->cold_start_on_boot) {
        aio_bh_schedule_oneshot(qemu_get_aio_context(),
                                sf_boot_cold_start_bh, NULL);
    }
}

static Notifier sf_cp_notifier = { .notify = sf_cp_machine_done };

static void sf_cp_register(void)
{
    qemu_add_machine_init_done_notifier(&sf_cp_notifier);
}

type_init(sf_cp_register)
