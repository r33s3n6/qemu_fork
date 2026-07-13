/*
 * sf/checkpoint — guest→host CHECKPOINT channel ABI.
 *
 * Shared conceptually with the guest probe (tools/sf-rig/microvm/probe.c keeps
 * its own copy of these constants — keep them in sync).
 */
#ifndef SF_CHECKPOINT_H
#define SF_CHECKPOINT_H

/* Free I/O port just past fw_cfg's 0x510-0x51b range; unused on microvm/pc. */
#define SF_CP_PORT       0x520
#define SF_CP_PORT_SIZE  4

/* Commands written to SF_CP_PORT (outl): eax carries the command and ebx the
 * full 32-bit composite node id. Keeping them separate preserves worker_id.
 * The single-site outl address remains the terminal-restore foundation. */
#define SF_CP_NOP        0    /* boundary only (channel mode); no save/restore */
#define SF_CP_SNAPSHOT   1
#define SF_CP_RESTORE    2

/* Reply the guest reads back (in %rax on KVM, inl readback on TCG): the active
 * node id for every cmd. It is baked into %rax before the snapshot capture, so
 * snapshot() returns the id uniformly whether the guest just snapshotted, was
 * restored, or cold-started — the guest can always-write its restore target with
 * no first-arrival detection. A failed restore is fatal (SF_RESTORE_FAIL_POLICY),
 * never a readback. */

/* Execute a guest SNAPSHOT/RESTORE/NOP on the vcpu thread and push the reply the
 * guest reads back in %rax (always the active node id). THE single shared
 * execution path: the standalone port write and
 * the gate ALLOW self-execute both call it, so a gate=ALLOW guest with the control
 * chardev attached is indistinguishable from no host. A failed restore never
 * returns a guest sentinel — it routes through sf_restore_fail (fatal per policy);
 * the return is that policy's resume decision (true = guest resumes; false = a
 * notify-policy restore failure left the vcpu parked — only the gate caller cares,
 * the standalone path always returns to KVM_RUN). */
bool sf_cp_execute_and_reply(uint32_t val);

/* Terminal restore to an explicit node id (plan 2026-07-08 T1 §2.1). The engine
 * sf_snap_restore(dst_id) already supports any id; this wrapper replaces the
 * old fixed-`sf_active->id` call. Returns true on success, false on bad id /
 * restore error (the caller routes failure through sf_restore_fail — a failed
 * restore is fatal, never a guest sentinel). */
bool sf_checkpoint_restore(uint32_t id);

#endif /* SF_CHECKPOINT_H */
