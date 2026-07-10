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

/* NO_RESTORE register port (plan 2026-07-08 T1 §2.2): a guest outl to this port
 * carries the GPA of a 24-byte request struct {gpa,size,flags} in guest RAM;
 * QEMU reads it, translates gpa→host and calls sf_exclude_add. inl returns the
 * current sf_exclude_count() so the guest can confirm the range landed. */
#define SF_NR_PORT       0x530
#define SF_NR_PORT_SIZE  4

/* Commands written to SF_CP_PORT (outl): eax carries the command and ebx the
 * full 32-bit composite node id. Keeping them separate preserves worker_id.
 * The single-site outl address remains the terminal-restore foundation. */
#define SF_CP_NOP        0    /* boundary only (channel mode); no save/restore */
#define SF_CP_SNAPSHOT   1
#define SF_CP_RESTORE    2

/* inl readback (single slot, meaning depends on the cmd the guest just sent):
 *   SNAPSHOT → the new node id (driver learns the id it must later restore to)
 *   RESTORE  → generation counter (++ per restore); 0xFFFFFFFF on bad id
 *   NOP      → generation counter
 * The guest knows which it sent, so it interprets the one slot accordingly. */

/* Host-side restore-generation accessors (kept in sf/checkpoint.c, updated by
 * sf/control/gate.c on snapshot/restore so the single-site probe still tells
 * gen 0 from gen k). */
void sf_cp_generation_reset(void);   /* gen = 0 (after a snapshot) */
void sf_cp_generation_inc(void);     /* gen++ (after a restore / cold-start) */

/* Terminal restore to an explicit node id (plan 2026-07-08 T1 §2.1). The engine
 * sf_snap_restore(dst_id) already supports any id; this wrapper replaces the
 * old fixed-`sf_active->id` call. Returns true on success, false on bad id /
 * restore error (caller sets the 0xFFFFFFFF readback). */
bool sf_checkpoint_restore(uint32_t id);

#endif /* SF_CHECKPOINT_H */
