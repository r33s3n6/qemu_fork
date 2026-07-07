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

/* Commands written to SF_CP_PORT (outl). */
#define SF_CP_SNAPSHOT   1
#define SF_CP_RESTORE    2

/* Host-side restore-generation accessors (kept in sf/checkpoint.c, updated by
 * sf/control/gate.c on snapshot/restore so the single-site probe still tells
 * gen 0 from gen k). */
void sf_cp_generation_reset(void);   /* gen = 0 (after a snapshot) */
void sf_cp_generation_inc(void);     /* gen++ (after a restore / cold-start) */

#endif /* SF_CHECKPOINT_H */
