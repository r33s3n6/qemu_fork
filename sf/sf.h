/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 *
 * Clean-room: does NOT include or copy QEMU-Nyx code; Nyx is read only as
 * design reference. Design spec: research/plans/2026-07-04-02-m0s-restore-spike-design.md
 *
 * This header holds sf-internal cross-module declarations. HMP entry points
 * are declared in include/monitor/hmp.h (hmp_sf_*).
 */
#ifndef SF_SF_H
#define SF_SF_H

/*
 * Terminal CHECKPOINT entry points (sf.c), called from the guest→host ioport
 * handler (sf/checkpoint.c) on the vcpu thread at an I/O-exit boundary. No
 * vm_stop — the single vCPU is already parked out of KVM_RUN with the BQL held.
 */
void sf_checkpoint_snapshot(void);
void sf_checkpoint_restore(void);

#endif /* SF_SF_H */
