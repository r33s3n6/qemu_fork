/*
 * sf/kvm_tsc — force a host-initiated guest TSC rewind that survives KVM's
 * kvm_synchronize_tsc() "synchronizing" heuristic.
 *
 * Background (root cause, stalefuzz 2026-07-06): on a snapshot restore we push
 * the vcpu's saved regs back with cpu_synchronize_post_init() ->
 * KVM_SET_MSRS(MSR_IA32_TSC = T0). Stock KVM treats a host TSC write that lands
 * within ~1 second of the free-running value as a CPU sync-up (SMP bringup) and
 * keeps the old offset instead of rewinding (arch/x86/kvm/x86.c
 * kvm_synchronize_tsc: `synchronizing` branch reuses cur_tsc_offset). So the
 * plain write is silently dropped and the guest TSC keeps advancing at wall
 * clock while kvmclock (re-anchored by an explicit KVM_SET_CLOCK) freezes at T0
 * -> the guest sees the two clocksources skew (clocksource watchdog cs vs wd).
 *
 * sf_kvm_force_tsc() defeats the heuristic the way QEMU-Nyx did, but this is
 * stock-KVM behavior, NOT a patched sentinel: write two MSR_IA32_TSC entries in
 * one KVM_SET_MSRS. The first (a huge bogus value) poisons last_tsc_write so the
 * second (real T0) can no longer look like a sync-up and takes a fresh offset.
 * Both entries apply atomically with the vcpu parked out of KVM_RUN, so the
 * guest never observes the bogus value. Clean-room: no QEMU-Nyx code copied.
 *
 * Declared with generic CPUState so sf/ (target-agnostic) can call it; defined
 * in target/i386/kvm/kvm.c where the X86 vcpu state lives.
 */
#ifndef SF_KVM_TSC_H
#define SF_KVM_TSC_H

#include "hw/core/cpu.h"

/* Force the guest TSC to @value (returns 0 on success, <0 on ioctl failure). */
int sf_kvm_force_tsc(CPUState *cs, uint64_t value);

/* Read the guest TSC via KVM_GET_MSRS(MSR_IA32_TSC). */
uint64_t sf_kvm_read_tsc(CPUState *cs);

/* Re-freeze: force the guest TSC to the value already replayed into CPUState
 * (env->tsc = the snapshot's T0). Call after cpu_synchronize_post_init on the
 * restore/snapshot-freeze paths so the rewind actually sticks. */
void sf_kvm_refreeze_tsc(CPUState *cs);

/* Put @value into the guest's %RAX and push to KVM directly (KVM_GET_REGS → rax
 * → KVM_SET_REGS). Used by the CHECKPOINT port write handler to return the
 * snapshot/restore reply on the same outl that carried the command (Nyx-style:
 * the guest reads it via a `+a` outl constraint, no inl). */
void sf_kvm_put_rax(CPUState *cs, uint64_t value);

/* Read the guest's %RBX (pull from KVM first). The NO_RESTORE register handler
 * receives a 64-bit request-struct GPA as low32=%eax (outl data) + high32=%rbx,
 * since one outl only carries 32 bits and a >4GB guest can have the page >4GB. */
uint64_t sf_kvm_get_rbx(CPUState *cs);

#endif /* SF_KVM_TSC_H */
