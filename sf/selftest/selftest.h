/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 * Discriminating restore-correctness selftest (design spec §G, cases ①–⑤).
 * Triggered by HMP sf_selftest. Clean-room (no Nyx).
 */
#ifndef SF_SELFTEST_H
#define SF_SELFTEST_H

#include "qapi/error.h"
#include "monitor/monitor.h"
#include "exec/hwaddr.h"

/*
 * Run every restore-correctness case, printing per-case GREEN/RED to @mon.
 * Returns true iff every case had its expected outcome (positive cases pass,
 * fault-injection cases are correctly detected). Device cases (④⑤) run under
 * TCG or KVM; RAM cases (①②③) need the KVM dirty ring + the sf-rig dirty
 * workload running (skipped with a note otherwise).
 */
bool sf_selftest_all(Monitor *mon, Error **errp);

/*
 * R3 spike (plan 2026-07-06-07 §3, hard prerequisite for cold start): verify
 * that munmap+mmap(MAP_PRIVATE|MAP_FIXED, fd) over a guest RAM page AFTER KVM
 * memslots are registered rebuilds the EPT (via the mmu-notifier) so the guest
 * can still read/write the page and the dirty ring still tracks it. @gpa is the
 * guest-physical page to remap (page-aligned). Run under KVM with a guest that
 * writes @gpa (e.g. the sf-rig dirty workload). Returns true if the guest
 * survived the remap (EPT rebuilt) AND the dirty ring tracked the post-remap
 * write. If the process crashes (SIGSEGV in the guest), the mmu-notifier did NOT
 * fire — R3 fails, observed by the caller as a crash. Research-only; not part of
 * sf_selftest_all.
 */
bool sf_r3_spike_run(Monitor *mon, hwaddr gpa);

/*
 * R3-full (plan 2026-07-06-07 §3): whole-RAM scale-up of the R3 spike — remap
 * EVERY guest RAM block to a dump file with munmap+mmap(MAP_PRIVATE|MAP_FIXED),
 * the Nyx shadow_memory.c:299-306 cold-start loop. Same three checks as R3
 * (survived/advanced/tracked) at whole-RAM scale. Run under KVM + dirty ring
 * with the sf-rig dirty workload. Destructive (leaves guest RAM file-mapped);
 * research-only, not part of sf_selftest_all.
 */
bool sf_remap_all_run(Monitor *mon);

#endif /* SF_SELFTEST_H */
