/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 * RAM dirty-page engine: hot/cold policy + collect/restore/reset over the KVM
 * dirty-log ring. Clean-room (no Nyx). Design: research/plans/2026-07-04-02-
 * m0s-restore-spike-design.md §C; ARCHITECTURE.md §4/§5.
 */
#ifndef SF_DIRTY_ENGINE_H
#define SF_DIRTY_ENGINE_H

#include "qapi/error.h"

/*
 * Per-page reprotect policy (design §C):
 *  - COLD: ring-tracked; restored only when dirtied, then reprotected.
 *  - HOT:  restored UNCONDITIONALLY every round (kept writable). On stock KVM
 *          6.8 every RAM slot is still tracked, so HOT here means "always in
 *          the restore set" (a safety net); the "never enters ring" fast path
 *          is a future I.3 KVM extension. Default is COLD.
 */
typedef enum { SF_PAGE_COLD = 0, SF_PAGE_HOT } SfPagePolicy;

/*
 * Snapshot guest RAM: record a shadow copy of every RAMBlock and start dirty
 * tracking from a clean slate (all pages reprotected, bitmaps cleared).
 * Idempotent (drops any previous snapshot). Requires KVM dirty ring + BQL.
 */
int sf_dirty_snapshot(Error **errp);

/*
 * Collect this round's dirtied pages into the to-restore set. Returns the
 * number of pages visited (drain + accumulated bitmap; see sf_kvm_collect_dirty).
 */
uint64_t sf_dirty_collect(void);

/*
 * Restore: copy the shadow back for every page in the to-restore set plus
 * every HOT page (unconditional). Drains the to-restore set. Returns pages
 * copied back.
 */
uint32_t sf_dirty_restore(void);

/* Clear per-slot dirty bitmaps to begin a fresh tracking round. */
void sf_dirty_reset_ring(void);

/* Policy of a guest page (keyed by host page address; see note above). */
SfPagePolicy sf_reprotect_policy(uint64_t page_addr);

/* Mark a guest page HOT (keyed by host page address). Default COLD. */
void sf_dirty_mark_hot(uint64_t page_addr);

/* Free the shadow + policy/to-restore sets. */
void sf_dirty_destroy(void);

/*
 * Fault injection (selftest only): make the next collect() DROP this host page
 * from the to-restore set, simulating a lost/uncaptured dirty page. Pass NULL
 * to disable. A correct restore-correctness check must go RED when a page the
 * guest changed is dropped here.
 */
void sf_dirty_inject_collect_skip(void *host_page);

/* True iff a RAM snapshot is currently held. */
bool sf_dirty_have_snapshot(void);

#endif /* SF_DIRTY_ENGINE_H */
