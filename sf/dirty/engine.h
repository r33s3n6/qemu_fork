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

typedef enum {
    SF_RESET_FULL = 0,   /* reset/reprotect at every generation boundary */
    SF_RESET_ALL_HOT,    /* same-active restore rounds keep harvested pages hot */
} SfResetPolicy;

typedef struct SfDirtyShadowDesc {
    void    *host;    /* live RAMBlock host base */
    uint64_t len;     /* RAMBlock used_length */
    uint8_t *shadow;  /* root backing slice for this block */
} SfDirtyShadowDesc;

/*
 * Snapshot guest RAM: record a shadow copy of every RAMBlock and start dirty
 * tracking from a clean slate (all pages reprotected, bitmaps cleared).
 * Idempotent (drops any previous snapshot). Requires KVM dirty ring + BQL.
 */
int sf_dirty_snapshot(Error **errp);

/* Register an already-built root shadow/backing as the restore source and start
 * dirty tracking from a clean slate. The engine does not own @descs[i].shadow.
 * Used by the M3 snapshot tree so root.ram/SfRamStore is the single root
 * backing, not a second private copy inside dirty/engine. */
int sf_dirty_use_external_shadows(const SfDirtyShadowDesc *descs, size_t n_descs,
                                  Error **errp);

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

/* Policy-aware generation boundary reset. SF_BLIND/ALL_HOT may defer it. */
void sf_dirty_reset_ring(void);

/* Unconditionally release/reprotect harvested ring entries. Use at layer switch. */
void sf_dirty_force_reset_ring(void);

/* Policy of a guest page (keyed by host page address; see note above). */
SfPagePolicy sf_reprotect_policy(uint64_t page_addr);

/* Mark a guest page HOT (keyed by host page address). Default COLD. */
void sf_dirty_mark_hot(uint64_t page_addr);

/* Query HOT membership by host page address. */
bool sf_dirty_is_hot(void *host_page);

/* Free the shadow + current dirty suffix. HOT policy persists across roots. */
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

/*
 * Locate the shadow copy that owns host page @p (the root snapshot's per-block
 * shadow). Returns the shadow pointer + bytes remaining to the block end, or
 * NULL if @p is outside any shadowed block. Used by the snap layer's root
 * owner-resolution (sf_resolve root兜底). The shadow stays owned by the engine
 * (the RAM mechanism layer); snap/ only reads it.
 */
uint8_t *sf_dirty_shadow_for(void *host_page, uint64_t *remain);

/*
 * Read-only access to the last collect() vector: the dirtied host page
 * addresses (g_dirty, g_dirty_n entries). The snap layer's non-root diff save
 * reads this to build the W key set. Valid until the next collect/clear.
 */
void *const *sf_dirty_collected(size_t *n);

/*
 * Iterate the HOT policy set (host page addresses restored unconditionally).
 * @cb is called for each HOT page; the snap layer unions these into W.
 */
void sf_dirty_iter_hot(void (*cb)(void *host_page, void *user), void *user);

/*
 * Clear the collected vector (g_dirty_n = 0; capacity kept). The snap layer's
 * non-root save reads the vector then clears it so the next collect starts fresh
 * (collect appends; without a clear, consecutive collects accumulate).
 */
void sf_dirty_clear_collected(void);

/*
 * KVM ring-full handler hook: record a page harvested outside the regular
 * restore collect() path. Same semantics as collect(): page enters this
 * generation's restore set.
 */
void sf_dirty_note_page(void *host_page, size_t page_size, void *user);

#endif /* SF_DIRTY_ENGINE_H */
