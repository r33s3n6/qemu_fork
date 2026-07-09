/*
 * sf/track — restore-set tracker (plan 2026-07-08-03).
 * Three layers: KVM primitives (accel/kvm) / thin tracker glue (tracker.c, R4) /
 * pluggable store strategy (this header's SfRestoreStoreOps; first impl flat_store.c).
 * The store is the ONLY extension point: a new strategy = a new SfRestoreStoreOps.
 * Clean-room: no Nyx code.
 */
#ifndef SF_TRACK_TRACKER_H
#define SF_TRACK_TRACKER_H

#include "qemu/osdep.h"

/* Guest RAM region registry: defines the dense page-index space + idx↔host.
 * Reuses the snap layer's block enumeration ({host,len} per RAMBlock). */
typedef struct {
    void    *host;   /* live RAMBlock host base */
    uint64_t len;    /* used_length */
} SfBlockReg;

/*
 * Resolve a live guest page's pristine restore source for target @target.
 * @host = live page; returns a pointer to its snapshot copy (owner ≤ target), or
 * NULL if it has none. Injected so the tracker/store stay independent of the
 * snapshot tree (prod wires sf_resolve; RAM-only tests wire a shadow lookup).
 * Stable for a fixed @target while its node chain lives (append-only tree).
 */
typedef uint8_t *(*SfResolveFn)(void *target, void *host, void *user);

/* Restore plan: one entry per page to roll back. src==NULL ⇒ skip (excluded /
 * outside any shadow). Two-pass (resolve all → memcpy all) is the fast path. */
typedef struct {
    void    *dst;    /* live guest page */
    uint8_t *src;    /* pristine source (from resolve), or NULL */
} SfPlanPage;

typedef struct {
    const SfPlanPage *pages;
    size_t            n;
    /* pages[0,unsure_n) = carried across a prior restore ("unsure": may already
     * equal the snapshot); pages[unsure_n,n) = this generation's net increment,
     * straight from the ring (guaranteed written). build_diff memcmp-confirms only
     * the unsure prefix (plan 2026-07-08-03/09-01 §4 D). 0 ⇒ all net increment. */
    size_t            unsure_n;
} SfRestorePlan;

/*
 * Pluggable strategy (plan §3.3). note_batch is the single funnel (ring drain /
 * ring-full / background all route here). Each hook's when+what is in its name;
 * the store itself calls sf_kvm_reset_ring / sf_kvm_protect at boundaries (the
 * tracker never touches protection).
 */
typedef struct SfRestoreStore SfRestoreStore;

typedef struct {
    /* A batch of freshly-dirtied live pages entered the restore set. */
    void (*note_batch)(SfRestoreStore *, void *const *host, size_t n);
    /* The {dst,src}[] to roll back for @target (src resolved, cached as it sees fit). */
    const SfRestorePlan *(*plan)(SfRestoreStore *, void *target);
    /* After a restore's memcpy: reset/protect + generation bookkeeping per policy. */
    void (*after_restore)(SfRestoreStore *, void *target);
    /* After a forced/background drain (ring-full): reclaim ring slots. */
    void (*after_drain)(SfRestoreStore *);
    /* Hint: the expected restore target (target==active ⇒ fast path). */
    void (*set_active)(SfRestoreStore *, void *node);
    /* @target's node chain is being torn down: drop any cached src for it. */
    void (*invalidate)(SfRestoreStore *, void *target);
    void (*free)(SfRestoreStore *);
    bool wants_background;   /* register the QEMU background reaper hook? */
} SfRestoreStoreOps;

/* Impls embed this as their first member so (SfRestoreStore*) ↔ impl casts work. */
struct SfRestoreStore { const SfRestoreStoreOps *ops; };

/*
 * Flat store (first backend, plan §4): a persistent {dst,src} plan partitioned
 * by insertion + a page-index membership bitmap for O(1) dedup. src is filled
 * lazily and cached across rounds (only touched pages); this one structure
 * subsumes the old GHashTable src memo + dirty bitmap + HOT set.
 *  - BLIND (ALL_HOT): after_restore keeps pages writable (no reset); plan grows
 *    to the active layer's footprint, drain goes ~empty in steady state.
 *    SF_RESET_EVERY_N=N (BLIND only): every N in-place restores, reset_ring+clear
 *    (n=1 ≡ FULL; n=0/unset = pure blind). Bounds long-run W drift.
 *  - FULL: after_restore resets + clears; next round ∝ this round's dirty.
 */
typedef enum { SF_FLAT_FULL, SF_FLAT_BLIND } SfFlatPolicy;

SfRestoreStore *sf_flat_store_new(const SfBlockReg *blocks, size_t n_blocks,
                                  SfResolveFn resolve, void *user,
                                  SfFlatPolicy policy);

/* ---- tracker glue (defined in tracker.c at R4; declared here for wiring) ---- */
/*
 * Fine-grained surface: production restore interleaves device replay between the
 * plan and the memcpy, and adds cross-node path pages, so it drives the steps
 * rather than a monolithic restore. RAM-only callers just do drain→plan→apply→
 * after_restore. begin arms KVM dirty tracking + a clean slate; end disarms.
 */
void sf_track_begin(const SfBlockReg *blocks, size_t n_blocks,
                    SfResolveFn resolve, void *user, SfRestoreStore *store);
void sf_track_end(void);

void sf_track_drain(void);                        /* ring → store->note_batch */
const SfRestorePlan *sf_track_plan(void *target); /* store->plan (live-dirty set) */
void sf_track_apply(const SfPlanPage *pages, size_t n);  /* 2-thread memcpy */
void sf_track_after_restore(void *target);        /* store->after_restore */
void sf_track_after_drain(void);                  /* store->after_drain (ring-full) */
uint8_t *sf_track_resolve(void *target, void *host); /* for the snap layer's path pages */
void sf_track_set_active(void *node);
void sf_track_invalidate(void *target);
bool sf_track_active(void);                       /* is a tracker session armed? */

/* Fault injection (selftest only): drop @host from the next drains so it never
 * enters the restore set, simulating a lost dirty page. NULL disables. A correct
 * restore-correctness check must go RED when a page the guest changed is dropped. */
void sf_track_inject_drop(void *host);

#endif /* SF_TRACK_TRACKER_H */
