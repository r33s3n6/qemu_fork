/*
 * sf/track/flat_store — first restore-store backend (plan 2026-07-08-03 §4).
 * A persistent {dst,src} plan + a page-index membership bitmap for O(1) dedup.
 * src is filled lazily on plan() and cached across rounds (only touched pages),
 * so this one structure replaces the old GHashTable src memo + dirty bitmap +
 * HOT set. Pure state + resolve callback; the KVM reset happens only in the
 * boundary hooks. Clean-room: no Nyx code.
 */
#include "qemu/osdep.h"
#include "qemu/bitmap.h"
#include "system/kvm.h"
#include "sf/track/tracker.h"

typedef struct {
    SfRestoreStore    base;          /* must be first (cast target) */
    const SfBlockReg *blocks;        /* borrowed; page-index space */
    size_t            n_blocks;
    long             *blk_pgbase;    /* prefix page count per block */
    SfResolveFn       resolve;
    void             *user;
    SfFlatPolicy      policy;

    unsigned long    *member;        /* page-idx bitmap: in this generation's set */
    SfPlanPage       *plan;          /* insertion-ordered {dst,src} */
    size_t            n, cap, resolved_upto;
    void             *plan_target;   /* target the src[0..resolved_upto) resolve to */
    void             *active;        /* set_active hint (fast path == plan_target) */
    SfRestorePlan     out;           /* returned by pointer */

    /* A3 debug trace (SF_DIRTY_TRACE): running intersection/union of per-round
     * member = 共享脏页 common set. FULL only (blind's member accumulates, no
     * per-round isolation). Untouched + unallocated unless enabled → hot path 零侵入. */
    bool              dbg_on;
    size_t            dbg_rounds;
    unsigned long    *dbg_common, *dbg_union;
} FlatStore;

/* host → dense page-index. ponytail: linear over the few RAMBlocks; if this
 * ever shows up hot, emit page-idx straight from the ring's (slot,offset). */
static bool flat_host_idx(FlatStore *f, void *host, long *idxp)
{
    size_t psize = qemu_real_host_page_size();

    for (size_t b = 0; b < f->n_blocks; b++) {
        const SfBlockReg *r = &f->blocks[b];
        if (host >= r->host && (uint8_t *)host < (uint8_t *)r->host + r->len) {
            *idxp = f->blk_pgbase[b] +
                    ((uint8_t *)host - (uint8_t *)r->host) / psize;
            return true;
        }
    }
    return false;
}

static void flat_note_batch(SfRestoreStore *s, void *const *host, size_t n)
{
    FlatStore *f = (FlatStore *)s;

    for (size_t i = 0; i < n; i++) {
        long idx;
        if (!flat_host_idx(f, host[i], &idx) ||
            test_and_set_bit(idx, f->member)) {
            continue;   /* outside any block, or already in the set (dedup) */
        }
        if (f->n == f->cap) {
            f->cap = f->cap ? f->cap * 2 : 4096;
            f->plan = g_renew(SfPlanPage, f->plan, f->cap);
        }
        f->plan[f->n].dst = host[i];
        f->plan[f->n].src = NULL;   /* resolved lazily in plan() */
        f->n++;
    }
}

static const SfRestorePlan *flat_plan(SfRestoreStore *s, void *target)
{
    FlatStore *f = (FlatStore *)s;

    if (target != f->plan_target) {   /* target changed → re-resolve all */
        f->plan_target = target;
        f->resolved_upto = 0;
    }
    for (size_t i = f->resolved_upto; i < f->n; i++) {
        f->plan[i].src = f->resolve(target, f->plan[i].dst, f->user);
    }
    f->resolved_upto = f->n;
    f->out.pages = f->plan;
    f->out.n = f->n;
    return &f->out;
}

/* A3: fold this round's member into the running common (AND) / union (OR) and
 * print, before FULL clears it. Meaningful over the steady (inplace) tail —
 * the first few notes are setup/build_diff diffs and only tighten the AND. */
static void flat_dbg_note(FlatStore *f)
{
    size_t nbits = f->blk_pgbase[f->n_blocks];
    size_t nwords = BITS_TO_LONGS(nbits);
    size_t pc_this = 0, pc_common = 0, pc_union = 0;

    if (f->dbg_rounds == 0) {
        memcpy(f->dbg_common, f->member, nwords * sizeof(long));
        memcpy(f->dbg_union, f->member, nwords * sizeof(long));
    } else {
        for (size_t i = 0; i < nwords; i++) {
            f->dbg_common[i] &= f->member[i];
            f->dbg_union[i] |= f->member[i];
        }
    }
    f->dbg_rounds++;
    for (size_t i = 0; i < nwords; i++) {
        pc_this += __builtin_popcountl(f->member[i]);
        pc_common += __builtin_popcountl(f->dbg_common[i]);
        pc_union += __builtin_popcountl(f->dbg_union[i]);
    }
    fprintf(stderr, "sf-dirty-trace: round=%zu this=%zu common=%zu union=%zu\n",
            f->dbg_rounds, pc_this, pc_common, pc_union);
}

static void flat_clear_generation(FlatStore *f)
{
    bitmap_zero(f->member, f->blk_pgbase[f->n_blocks]);   /* [n_blocks] = total pages */
    f->n = 0;
    f->resolved_upto = 0;
}

static void flat_after_restore(SfRestoreStore *s, void *target)
{
    FlatStore *f = (FlatStore *)s;
    (void)target;

    if (f->dbg_on) {
        flat_dbg_note(f);      /* A3: fold member before clear (FULL per-round set) */
    }
    if (f->policy == SF_FLAT_BLIND) {
        return;   /* keep writable + keep plan; no reset (periodic clear = knob) */
    }
    sf_kvm_reset_ring();       /* FULL: reprotect all harvested */
    flat_clear_generation(f);  /* next round ∝ this round's dirty */
}

static void flat_after_drain(SfRestoreStore *s)
{
    (void)s;
    /* Forced (ring-full): reclaim slots; keep membership (pages still in the set,
     * they will re-fault and re-note after reprotect — correctness-safe). */
    sf_kvm_reset_ring();
}

static void flat_set_active(SfRestoreStore *s, void *node)
{
    ((FlatStore *)s)->active = node;   /* hint; plan() already fast-paths ==plan_target */
}

static void flat_invalidate(SfRestoreStore *s, void *target)
{
    FlatStore *f = (FlatStore *)s;
    if (f->plan_target == target) {
        f->plan_target = NULL;
        f->resolved_upto = 0;   /* force re-resolve next plan() */
    }
}

static void flat_free(SfRestoreStore *s)
{
    FlatStore *f = (FlatStore *)s;
    g_free(f->member);
    g_free(f->plan);
    g_free(f->blk_pgbase);
    g_free(f->dbg_common);
    g_free(f->dbg_union);
    g_free(f);
}

static const SfRestoreStoreOps flat_ops = {
    .note_batch    = flat_note_batch,
    .plan          = flat_plan,
    .after_restore = flat_after_restore,
    .after_drain   = flat_after_drain,
    .set_active    = flat_set_active,
    .invalidate    = flat_invalidate,
    .free          = flat_free,
    .wants_background = false,   /* blind: background reap = reprotect on stock */
};

SfRestoreStore *sf_flat_store_new(const SfBlockReg *blocks, size_t n_blocks,
                                  SfResolveFn resolve, void *user,
                                  SfFlatPolicy policy)
{
    size_t psize = qemu_real_host_page_size();
    FlatStore *f = g_new0(FlatStore, 1);
    long base = 0;

    f->base.ops = &flat_ops;
    f->blocks = blocks;
    f->n_blocks = n_blocks;
    f->resolve = resolve;
    f->user = user;
    f->policy = policy;

    /* blk_pgbase has n_blocks+1 entries: [b] = first idx of block b, [n_blocks]
     * = total page count (used to size the bitmap + clear it). */
    f->blk_pgbase = g_new(long, n_blocks + 1);
    for (size_t b = 0; b < n_blocks; b++) {
        f->blk_pgbase[b] = base;
        base += DIV_ROUND_UP(blocks[b].len, psize);
    }
    f->blk_pgbase[n_blocks] = base;
    f->member = bitmap_new(base ? base : 1);

    f->dbg_on = getenv("SF_DIRTY_TRACE") != NULL;   /* A3: opt-in, FULL diagnostic */
    if (f->dbg_on) {
        f->dbg_common = bitmap_new(base ? base : 1);
        f->dbg_union = bitmap_new(base ? base : 1);
    }
    return &f->base;
}
