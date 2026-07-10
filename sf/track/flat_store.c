/*
 * sf/track/flat_store — first restore-store backend (plan 2026-07-08-03 §4 +
 * 2026-07-09-01 C1 + 2026-07-10-02 warmup-reset). A persistent {dst,src} plan
 * + page-index membership bitmap for O(1) dedup. src filled lazily on plan()
 * and cached across rounds.
 * Policies: FULL = after_restore reset_ring+clear every round; BLIND = keep
 * writable (SF_BLIND=1); BLIND+SF_RESET_EVERY_N=N = reprotect+clear every N
 * in-place restores (n=1 ≡ FULL; n=0/unset = pure blind);
 * BLIND+SF_WARMUP_RESET=K = one-shot full-reset after K in-place rounds
 * (shed cold-start first-window tax capitalised into blind union; orthogonal
 * to reset_every_n: warmup once, then periodic). Clean-room: no Nyx.
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
    /* BLIND only: 0 = pure blind (never reset in-place); N = reset_ring+clear
     * every N in-place restores (n=1 ≡ FULL). Read once from SF_RESET_EVERY_N. */
    size_t            reset_every_n;
    size_t            inplace_since_reset; /* in-place after_restore count since clear */
    /* BLIND only: one-shot reset_ring+clear after K in-place rounds
     * (SF_WARMUP_RESET). 0/unset = off. Pending warmup suppresses reset_every_n
     * so both levers compose as "once @K, then every N". */
    size_t            warmup_reset_k;
    bool              warmup_reset_done;

    unsigned long    *member;        /* page-idx bitmap: in this generation's set */
    SfPlanPage       *plan;          /* insertion-ordered {dst,src} */
    size_t            n, cap, resolved_upto;
    size_t            pos;           /* n as of the last restore = unsure/net-increment split */
    void             *plan_target;   /* target the src[0..resolved_upto) resolve to */
    void             *active;        /* set_active hint (fast path == plan_target) */
    SfRestorePlan     out;           /* returned by pointer */

    /* A3/A4 debug trace (SF_DIRTY_TRACE): per steady/in-place round member plus
     * running intersection/union. FULL only (blind's member accumulates, no
     * per-round isolation). Untouched + unallocated unless enabled -> hot path
     * zero intrusion. */
    bool              dbg_on;
    size_t            dbg_rounds;
    unsigned long    *dbg_common, *dbg_union, *dbg_prev;
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
    f->out.unsure_n = f->pos;   /* [0,pos) carried across a restore; [pos,n) net increment */
    return &f->out;
}

/* A3/A4: fold this steady in-place round's member into the running common
 * (AND) / union (OR) and print, before FULL clears it. setup/build_diff/cross
 * re-baselines have target != active and are skipped at the caller, so union is
 * a steady-tail working-set view. */
static void flat_dbg_note(FlatStore *f)
{
    size_t nbits = f->blk_pgbase[f->n_blocks];
    size_t nwords = BITS_TO_LONGS(nbits);
    size_t pc_this = 0, pc_common = 0, pc_union = 0;
    size_t pc_overlap_prev = 0, pc_overlap_union = 0;

    if (f->dbg_rounds == 0) {
        memcpy(f->dbg_common, f->member, nwords * sizeof(long));
        memcpy(f->dbg_union, f->member, nwords * sizeof(long));
    } else {
        for (size_t i = 0; i < nwords; i++) {
            pc_overlap_prev += __builtin_popcountl(f->member[i] & f->dbg_prev[i]);
            pc_overlap_union += __builtin_popcountl(f->member[i] & f->dbg_union[i]);
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
    double union_ratio = pc_this ? (double)pc_union / (double)pc_this : 0.0;

    fprintf(stderr,
            "sf-dirty-trace: round=%zu this=%zu common=%zu union=%zu "
            "overlap_prev=%zu overlap_union=%zu union_per_round=%.3f\n",
            f->dbg_rounds, pc_this, pc_common, pc_union,
            pc_overlap_prev, pc_overlap_union, union_ratio);
    memcpy(f->dbg_prev, f->member, nwords * sizeof(long));
}

static void flat_clear_generation(FlatStore *f)
{
    bitmap_zero(f->member, f->blk_pgbase[f->n_blocks]);   /* [n_blocks] = total pages */
    f->n = 0;
    f->resolved_upto = 0;
    f->pos = 0;               /* fresh generation: nothing carried, all net increment */
    f->inplace_since_reset = 0;
}

static size_t flat_after_restore(SfRestoreStore *s, void *target)
{
    FlatStore *f = (FlatStore *)s;
    size_t n_reprotect;

    if (target != f->active) {
        /* Cross restore: the active baseline is about to switch; set_active()
         * re-baselines (reprotect + clear). Nothing to do here — one reset only. */
        return 0;
    }
    /* In-place restore of the active baseline (steady loop). */
    if (f->dbg_on) {
        flat_dbg_note(f);      /* A3: fold this round's member before FULL/periodic clear */
    }
    if (f->policy == SF_FLAT_BLIND) {
        f->inplace_since_reset++;
        /* Warmup-reset @K (plan 2026-07-10-02): one-shot full-reset after K
         * in-place rounds. Rebuilds blind baseline so cold-start first-window
         * tax is not permanently capitalised into member. While pending, skip
         * reset_every_n (compose = once @K then every N). */
        if (f->warmup_reset_k > 0 && !f->warmup_reset_done) {
            if (f->inplace_since_reset >= f->warmup_reset_k) {
                n_reprotect = sf_kvm_reset_ring();
                flat_clear_generation(f);
                f->warmup_reset_done = true;
                return n_reprotect;
            }
            f->pos = f->n;
            return 0;
        }
        /* C1 reset_every_n: every N in-place rounds reprotect + clear (n=1 ≡ FULL).
         * n=0 (default) = pure blind — keep writable, plan accumulates. */
        if (f->reset_every_n > 0 &&
            f->inplace_since_reset >= f->reset_every_n) {
            n_reprotect = sf_kvm_reset_ring();
            flat_clear_generation(f);
            return n_reprotect;
        }
        /* Keep writable + keep plan. Whole set is now carried → unsure next
         * time; notes after this are the next generation's net increment. */
        f->pos = f->n;
        return 0;
    }
    n_reprotect = sf_kvm_reset_ring();  /* FULL: reprotect this round's dirty */
    flat_clear_generation(f);           /* next round ∝ this round's dirty */
    return n_reprotect;
}

static void flat_after_drain(SfRestoreStore *s)
{
    (void)s;
    /* Forced (ring-full): reclaim slots; keep membership (pages still in the set,
     * they will re-fault and re-note after reprotect — correctness-safe). */
    (void)sf_kvm_reset_ring();
}

static void flat_set_active(SfRestoreStore *s, void *node)
{
    FlatStore *f = (FlatStore *)s;

    if (node == f->active) {
        return;   /* same baseline, nothing to re-base */
    }
    /* Baseline switch (snapshot created, or cross restore): the tracked dirty set is
     * relative to the OLD baseline. Re-base to @node — on stock KVM that means
     * reprotect everything harvested (reset_ring) + drop the vec. FULL already
     * reprotects each in-place after_restore, so this matters most for BLIND, whose
     * only re-baseline point is the switch: without it the old baseline's dirt (and
     * one-time setup pages) leak into @node's generation and its saved diff. */
    (void)sf_kvm_reset_ring();
    flat_clear_generation(f);
    f->active = node;
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
    g_free(f->dbg_prev);
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
    /* SF_RESET_EVERY_N / SF_WARMUP_RESET only meaningful under BLIND
     * (FULL already resets every 1). 0 / unset = off. */
    if (policy == SF_FLAT_BLIND) {
        const char *ren = getenv("SF_RESET_EVERY_N");
        if (ren && *ren) {
            char *end = NULL;
            unsigned long v = strtoul(ren, &end, 10);
            if (end != ren && *end == '\0') {
                f->reset_every_n = (size_t)v;
            }
        }
        const char *wrk = getenv("SF_WARMUP_RESET");
        if (wrk && *wrk) {
            char *end = NULL;
            unsigned long v = strtoul(wrk, &end, 10);
            if (end != wrk && *end == '\0') {
                f->warmup_reset_k = (size_t)v;
            }
        }
    }

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
        f->dbg_prev = bitmap_new(base ? base : 1);
    }
    return &f->base;
}
