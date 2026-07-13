/*
 * sf/snap — multi-level snapshot tree (M3). Node model, RAM-store, block
 * registry, page-key, owner resolution. See design:
 *   research/plans/2026-07-06-03-m3-multilevel-snapshot-tree.md  (§1–§4)
 *   research/plans/2026-07-06-04-m3-core-engine-impl.md          (impl truth)
 *
 * INV-B (boundary invariant, design §1): at every save/restore boundary the
 * live RAM == the active node's RAM state and dirty tracking is cleared, so the
 * next collect() yields exactly the live diff vs the active node (HOT pages
 * excepted, design §3). save() and restore() both restore INV-B at the end.
 *
 * Clean-room: no QEMU-Nyx code.
 *
 * Include qemu/osdep.h before this header.
 */
#ifndef SF_SNAP_NODE_H
#define SF_SNAP_NODE_H

#include "qapi/error.h"
#include "qemu/queue.h"
#include "monitor/monitor.h"
#include "sf/vmstate_replay/preparse.h"
#include "sf/vmstate_replay/replay.h"   /* SfReplayDebug (sf_snap_restore) */

/*
 * Page key = (block_id << 40) | pfn_in_block. block_id is the index into the
 * SfBlockDesc table (enumerated at root creation, ~个位数 of blocks); pfn is the
 * page number within that block (pfn < 2^40 = 4EB @ 4K, plenty). Encoded as a
 * single u64 so the diff index is sortable by qsort and searchable by bsearch.
 */
typedef uint64_t SfPageKey;
#define SF_KEY(bid, pfn)  (((uint64_t)(bid) << 40) | (pfn))
#define SF_KEY_BLOCK(k)   ((uint32_t)((k) >> 40))
#define SF_KEY_PFN(k)     ((k) & 0xFFFFFFFFFFULL)

/*
 * Composite node id = (worker_id << SF_ID_LOCAL_BITS) | local_id. The on-disk
 * id stored in nodes.log is this full uint32; the per-worker local_id is the
 * process-monotonic counter. root is the shared main-tree node and takes the
 * reserved id 0 (worker 0, local 0); a non-root node built by worker W gets
 * worker_id = W. Multi-worker trees branched off the same base then never
 * collide, and a controller-side treelib can merge them without renumbering
 * (snapshot-tree.md §6 id 契约). Bit split 8/24 → 256 workers × 16M locals.
 */
#define SF_ID_WORKER_BITS 8
#define SF_ID_LOCAL_BITS  24
#define SF_ID_MAX_WORKER  ((1u << SF_ID_WORKER_BITS) - 1u)
#define SF_ID_MAX_LOCAL   ((1u << SF_ID_LOCAL_BITS) - 1u)
#define SF_ID(worker, local) \
    (((uint32_t)((worker) & SF_ID_MAX_WORKER) << SF_ID_LOCAL_BITS) | \
     ((uint32_t)(local) & SF_ID_MAX_LOCAL))
#define SF_ID_WORKER(id)  ((uint32_t)(id) >> SF_ID_LOCAL_BITS)
#define SF_ID_LOCAL(id)   ((uint32_t)(id) & SF_ID_MAX_LOCAL)
#define SF_ROOT_ID        0u

/*
 * Per-node origin (plan 2026-07-11-04 §2.2) is DERIVED from the id, not stored:
 * common nodes (root + the shared read-only base tree, built by the worker-0
 * base builder) carry worker_id 0; a worker W's private nodes carry worker_id W.
 * So common ⟺ worker_id == 0. The persist skip (don't re-copy the common prefix
 * into a worker's private_dir) and the two-dir cold-start load both key off this.
 */
#define SF_NODE_IS_COMMON(n)  (SF_ID_WORKER((n)->id) == 0u)

typedef enum {
    SF_SNAP_ROOT = 0,
    SF_SNAP_CLEAN,
    SF_SNAP_SCHEMA,
    SF_SNAP_PREFIX,
    SF_SNAP_RUN,
} SfSnapKind;

typedef enum {
    SF_SNAP_OPEN = 0,     /* just created, process-private */
    SF_SNAP_SEALED,       /* immutable; PROT_READ; shareable across workers */
    SF_SNAP_PERSISTED,    /* file-mapped, manifest-recorded */
} SfSnapState;

typedef enum { SF_BACKING_ANON = 0, SF_BACKING_FILE } SfBacking;

/*
 * Block registry: enumerated once at root creation from the live RAMBlock list
 * and frozen for the snapshot tree's lifetime. It is the sole authority for
 * key<->host translation. Ordering = block_id = enumeration order.
 */
typedef struct SfBlockDesc {
    char     idstr[64];   /* RAMBlock idstr, for manifest/persistence */
    void    *host;        /* live RAMBlock host base */
    uint64_t len;         /* used_length at root creation */
    uint64_t root_off;    /* offset in root.ram/root backing (block-order) */
} SfBlockDesc;

/* On-disk-ish header of a non-root SfRamStore (memory layout == file layout,
 * design §3/§5). root has no header (index=NULL, data via SfBlockDesc shadows). */
typedef struct SfStoreHdr {
    uint32_t magic;
    uint32_t version;
    uint32_t n_pages;
    uint32_t page_size;
    uint32_t crc32c;
} SfStoreHdr;

/*
 * RAM store (design §3 layout): a single contiguous allocation/mapping
 *   [hdr][index: n_pages × SfPageKey, ascending][data: n_pages × PAGE]
 * root特例: hdr=NULL, index=NULL, data=NULL — the root shadow lives in the
 * dirty engine's per-block shadows; sf_resolve falls through to it.
 */
#define SF_STORE_MAGIC   0x53465254u   /* "SFRT" */
#define SF_STORE_VERSION 1u

typedef struct SfRamStore {
    SfStoreHdr *hdr;
    SfPageKey  *index;     /* ascending; NULL for root */
    uint8_t    *data;      /* n_pages × page; NULL for root */
    SfBacking   backing;
    uint32_t    n_pages;
    int         fd;        /* FILE backing fd; -1 for ANON */
    void       *map_base;  /* FILE/root contiguous mmap base */
    size_t      map_len;   /* FILE: contiguous mmap length; 0 for ANON */
    char       *path;      /* FILE backing path, for root.ram persist fast path */
} SfRamStore;

/*
 * Device capture. T1 wraps the existing preparse replay tables (the root capture
 * IS the preparse). T4 (plan 2026-07-06-05) evolves this into per-node arenas
 * (mblock_arena + get_arena) captured from live state without re-serializing).
 *
 * 方案 B persistence (plan 07): each snapshot keeps the raw stock vmstate stream
 * it was preparsed from, so sf_snap_persist can write <id>.dev and a cold start
 * can re-preparse it. stream is NULL only when capture failed or a future
 * explicit GC/promote policy drops it; such a node/subtree is not promotable.
 * Freeing the node frees both the replay tables and the retained stream.
 */
typedef struct SfDevCapture {
    SfReplayTables tables;
    bool           have;       /* preparse succeeded; restore replays iff true */
    uint8_t       *stream;     /* owned stock vmstate stream; NULL if absent/dropped */
    size_t         stream_len;
} SfDevCapture;

/*
 * KVM capture (plan 2026-07-06-05 §1). Under the no-kvmclock guest config the
 * TSC is the sole time承重项; kvmclock/KVM master clock are intentionally not
 * maintained (design §4.4 / plan -04 §3 注). T4 may add vapic re-activation
 * markers here; T1 stores only the boundary TSC target.
 */
typedef struct SfKvmCapture {
    uint64_t tsc;
} SfKvmCapture;

typedef struct SfSnapNode {
    uint32_t              id;       /* process-monotonic; root = 0 */
    uint32_t              depth;    /* for LCA two-pointer walk */
    struct SfSnapNode    *parent;   /* root's parent = NULL */
    QLIST_HEAD(, SfSnapNode) children;
    QLIST_ENTRY(SfSnapNode) sibling;
    SfSnapKind            kind;
    SfSnapState           state;
    SfRamStore            ram;
    SfDevCapture          dev;
    SfKvmCapture          kvm;
} SfSnapNode;

/* Global active node (protocol spec: save's parent, restore only changes it). */
extern SfSnapNode *sf_active;
/* Block registry, shared by every node of the current tree. */
extern SfBlockDesc *sf_blocks;
extern size_t       sf_n_blocks;

/* ---- Node tree lifecycle ---- */
SfSnapNode *sf_node_new(SfSnapNode *parent, SfSnapKind kind);
void        sf_node_destroy(SfSnapNode *node);   /* whole subtree, post-order */
SfSnapNode *sf_node_find(uint32_t id);
SfSnapNode *sf_node_lca(SfSnapNode *a, SfSnapNode *b);

/* ---- Block registry / key<->host ---- */
int        sf_blocks_enumerate(Error **errp);    /* RAMBLOCK_FOREACH → sf_blocks */
void       sf_blocks_destroy(void);
bool       sf_host_to_key_safe(void *host_page, SfPageKey *out);  /* false if unknown */
uint8_t   *sf_key_to_host(SfPageKey key);        /* key → live host page base; NULL if bad */
int        sf_key_cmp(const void *a, const void *b);  /* qsort/bsearch SfPageKey order */

/* Host address backing guest-physical @gpa (RAM only); NULL if not RAM. The
 * result is the same host pointer save/restore walks, so it feeds sf_exclude_add
 * for the guest NO_RESTORE register ABI. */
void      *sf_gpa_to_host(hwaddr gpa);

/* ---- Ramstore ---- */
int   sf_ramstore_create_anon(SfRamStore *s, uint32_t n_pages);
void  sf_ramstore_destroy(SfRamStore *s);
int   sf_ramstore_lookup(const SfRamStore *s, SfPageKey key);  /* bsearch; -1 if absent */

/* FILE backing (T6 persistence, plan 07 §2). Layout == on-disk == in-mmap:
 *   [hdr][index n_pages×key][pad→page][data n_pages×page]  (data page-aligned).
 * create_file: O_RDWR mmap, writable, caller fills index/data (as for anon).
 * seal: crc32c the payload into hdr, msync, mprotect(PROT_READ) → immutable/shareable.
 * open_file: map an existing sealed file read-only, verifying magic/version/size/crc. */
int   sf_ramstore_create_file(SfRamStore *s, uint32_t n_pages, const char *path,
                              Error **errp);
int   sf_ramstore_seal(SfRamStore *s, Error **errp);
int   sf_ramstore_open_file(SfRamStore *s, const char *path, Error **errp);

/* Root backing: raw block-order contiguous bytes (no SfStoreHdr/index). This is
 * root.ram's in-memory form. create_* copies no RAM; caller fills data using
 * sf_blocks[i].root_off, then registers the slices with the dirty engine. */
uint64_t sf_blocks_root_len(void);
int   sf_rootstore_create_anon(SfRamStore *s);
int   sf_rootstore_create_file(SfRamStore *s, const char *path, Error **errp);
int   sf_rootstore_open_file(SfRamStore *s, const char *path, Error **errp);
int   sf_rootstore_seal(SfRamStore *s, Error **errp);
uint8_t *sf_rootstore_page(const SfRamStore *s, SfPageKey key);
void  sf_node_observe_id(uint32_t id);

/* Composite-id worker slot. worker_id is injected by the host (env SF_WORKER_ID
 * at first node creation, or this override for HMP/tests); the worker never
 * self-selects. root always keeps the reserved id 0 regardless of the worker
 * slot. Switching the slot resets the per-worker local counter (worker 0
 * reserves local 0 for the root). */
void     sf_node_set_worker_id(uint32_t wid);
uint32_t sf_node_worker_id(void);
/* Id the next non-root sf_node_new will assign (peek, no advance). */
uint32_t sf_node_peek_next_id(void);

/* Owner resolution (design §3): ≤dst 的最近 owner 的 data page; root 兜底. */
uint8_t *sf_resolve(SfSnapNode *dst, SfPageKey key);

/* ---- Top-level save/restore (HMP + terminal route here) ---- */
/* @persist_dir != NULL (op `S`, non-root only) builds the diff straight into its
 * file store and promotes it (durable in one pass, skipping promote's second copy);
 * @common_ref threads through to that promote. NULL/NULL = plain in-RAM `s`. */
int   sf_snap_save(SfSnapKind kind, const char *persist_dir,
                   const char *common_ref, Error **errp);
/* @debug is an optional device-replay skip-knob (HMP debug=/terminal SF_CP_SKIP);
 * NULL for a normal restore. */
int   sf_snap_restore(uint32_t dst_id, const SfReplayDebug *debug, Error **errp);

/* Restore-tracker lifecycle (plan 2026-07-08-03 R4). Build the flat restore-store
 * over the current sf_blocks + arm KVM dirty tracking (@active = restore-target
 * hint); disarm frees the store. ram_root/cold-start/promote drive these; every
 * other save/restore just drains/plans/applies through the armed session. */
int   sf_snap_tracker_arm(SfSnapNode *active, Error **errp);
void  sf_snap_tracker_disarm(void);

/* ---- RAM-only cores (selftest / building blocks; no device, no guard) ----
 * Production save/restore wrap these with device capture (T4) + clock tail.
 * Exposed so the RAM diff/delta mechanics are testable under pc KVM (where the
 * microvm hot-profile guard refuses the full preparse). */
SfSnapNode *sf_snap_ram_root(Error **errp);   /* root backing + blocks + root node, sets sf_active */

/* Optional out-params for SF_TIME bucket split of build_diff (plan/memcmp/save/rebase).
 * Pass NULL when not timing. See arch/perf-metrics.md §2. */
typedef struct {
    uint64_t plan_ns;
    uint64_t memcmp_ns;
    uint64_t save_ns;
    uint64_t rebase_ns;
} SfSnapDiffTiming;

SfSnapNode *sf_snap_build_diff(SfSnapNode *parent, SfSnapKind kind, bool activate,
                               const char *persist_dir,
                               SfSnapDiffTiming *timing_out, Error **errp);
                               /* collect ∪ HOT → non-root diff node (RAM only);
                                * activate=re-baseline tracker to the new node */
int   sf_snap_delta_restore(uint32_t dst_id, Error **errp);  /* RAM delta-restore (no device/clock) */

/* ---- selftest fault injection (test-only; production never calls these) ----
 * Each forces the RAM diff/delta machinery down a wrong path so a correctness
 * check goes RED — proving the mechanism has teeth. Pass id=0xFFFFFFFF to
 * disable. Dirty-page loss injection lives in the tracker (sf_track_inject_drop). */
void sf_resolve_inject_skip_node(uint32_t node_id);   /* sf_resolve skips this node */

int   sf_snap_delete(uint32_t id, Error **errp);
void  sf_snap_tree(Monitor *mon);
bool  sf_snap_have_snapshot(void);   /* sf_active != NULL */

#endif /* SF_SNAP_NODE_H */
