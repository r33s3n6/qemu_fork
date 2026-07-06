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
#include "sf/vmstate_replay/replay.h"   /* SfReplayDebug (sf_snap_restore_debug) */

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
typedef struct SfRamStore {
    SfStoreHdr *hdr;
    SfPageKey  *index;     /* ascending; NULL for root */
    uint8_t    *data;      /* n_pages × page; NULL for root */
    SfBacking   backing;
    uint32_t    n_pages;
    int         fd;        /* FILE backing fd; -1 for ANON */
} SfRamStore;

/*
 * Device capture. T1 wraps the existing preparse replay tables (the root capture
 * IS the preparse). T4 (plan 2026-07-06-05) evolves this into per-node arenas
 * (mblock_arena + get_arena) captured from live state without re-serializing.
 */
typedef struct SfDevCapture {
    SfReplayTables tables;
    bool           have;   /* preparse succeeded; restore replays iff true */
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
SfPageKey  sf_host_to_key(void *host_page);      /* host page addr → key; 0 if unknown */
bool       sf_host_to_key_safe(void *host_page, SfPageKey *out);  /* false if unknown */
uint8_t   *sf_key_to_host(SfPageKey key);        /* key → live host page base; NULL if bad */

/* ---- Ramstore ---- */
int   sf_ramstore_create_anon(SfRamStore *s, uint32_t n_pages);
void  sf_ramstore_destroy(SfRamStore *s);
int   sf_ramstore_lookup(const SfRamStore *s, SfPageKey key);  /* bsearch; -1 if absent */

/* Owner resolution (design §3): ≤dst 的最近 owner 的 data page; root 兜底. */
uint8_t *sf_resolve(SfSnapNode *dst, SfPageKey key);

/* ---- Top-level save/restore (HMP + terminal route here) ---- */
int   sf_snap_save(SfSnapKind kind, Error **errp);
int   sf_snap_restore(uint32_t dst_id, Error **errp);

/* ---- RAM-only cores (selftest / building blocks; no device, no guard) ----
 * Production save/restore wrap these with device capture (T4) + clock tail.
 * Exposed so the RAM diff/delta mechanics are testable under pc KVM (where the
 * microvm hot-profile guard refuses the full preparse). */
SfSnapNode *sf_snap_ram_root(Error **errp);   /* engine shadow + blocks + root node, sets sf_active */
SfSnapNode *sf_snap_build_diff(SfSnapNode *parent, SfSnapKind kind,
                               Error **errp);  /* collect ∪ HOT → non-root diff node (RAM only) */
int   sf_snap_delta_restore(uint32_t dst_id, Error **errp);  /* RAM delta-restore (no device/clock) */

/* ---- selftest fault injection (test-only; production never calls these) ----
 * Each forces the RAM diff/delta machinery down a wrong path so a correctness
 * check goes RED — proving the mechanism has teeth. Pass id=0xFFFFFFFF / false
 * to disable. */
void sf_resolve_inject_skip_node(uint32_t node_id);   /* sf_resolve skips this node */
void sf_snap_inject_skip_hot(bool skip);              /* build_diff omits the HOT union */

/* Restore with a device-replay skip-knob (HMP debug=/terminal SF_CP_SKIP). */
int   sf_snap_restore_debug(uint32_t dst_id, const SfReplayDebug *debug,
                            Error **errp);
int   sf_snap_delete(uint32_t id, Error **errp);
void  sf_snap_tree(Monitor *mon);
bool  sf_snap_have_snapshot(void);   /* sf_active != NULL */

#endif /* SF_SNAP_NODE_H */