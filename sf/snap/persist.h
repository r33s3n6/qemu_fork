/*
 * sf/snap/persist — snapshot-tree persistence (T6, plan 07 §1/§2, 方案 B).
 * Serialize a tree to a directory and load it back:
 *   <dir>/manifest.json     version/page_size/blocks/root_ram_len/exclude
 *                           (NO_RESTORE ranges as block-relative block/off/size).
 *                           Header only — NO nodes here.
 *   <dir>/nodes.log         append-only node log, one record per line:
 *                           id(parent composite)/parent/kind/depth/kvm_tsc/
 *                           dev_len/dev_crc + trailing crc32c; load drops a
 *                           truncated tail line (snapshot-tree.md §5.1).
 *   <dir>/root.ram          root full-RAM shadow, raw block-order平铺(no hdr)
 *   <dir>/root.dev          root device stream (stock vmstate; 方案 B), if kept
 *   <dir>/nodes/<id>.ram    each non-root diff store (SfRamStore FILE format)
 *   <dir>/nodes/<id>.dev    each retained non-root device stream
 * Load re-parses each present .dev via sf_preparse_stream to rebuild the replay
 * tables (方案 B cold-start重建). Device-state真实端到端对拍待 microvm (selftest 8).
 *
 * Include qemu/osdep.h before this header.
 */
#ifndef SF_SNAP_PERSIST_H
#define SF_SNAP_PERSIST_H

#include "qapi/error.h"
#include "sf/snap/node.h"

/* Persist the tree rooted at @root (must be a real root, parent==NULL) into
 * @dir (created if absent). Manifest written atomically (tmp+rename). */
int  sf_snap_persist(SfSnapNode *root, const char *dir, bool save_exclude,
                     Error **errp);

/* Promote one node into @dir's append-only log. Root may be promoted first; a
 * non-root node is accepted only after its parent is already PERSISTED. The
 * node's RAM store is switched to file backing, its device stream is written,
 * then exactly one record is appended to nodes.log (the commit point). The log
 * is never rewritten, so sibling branches promoted before/after are preserved
 * (snapshot-tree.md §5.1). Root promote also writes the manifest.json header. */
int  sf_snap_promote(SfSnapNode *node, const char *dir, Error **errp);

/* Load a persisted tree from @dir into a fresh detached tree (*root_out).
 * Validates the manifest header against the live block registry (idstr/len) and
 * root.ram length, then replays nodes.log (crc per line, truncated tail
 * dropped) and each diff store's crc. Does NOT touch sf_active or remap guest
 * RAM (cold start does that, T7); the loaded root's RAM stays empty until the
 * cold-start core maps root.ram as the root backing. */
int  sf_snap_load(const char *dir, SfSnapNode **root_out, Error **errp);

/* Free a tree returned by sf_snap_load (no tripwire side effects). */
void sf_snap_free_loaded(SfSnapNode *root);

/* Cold-start only: re-read @dir/manifest.json's exclude list and rebuild the
 * live NO_RESTORE table from block-relative offsets (host = live block base +
 * off). Requires the live block registry to be enumerated first. §4.2-3. */
int  sf_exclude_reload(const char *dir, bool restore_content, Error **errp);

#endif /* SF_SNAP_PERSIST_H */
