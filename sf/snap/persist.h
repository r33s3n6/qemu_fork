/*
 * sf/snap/persist — snapshot-tree persistence (T6, plan 07 §1/§2, 方案 B).
 * Serialize a tree to a directory and load it back:
 *   <dir>/manifest.json     version/page_size/blocks/nodes(id,parent,kind,depth,
 *                           kvm_tsc)/root_ram len+crc
 *   <dir>/root.ram          root full-RAM shadow, raw block-order平铺(no hdr)
 *   <dir>/nodes/<id>.ram    each non-root diff store (SfRamStore FILE format)
 * Device streams (<id>.dev, 方案 B) are the next increment; this covers the RAM
 * + tree structure, which is testable in-process without the microvm rig.
 *
 * Include qemu/osdep.h before this header.
 */
#ifndef SF_SNAP_PERSIST_H
#define SF_SNAP_PERSIST_H

#include "qapi/error.h"
#include "sf/snap/node.h"

/* Persist the tree rooted at @root (must be a real root, parent==NULL) into
 * @dir (created if absent). Manifest written atomically (tmp+rename). */
int  sf_snap_persist(SfSnapNode *root, const char *dir, Error **errp);

/* Load a persisted tree from @dir into a fresh detached tree (*root_out).
 * Validates the manifest against the live block registry (idstr/len), root.ram
 * len+crc, and each diff store's crc. Does NOT touch sf_active or remap guest
 * RAM (cold start does that, T7); the loaded root's RAM stays empty so
 * in-process owner-resolution falls through to the live engine shadow. */
int  sf_snap_load(const char *dir, SfSnapNode **root_out, Error **errp);

/* Free a tree returned by sf_snap_load (no tripwire side effects). */
void sf_snap_free_loaded(SfSnapNode *root);

#endif /* SF_SNAP_PERSIST_H */
