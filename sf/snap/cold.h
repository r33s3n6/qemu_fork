/*
 * sf/snap/cold — M3 cold-start core. Load a persisted tree, remap root.ram as
 * live RAM, rebuild replay tables from .dev streams, and restore to a target.
 */
#ifndef SF_SNAP_COLD_H
#define SF_SNAP_COLD_H

#include "qapi/error.h"

/* Cold-start into a persisted tree and restore to @dst_id. Two dirs (plan 04
 * §2.2): @common_dir is the read-only shared base (holds root.ram + the common
 * tree); @private_dir is a worker's writable overlay grafted on top. Either may
 * be NULL/"" — passing one dir is the single-dir case (self-contained tree, or
 * a private_dir whose manifest names its common base). */
int sf_cold_start(const char *common_dir, const char *private_dir,
                  uint32_t dst_id, bool restore_exclude,
                  bool skip_checkpoint_outl, Error **errp);

#endif /* SF_SNAP_COLD_H */
