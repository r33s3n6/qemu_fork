/*
 * sf/snap/cold — M3 cold-start core. Load a persisted tree, remap root.ram as
 * live RAM, rebuild replay tables from .dev streams, and restore to a target.
 */
#ifndef SF_SNAP_COLD_H
#define SF_SNAP_COLD_H

#include "qapi/error.h"

int sf_cold_start(const char *dir, uint32_t dst_id, bool restore_exclude,
                  bool skip_checkpoint_outl, Error **errp);

#endif /* SF_SNAP_COLD_H */
