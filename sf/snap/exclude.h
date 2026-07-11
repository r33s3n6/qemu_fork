/*
 * sf/snap/exclude — NO_RESTORE exclusion region table (plan 2026-07-06-06 §1).
 *
 * Truth source = the protocol v2 REGISTER_BUF(...,flags) NO_RESTORE flag: buf
 * pages flagged NO_RESTORE are excluded from save/restore (not diffed, not
 * rolled back) and tripwire-exempt. The M1 hypercall handler will call
 * sf_exclude_add() at registration time; until then the table is empty (the
 * three接入点 are no-ops). Persisted with the manifest (plan 07); cold start
 * rebuilds the host mapping then re-fills this table.
 *
 * Include qemu/osdep.h before this header.
 */
#ifndef SF_SNAP_EXCLUDE_H
#define SF_SNAP_EXCLUDE_H

#include <stdint.h>
#include <stdbool.h>
#include "qapi/error.h"

/*
 * Add an excluded range [host_start, host_start + size) tagged with @buf_id.
 * @host_start and @size must be page-aligned (enforced). Keeps the table sorted
 * by host_start so sf_excluded() is a binary search.
 */
void sf_exclude_add(uint64_t host_start, uint64_t size, uint32_t buf_id);

/* True iff @host falls in any excluded range. Empty table → false (one load +
 * branch, hot-path zero-cost). */
bool sf_excluded(const void *host);

/* Drop every excluded range (tree teardown / fresh tree). */
void sf_exclude_clear(void);

/* Number of registered ranges (diagnostics / selftest). */
size_t sf_exclude_count(void);

/* Read range @i (0-based, i < sf_exclude_count) as host_start/size/buf_id.
 * Used to persist the table into the manifest as block-relative offsets. */
bool sf_exclude_get(size_t i, uint64_t *host_start, uint64_t *size,
                    uint32_t *buf_id);

/* Backing-file path for a registered buffer: <dir>/bufs/<buf_id>.buf. Caller
 * frees (g_free). The convention is the single source — no manifest path field. */
char *sf_buf_path(const char *dir, uint32_t buf_id);

/*
 * Remap the excluded buffer [host, host+size) onto a named MAP_SHARED file
 * (sf_buf_path) so a control process can mmap the same file and write the
 * guest's task buffer zero-copy (plan 04 §2.4 / S5). @host and @size are
 * page-aligned (sf_exclude_add enforced it).
 *   @create   — register time: create+truncate the file and seed it from the
 *               buffer's current bytes (preserve what the guest already wrote).
 *               !@create reopens an existing file (cold-start re-remap after the
 *               root.ram MAP_PRIVATE remap clobbered this mapping, M1 §8 order ①).
 *   @map_fixed— MAP_FIXED the file over @host's HVA in place (KVM re-faults the
 *               page from the file on resume). false only for the S5 teeth
 *               (SF_BUF_NO_REMAP): the file exists+seeded but the guest page is
 *               NOT backed by it, so a control-process write stays invisible.
 */
int sf_buf_remap(uint64_t host, uint64_t size, uint32_t buf_id,
                 const char *dir, bool create, bool map_fixed, Error **errp);

#endif /* SF_SNAP_EXCLUDE_H */