/*
 * sf/vmstate_replay/preparse — pre-parse the device-state VMSD tree once into
 * three flat replay tables (mblock / get / post).
 *
 * Model (design decision 2026-07-04, see the impl plan Task 4): pre-parse is a
 * "recording real load". We save the current device state to a buffer, reopen
 * it, and walk it field-by-field running the stock info->get() (advancing the
 * stream and re-applying side effects with identical values). Per field we
 * record where to put it back on replay:
 *   - plain scalars / buffers  -> mblock: memcpy live memory back on replay.
 *     copy is captured from *memory* (post-get, host-endian), never from the
 *     big-endian stream, so endianness is correct by construction.
 *   - side-effecting fields (timer, ...) -> get: replay info->get() over the
 *     exact captured stream slice (re-arms timers, etc.).
 *   - pre_load / post_load hooks -> post: re-run in order on replay.
 *
 * Include qemu/osdep.h before this header.
 */
#ifndef SF_VMSTATE_REPLAY_PREPARSE_H
#define SF_VMSTATE_REPLAY_PREPARSE_H

#include "migration/vmstate.h"

/* Contiguous run of device memory to memcpy back verbatim on replay. */
typedef struct {
    void   *ptr;    /* live device memory */
    void   *copy;   /* snapshot bytes (owned; captured from ptr at preparse) */
    size_t  size;
} SfMblock;

/* A field whose load has side effects: replay by re-running info->get(). */
typedef struct {
    const VMStateInfo   *info;         /* the stock get to replay */
    const VMStateField  *field;        /* field arg for info->get */
    void                *ptr;          /* target device memory (curr_elem) */
    void                *captured;     /* owned raw stream slice this get read */
    size_t               captured_len; /* bytes in captured */
    size_t               size;         /* size arg for info->get */
} SfGet;

/* A pre_load / post_load hook to re-run on replay, in recorded order. */
typedef struct {
    const VMStateDescription *vmsd;
    void                     *opaque;
    bool                      is_pre;     /* true: pre_load, false: post_load */
    int                       version_id; /* arg for post_load */
} SfPost;

typedef struct {
    SfMblock *mblocks; size_t n_mblocks;
    SfGet    *gets;    size_t n_gets;
    SfPost   *posts;   size_t n_posts;
} SfReplayTables;

/*
 * Pre-parse the full non-iterable device state (all VMSD sections; RAM and
 * other iterable/ops sections are handled by the dirty engine, not here) into
 * @out. Returns 0 on success, <0 with @errp set on failure. On success the
 * caller owns @out and must release it with sf_replay_tables_destroy().
 */
int sf_preparse(SfReplayTables *out, Error **errp);

void sf_replay_tables_destroy(SfReplayTables *t);

#endif /* SF_VMSTATE_REPLAY_PREPARSE_H */
