/*
 * sf/vmstate_replay/replay — replay the three tables built by preparse to
 * restore device state, and cross-check against the stock loader.
 *
 * Include qemu/osdep.h before this header.
 */
#ifndef SF_VMSTATE_REPLAY_REPLAY_H
#define SF_VMSTATE_REPLAY_REPLAY_H

#include "sf/vmstate_replay/preparse.h"

/*
 * Restore device state from @t: run pre_load hooks, memcpy every mblock, replay
 * every get (re-arming timers etc. via info->get over the captured stream
 * slice), then run post_load hooks — in that order.
 */
typedef struct {
    bool skip_mblock;
    size_t skip_mblock_index;
    bool skip_get;
    size_t skip_get_index;
    bool skip_pre;
    size_t skip_pre_index;
    bool skip_post;
    size_t skip_post_index;
} SfReplayDebug;

void sf_replay(const SfReplayTables *t);

/*
 * Debug-only replay fault injection for selftests. Production restore calls
 * sf_replay(), which passes no debug knobs.
 */
void sf_replay_with_debug(const SfReplayTables *t, const SfReplayDebug *debug);

/*
 * selftest ⑤: from the current device state, verify sf_replay reconstructs the
 * exact same device state as the stock qemu_load_device_state. Both paths start
 * from an identical deliberate perturbation; their re-serialized device states
 * must be byte-equal. Returns true on match. Destroys+restores state internally.
 */
bool sf_replay_matches_stock(const SfReplayTables *t, Error **errp);

bool sf_replay_matches_stock_with_debug(const SfReplayTables *t,
                                        const SfReplayDebug *debug,
                                        Error **errp);

#endif /* SF_VMSTATE_REPLAY_REPLAY_H */
