/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 * HMP entry points. Wires pre-parse (snapshot) + replay (restore) + selftest.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"
#include "migration/vmstate.h"
#include "sf/sf.h"
#include "sf/vmstate_replay/preparse.h"
#include "sf/vmstate_replay/replay.h"
#include "sf/dirty/engine.h"
#include "sf/selftest/selftest.h"

/* Single snapshot slot for the M0-S spike (one snapshot, many restores). */
static SfReplayTables g_sf_tables;
static bool g_sf_have_snapshot;

void hmp_sf_snapshot(Monitor *mon, const QDict *qdict)
{
    Error *err = NULL;

    /* RAM side (Task 6) — the subject of this task; must succeed. */
    if (sf_dirty_snapshot(&err) < 0) {
        monitor_printf(mon, "sf: snapshot failed (RAM): %s\n",
                       error_get_pretty(err));
        error_free(err);
        return;
    }

    /*
     * Device side (Task 4/5) — best-effort so a device-preparse gap (e.g. an
     * unhandled vmstate field only present under KVM) surfaces loudly without
     * masking the RAM result. Restore replays the device table only if present.
     */
    if (g_sf_have_snapshot) {
        sf_replay_tables_destroy(&g_sf_tables);
        g_sf_have_snapshot = false;
    }
    if (sf_preparse(&g_sf_tables, &err) < 0) {
        monitor_printf(mon, "sf: WARNING device preparse failed: %s "
                       "(RAM snapshot still taken)\n", error_get_pretty(err));
        error_free(err);
        err = NULL;
    } else {
        g_sf_have_snapshot = true;
    }

    size_t mbytes = 0;
    for (size_t i = 0; i < g_sf_tables.n_mblocks; i++) {
        mbytes += g_sf_tables.mblocks[i].size;
    }
    monitor_printf(mon, "sf: snapshot ok: RAM shadowed; device %s "
                   "(mblocks=%zu (%zu bytes) gets=%zu posts=%zu)\n",
                   g_sf_have_snapshot ? "ok" : "SKIPPED",
                   g_sf_tables.n_mblocks, mbytes,
                   g_sf_tables.n_gets, g_sf_tables.n_posts);
}

void hmp_sf_restore(Monitor *mon, const QDict *qdict)
{
    uint64_t collected;
    uint32_t copied;

    if (!sf_dirty_have_snapshot()) {
        monitor_printf(mon, "sf: no snapshot; run sf_snapshot first\n");
        return;
    }

    /* Device state first (registers), then RAM contents. */
    if (g_sf_have_snapshot) {
        sf_replay(&g_sf_tables);
    }

    collected = sf_dirty_collect();
    copied = sf_dirty_restore();
    sf_dirty_reset_ring();

    monitor_printf(mon, "sf: restore ok: device=%s ram collected=%" PRIu64
                   " copied-back=%" PRIu32 "\n",
                   g_sf_have_snapshot ? "replayed" : "SKIPPED",
                   collected, copied);
}

void hmp_sf_selftest(Monitor *mon, const QDict *qdict)
{
    Error *err = NULL;

    /* Self-contained: preparse/snapshot as each case needs (no prior sf_snapshot
     * required). Aggregates restore-correctness cases ①–⑤ (see sf/selftest/). */
    if (!sf_selftest_all(mon, &err)) {
        if (err) {
            monitor_printf(mon, "sf: selftest error: %s\n", error_get_pretty(err));
            error_free(err);
        }
    }
}
