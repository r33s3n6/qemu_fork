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

/* Single snapshot slot for the M0-S spike (one snapshot, many restores). */
static SfReplayTables g_sf_tables;
static bool g_sf_have_snapshot;

void hmp_sf_snapshot(Monitor *mon, const QDict *qdict)
{
    Error *err = NULL;

    if (g_sf_have_snapshot) {
        sf_replay_tables_destroy(&g_sf_tables);
        g_sf_have_snapshot = false;
    }
    if (sf_preparse(&g_sf_tables, &err) < 0) {
        monitor_printf(mon, "sf: snapshot failed: %s\n", error_get_pretty(err));
        error_free(err);
        return;
    }
    g_sf_have_snapshot = true;

    size_t mbytes = 0;
    for (size_t i = 0; i < g_sf_tables.n_mblocks; i++) {
        mbytes += g_sf_tables.mblocks[i].size;
    }
    monitor_printf(mon, "sf: snapshot ok: mblocks=%zu (%zu bytes) gets=%zu "
                   "posts=%zu\n", g_sf_tables.n_mblocks, mbytes,
                   g_sf_tables.n_gets, g_sf_tables.n_posts);
}

void hmp_sf_restore(Monitor *mon, const QDict *qdict)
{
    if (!g_sf_have_snapshot) {
        monitor_printf(mon, "sf: no snapshot; run sf_snapshot first\n");
        return;
    }
    sf_replay(&g_sf_tables);
    monitor_printf(mon, "sf: restore ok\n");
}

void hmp_sf_selftest(Monitor *mon, const QDict *qdict)
{
    Error *err = NULL;

    if (!g_sf_have_snapshot) {
        monitor_printf(mon, "sf: no snapshot; run sf_snapshot first\n");
        return;
    }

    /* Case ⑤: sf_replay must reconstruct the same device state as stock load. */
    bool good = sf_replay_matches_stock(&g_sf_tables, &err);
    monitor_printf(mon, "sf: selftest[5] replay-vs-stock: %s%s%s\n",
                   good ? "GREEN" : "RED",
                   good ? "" : " — ", good ? "" : error_get_pretty(err));
    error_free(err);
    err = NULL;
    if (!good) {
        return;
    }

    /* Discriminator: corrupt one mblock.copy and confirm the cross-check turns
     * RED. Proves the check has teeth (not a tautology). Restore the byte after. */
    if (g_sf_tables.n_mblocks && g_sf_tables.mblocks[0].size) {
        uint8_t *copy = g_sf_tables.mblocks[0].copy;
        uint8_t orig = copy[0];
        copy[0] ^= 0xFF;
        bool matched = sf_replay_matches_stock(&g_sf_tables, &err);
        copy[0] = orig;
        error_free(err);
        /* The check has teeth iff the corruption made it diverge (RED). */
        monitor_printf(mon, "sf: selftest[5-neg] corruption-detected: %s\n",
                       !matched ? "GREEN (has teeth)" : "RED (BUG: undetected)");
    }
}
