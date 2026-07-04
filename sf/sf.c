/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 * HMP entry points. Task 1: stubs; wired to real engine in later tasks.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"
#include "migration/vmstate.h"
#include "sf/sf.h"
#include "sf/vmstate_replay/preparse.h"

/* Task4 probe: pre-parse device state into the three replay tables and report
 * their shape. Task5 will keep the tables and add replay; here we free them. */
void hmp_sf_snapshot(Monitor *mon, const QDict *qdict)
{
    SfReplayTables t = {0};
    Error *err = NULL;

    if (sf_preparse(&t, &err) < 0) {
        monitor_printf(mon, "sf: preparse failed: %s\n",
                       error_get_pretty(err));
        error_free(err);
        return;
    }

    size_t mbytes = 0;
    for (size_t i = 0; i < t.n_mblocks; i++) {
        mbytes += t.mblocks[i].size;
    }
    monitor_printf(mon, "sf: preparse ok: mblocks=%zu (%zu bytes) gets=%zu "
                   "posts=%zu\n", t.n_mblocks, mbytes, t.n_gets, t.n_posts);
    for (size_t i = 0; i < t.n_gets; i++) {
        monitor_printf(mon, "sf:   get[%zu] info=%s len=%zu\n",
                       i, t.gets[i].info->name, t.gets[i].captured_len);
    }
    sf_replay_tables_destroy(&t);
}

void hmp_sf_restore(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "sf: stub restore\n");
}

void hmp_sf_selftest(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "sf: stub selftest (no cases)\n");
}
