/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 * HMP entry points. Task 1: stubs; wired to real engine in later tasks.
 */
#include "qemu/osdep.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"
#include "sf/sf.h"

void hmp_sf_snapshot(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "sf: stub snapshot\n");
}

void hmp_sf_restore(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "sf: stub restore\n");
}

void hmp_sf_selftest(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "sf: stub selftest (no cases)\n");
}
