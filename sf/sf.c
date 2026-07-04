/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 * HMP entry points. Task 1: stubs; wired to real engine in later tasks.
 */
#include "qemu/osdep.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"
#include "migration/vmstate.h"
#include "sf/sf.h"

/* Task2 temporary probe: prove we can walk savevm sections + reach their VMSD. */
static void sf_probe_visit(const char *idstr, uint32_t instance_id,
                           const VMStateDescription *vmsd, void *opaque,
                           void *user)
{
    Monitor *mon = user;
    monitor_printf(mon, "sf-section: %-24s inst=%u vmsd=%s\n",
                   idstr, instance_id, vmsd ? vmsd->name : "(null/ops)");
}

void hmp_sf_snapshot(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "sf: sections:\n");
    sf_savevm_for_each_vmsd(sf_probe_visit, mon);
}

void hmp_sf_restore(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "sf: stub restore\n");
}

void hmp_sf_selftest(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "sf: stub selftest (no cases)\n");
}
