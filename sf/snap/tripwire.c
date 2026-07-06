/*
 * sf/snap/tripwire — host-write-to-snapshot-RAM enforcement. See tripwire.h.
 * Clean-room: no QEMU-Nyx code (Nyx hooks the same funnel in 4.2 for user-fdl).
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "system/memory.h"
#include "sf/snap/tripwire.h"
#include "sf/snap/exclude.h"
#include "sf/snap/node.h"   /* sf_host_to_key_safe (snapshot-semantic membership) */

static bool          g_armed;
static bool          g_inject_disable;
static bool          g_mode_override;   /* true once sf_tripwire_set_mode used */
static bool          g_mode_abort;
static unsigned long g_count;

/* SF_TRIPWIRE=abort (default, debug) → abort on violation; =count → count + log.
 * sf_tripwire_set_mode overrides the env (selftest runs count). */
static bool sf_trip_abort_mode(void)
{
    if (g_mode_override) {
        return g_mode_abort;
    }
    const char *s = getenv("SF_TRIPWIRE");
    return !(s && !strcmp(s, "count"));
}

void sf_tripwire_arm(bool arm) { g_armed = arm; }
bool sf_tripwire_armed(void) { return g_armed; }
unsigned long sf_tripwire_count(void) { return g_count; }
void sf_tripwire_reset_count(void) { g_count = 0; }
void sf_tripwire_inject_disable(bool disable) { g_inject_disable = disable; }
void sf_tripwire_set_mode(bool abort_mode) { g_mode_override = true; g_mode_abort = abort_mode; }

void sf_tripwire_hit(MemoryRegion *mr, hwaddr addr, hwaddr length)
{
    if (!g_armed || g_inject_disable) {
        return;
    }
    /* Host address of the written byte (resolve aliases via get_ram_ptr). */
    uint8_t *host = (uint8_t *)memory_region_get_ram_ptr(mr) + addr;

    /* Not snapshot-semantic RAM (e.g. device mmio, non-tracked region) → 放行. */
    SfPageKey key;
    if (!sf_host_to_key_safe(host, &key)) {
        return;
    }
    /* NO_RESTORE-excluded (task buffer etc.) → legitimate host write → 放行. */
    if (sf_excluded(host)) {
        return;
    }

    /* Violation: a host-side write reached snapshot-semantic RAM. This is the
     * DMA / future non-NO_RESTORE-buf hazard. Upgrade path (plan -06 §2): turn
     * this into a Nyx-style user-dirty record (append to the restore set +
     * mark dirty) instead of abort, when the first non-NO_RESTORE buf appears. */
    g_count++;
    error_report("sf_tripwire: host write to snapshot RAM %p (mr=%s addr=0x%"
                 HWADDR_PRIx " len=%" HWADDR_PRIx ") — host writes bypass the KVM"
                 " dirty ring; snapshot would silently miss this page",
                 host, memory_region_name(mr), addr, length);
    if (sf_trip_abort_mode()) {
        abort();
    }
}