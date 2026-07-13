/* sf/perf/hwcounters.h — see header for the two-group / phase-split design. */
#include "qemu/osdep.h"
#include "sf/perf/hwcounters.h"

#include <linux/perf_event.h>
#include <sys/syscall.h>

#define SF_HW_N 3   /* insns, cycles, llc-miss (creation order) */

struct SfHwGroup {
    int fd[SF_HW_N];   /* independent counters; fd < 0 = unsupported → 0 */
};

static int sf_perf_event_open(struct perf_event_attr *a, pid_t pid, int cpu,
                              int group_fd, unsigned long flags)
{
    return (int)syscall(__NR_perf_event_open, a, pid, cpu, group_fd, flags);
}

/* Open one enabled counter on the calling thread, or -1 if unsupported. */
static int sf_hw_open_one(uint32_t type, uint64_t config, bool guest_only)
{
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = type;
    a.size = sizeof(a);
    a.config = config;
    a.exclude_host  = guest_only ? 1 : 0;
    a.exclude_guest = guest_only ? 0 : 1;
    /* count kernel too: guest side needs guest-kernel; host side folds in the
     * kernel page-fault/COW handling that is part of the restore memcpy. */
    return sf_perf_event_open(&a, 0 /* calling thread */, -1, -1, 0);
}

SfHwGroup *sf_hw_open(bool guest_only)
{
    static const struct { uint32_t type; uint64_t config; } evs[SF_HW_N] = {
        { PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS },
        { PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES },
        /* generic last-level-cache misses → DRAM traffic. The HW_CACHE_LL|READ|MISS
         * encoding (perf's "LLC-load-misses") is <not supported> on this EPYC;
         * PERF_COUNT_HW_CACHE_MISSES maps to a real LLC-miss event on AMD. */
        { PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES },
    };
    SfHwGroup *g = g_new(SfHwGroup, 1);
    int i, ok = 0;

    for (i = 0; i < SF_HW_N; i++) {
        g->fd[i] = sf_hw_open_one(evs[i].type, evs[i].config, guest_only);
        ok += (g->fd[i] >= 0);
    }
    if (!ok) {   /* nothing opened (denied?) → caller zeros */
        g_free(g);
        return NULL;
    }
    return g;
}

static uint64_t sf_hw_read_one(int fd)
{
    uint64_t v = 0;
    if (fd >= 0 && read(fd, &v, sizeof(v)) != (ssize_t)sizeof(v)) {
        v = 0;
    }
    return v;
}

void sf_hw_read(SfHwGroup *g, SfHwCounts *out)
{
    memset(out, 0, sizeof(*out));
    if (!g) {
        return;
    }
    out->insns    = sf_hw_read_one(g->fd[0]);
    out->cycles   = sf_hw_read_one(g->fd[1]);
    out->llc_miss = sf_hw_read_one(g->fd[2]);
}
