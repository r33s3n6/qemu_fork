/* sf/perf/hwcounters.h — see header for the two-group / phase-split design. */
#include "qemu/osdep.h"
#include "sf/perf/hwcounters.h"

#include <linux/perf_event.h>
#include <sys/syscall.h>

#define SF_HW_N 3   /* insns, cycles, llc-miss (creation order) */

struct SfHwGroup {
    int fd[SF_HW_N];   /* independent counters; fd < 0 = unsupported → 0 */
    int aperf_fd;      /* msr PMU; guest group only, else -1 */
    int mperf_fd;
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

/* AMD Zen3 ls_any_fills_from_sys.mem_io_local — data-cache fills from local DRAM
 * (incl. prefetch). TRUE DRAM read traffic; replaces the coarse CACHE_MISSES that
 * conflated L3-hit L2-misses with real DRAM. See header. ponytail: AMD-specific
 * raw code; on non-Zen3 this event is unsupported → fd<0 → dram_fill reads 0. */
#define SF_EV_DRAM_FILL 0x844

/* msr PMU dynamic type (config 0x01=aperf, 0x02=mperf). Type is not a fixed
 * PERF_TYPE_* — read it from sysfs. -1 if the PMU is absent. */
static int sf_msr_pmu_type(void)
{
    int t = -1;
    FILE *f = fopen("/sys/bus/event_source/devices/msr/type", "re");
    if (f) {
        if (fscanf(f, "%d", &t) != 1) {
            t = -1;
        }
        fclose(f);
    }
    return t;
}

/* aperf/mperf on the calling thread, no exclude (total on-cpu cycles: aperf
 * spans guest + in-kernel KVM, so aperf-guest_cycles = machinery). msr PMU is
 * not a core PMC → free of the 6-counter budget. -1 if unsupported. */
static int sf_msr_open_one(uint64_t config)
{
    int type = sf_msr_pmu_type();
    struct perf_event_attr a;
    if (type < 0) {
        return -1;
    }
    memset(&a, 0, sizeof(a));
    a.type = (uint32_t)type;
    a.size = sizeof(a);
    a.config = config;
    return sf_perf_event_open(&a, 0 /* calling thread */, -1, -1, 0);
}

SfHwGroup *sf_hw_open(bool guest_only)
{
    static const struct { uint32_t type; uint64_t config; } evs[SF_HW_N] = {
        { PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS },
        { PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES },
        { PERF_TYPE_RAW,      SF_EV_DRAM_FILL },
    };
    SfHwGroup *g = g_new(SfHwGroup, 1);
    int i, ok = 0;

    for (i = 0; i < SF_HW_N; i++) {
        g->fd[i] = sf_hw_open_one(evs[i].type, evs[i].config, guest_only);
        ok += (g->fd[i] >= 0);
    }
    /* aperf/mperf only on the guest group (vCPU thread, spans the guest run). */
    g->aperf_fd = guest_only ? sf_msr_open_one(0x01) : -1;
    g->mperf_fd = guest_only ? sf_msr_open_one(0x02) : -1;
    if (!ok) {   /* nothing opened (denied?) → caller zeros */
        g_free(g);
        return NULL;
    }
    return g;
}

/* Host-side miss-HIERARCHY group (exclude_guest): AMD Zen3 "any data-cache fills
 * by source" — where each restore-memcpy L2-miss was satisfied. fd order:
 * [0] mem_io_local (DRAM, 0x844), [1] int_cache (same-CCX, 0x244),
 * [2] ext_cache_local (cross-CCX, 0x444). Read into dram_fill/l3_fill/ccx_fill. */
SfHwGroup *sf_hw_open_hier(void)
{
    /* Default = miss hierarchy {mem_io_local, int_cache, ext_cache}. A3: with
     * SF_STALL_PMC set, swap to Zen3 backend-stall on the restore memcpy window
     * {host cycles 0x076, store_queue_rsrc_stall 0x4ae, load_queue_rsrc_stall
     * 0x2ae} — reuses the dram_fill/l3_fill/ccx_fill fields (relabel offline).
     * Per-window (t2..t3) isolation the system-wide perf proxy couldn't give. */
    static const uint64_t cfg_fill[SF_HW_N]  = { 0x844, 0x244, 0x444 };
    static const uint64_t cfg_stall[SF_HW_N] = { 0x076, 0x4ae, 0x2ae };
    const uint64_t *cfg = getenv("SF_STALL_PMC") ? cfg_stall : cfg_fill;
    SfHwGroup *g = g_new(SfHwGroup, 1);
    int i, ok = 0;
    g->aperf_fd = g->mperf_fd = -1;   /* host group: no aperf/mperf */
    for (i = 0; i < SF_HW_N; i++) {
        struct perf_event_attr a;
        memset(&a, 0, sizeof(a));
        a.type = PERF_TYPE_RAW;
        a.size = sizeof(a);
        a.config = cfg[i];
        a.exclude_guest = 1;   /* host-mode only = the memcpy, not guest exec */
        g->fd[i] = sf_perf_event_open(&a, 0, -1, -1, 0);
        ok += (g->fd[i] >= 0);
    }
    if (!ok) {
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
    out->insns     = sf_hw_read_one(g->fd[0]);
    out->cycles    = sf_hw_read_one(g->fd[1]);
    out->dram_fill = sf_hw_read_one(g->fd[2]);
    out->aperf     = sf_hw_read_one(g->aperf_fd);
    out->mperf     = sf_hw_read_one(g->mperf_fd);
}

void sf_hw_read_hier(SfHwGroup *g, SfHwCounts *out)
{
    memset(out, 0, sizeof(*out));
    if (!g) {
        return;
    }
    out->dram_fill = sf_hw_read_one(g->fd[0]);   /* mem_io_local */
    out->l3_fill   = sf_hw_read_one(g->fd[1]);   /* int_cache (same-CCX) */
    out->ccx_fill  = sf_hw_read_one(g->fd[2]);   /* ext_cache (cross-CCX) */
}
