/*
 * sf/perf/hwcounters.h — per-round hardware counters for restore-cost attribution.
 *
 * Two perf_event groups on the vCPU thread, split by domain so the two phases
 * that share the thread don't pollute each other:
 *   - guest group (exclude_host):  {insns, cycles, DRAM-fill}, read across the
 *     guest-run interval (last restore → this restore). IPC = insns/cycles,
 *     guest DRAM bandwidth = dram_fill×64/wall. Plus {aperf, mperf} (msr PMU,
 *     no-exclude → total on-cpu cycles): machinery time in the window is
 *     guest_active_cpu×(aperf−cycles)/aperf (frequency-free, aperf≥cycles); the
 *     aperf/mperf ratio also gives true eff-freq without the cycles/wall confound.
 *   - host group (exclude_guest):  {DRAM, same-CCX-L3, cross-CCX} MISS HIERARCHY,
 *     read t2→t3 isolates the restore memcpy (sf_restore_apply_ram). Total L2-miss
 *     = dram+l3+ccx; the split tells a full miss (DRAM, costs bandwidth) from a
 *     cheap on-die hit, and surfaces cross-CCX traffic as workers span more CCXs.
 *
 * 3 + 3 = 6 core PMCs (AMD Zen3), no multiplex. Counters are independent (one
 * unsupported event doesn't zero the rest). Effective frequency catches multi-core
 * turbo drop, the confound CPU-time alone can't separate from memory stall.
 * (ref-cycles dropped: PERF_COUNT_HW_REF_CPU_CYCLES is Intel-only; cycles/wall
 * gives freq on AMD too.)
 *
 * dram_fill = AMD ls_any_fills_from_sys.mem_io_local (data-cache fills from local
 * DRAM, incl. prefetch) — the TRUE per-phase DRAM read traffic (×64B = bytes). It
 * replaces the old generic CACHE_MISSES, which counted L2 misses that HIT L3 as
 * "misses" too (cheap, not DRAM) and made a shared-base restore look bandwidth-heavy
 * when it was actually L3-warm. The host group splits its DRAM further (see above).
 *
 * Whole thing is gated by the caller on SF_TIME. If perf_event_open is denied
 * (perf_event_paranoid), open returns NULL and reads yield zeros — the sf-time
 * line still emits, just with zeroed hw fields.
 */
#ifndef SF_PERF_HWCOUNTERS_H
#define SF_PERF_HWCOUNTERS_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint64_t insns;
    uint64_t cycles;
    uint64_t dram_fill;   /* DRAM read fills (ls_any_fills_from_sys.mem_io_local) */
    uint64_t l3_fill;     /* same-CCX cache fills (int_cache): L2-miss, on-die hit */
    uint64_t ccx_fill;    /* cross-CCX cache fills (ext_cache): another CCX's cache */
    uint64_t aperf;       /* actual core cycles over on-cpu window (msr PMU, guest grp only) */
    uint64_t mperf;       /* reference cycles (mperf ticks at host base rate) */
} SfHwCounts;

typedef struct SfHwGroup SfHwGroup;

/* Open+enable the {insns, cycles, dram_fill} group on the calling thread.
 * @guest_only picks the domain (true = exclude_host, false = exclude_guest).
 * NULL on failure. Read with sf_hw_read. */
SfHwGroup *sf_hw_open(bool guest_only);

/* Open the host-side miss-HIERARCHY group {DRAM, same-CCX-L3, cross-CCX} — the
 * restore memcpy's data-cache fills split by where each L2-miss was satisfied
 * (total L2-miss = dram+l3+ccx). Lets a full miss (DRAM) be told from a cheap
 * on-die hit, so a shared L3-warm base isn't misread as bandwidth-heavy, and
 * cross-CCX traffic shows up as worker count spans more CCXs. Read with
 * sf_hw_read_hier. */
SfHwGroup *sf_hw_open_hier(void);

/* Read the {insns,cycles,dram_fill} group (l3/ccx left 0). Zeros @out if NULL. */
void sf_hw_read(SfHwGroup *g, SfHwCounts *out);
/* Read the hierarchy group into {dram_fill,l3_fill,ccx_fill} (insns/cycles 0). */
void sf_hw_read_hier(SfHwGroup *g, SfHwCounts *out);

/* out = a - b, field-wise. */
static inline void sf_hw_delta(SfHwCounts *out,
                               const SfHwCounts *a, const SfHwCounts *b)
{
    out->insns     = a->insns     - b->insns;
    out->cycles    = a->cycles    - b->cycles;
    out->dram_fill = a->dram_fill - b->dram_fill;
    out->l3_fill   = a->l3_fill   - b->l3_fill;
    out->ccx_fill  = a->ccx_fill  - b->ccx_fill;
    out->aperf     = a->aperf     - b->aperf;
    out->mperf     = a->mperf     - b->mperf;
}

#endif /* SF_PERF_HWCOUNTERS_H */
