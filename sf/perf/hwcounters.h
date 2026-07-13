/*
 * sf/perf/hwcounters.h — per-round hardware counters for restore-cost attribution.
 *
 * Two perf_event groups on the vCPU thread, split by domain so the two phases
 * that share the thread don't pollute each other:
 *   - guest group (exclude_host):  advances only in guest mode → read across the
 *     guest-run interval (last restore → this restore) isolates guest execution.
 *   - host group (exclude_guest):  advances only in host mode → read t2→t3 isolates
 *     the restore memcpy (sf_restore_apply_ram).
 *
 * Each group carries {instructions, cpu-cycles, LLC-read-miss}, opened as
 * independent counters (one unsupported event doesn't zero the rest). Effective
 * frequency = cpu_cycles ÷ wall (downstream) → catches multi-core turbo drop, the
 * confound CPU-time alone can't separate from memory stall. (ref-cycles is dropped:
 * PERF_COUNT_HW_REF_CPU_CYCLES is Intel-only; cycles/wall gives freq on AMD too.)
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
    uint64_t llc_miss;
} SfHwCounts;

typedef struct SfHwGroup SfHwGroup;

/* Open+enable a counter group on the calling thread. @guest_only picks the
 * domain (true = exclude_host, false = exclude_guest). NULL on failure. */
SfHwGroup *sf_hw_open(bool guest_only);

/* Investigation-only (SF_HW_FILLSRC): host-side AMD data-cache-fill-by-source
 * group. Slots: insns←mem_io_local, cycles←ext_cache_local, llc_miss←int_cache. */
SfHwGroup *sf_hw_open_fillsrc(void);

/* Read the group's running totals. Zeros @out if @g is NULL. */
void sf_hw_read(SfHwGroup *g, SfHwCounts *out);

/* out = a - b, field-wise. */
static inline void sf_hw_delta(SfHwCounts *out,
                               const SfHwCounts *a, const SfHwCounts *b)
{
    out->insns    = a->insns    - b->insns;
    out->cycles   = a->cycles   - b->cycles;
    out->llc_miss = a->llc_miss - b->llc_miss;
}

#endif /* SF_PERF_HWCOUNTERS_H */
