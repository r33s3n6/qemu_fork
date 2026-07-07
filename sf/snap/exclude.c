/*
 * sf/snap/exclude — NO_RESTORE exclusion region table. See exclude.h.
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "sf/snap/exclude.h"

typedef struct SfExclRange {
    uint64_t host_start;
    uint64_t host_end;   /* exclusive */
    uint32_t buf_id;
} SfExclRange;

static SfExclRange *g_excl;
static size_t       g_excl_n;
static size_t       g_excl_cap;

void sf_exclude_clear(void)
{
    g_free(g_excl);
    g_excl = NULL;
    g_excl_n = 0;
    g_excl_cap = 0;
}

size_t sf_exclude_count(void)
{
    return g_excl_n;
}

void sf_exclude_add(uint64_t host_start, uint64_t size, uint32_t buf_id)
{
    size_t psize = qemu_real_host_page_size();

    /* Page-aligned registration (plan -06 §1: 页粒度断言). */
    if (host_start & (psize - 1)) {
        error_report("sf_exclude_add: host_start %lx not page-aligned", host_start);
        return;
    }
    if (size & (psize - 1)) {
        error_report("sf_exclude_add: size %lx not page-aligned", size);
        return;
    }
    if (size == 0) {
        return;
    }

    if (g_excl_n == g_excl_cap) {
        g_excl_cap = g_excl_cap ? g_excl_cap * 2 : 8;
        g_excl = g_renew(SfExclRange, g_excl, g_excl_cap);
    }
    g_excl[g_excl_n].host_start = host_start;
    g_excl[g_excl_n].host_end = host_start + size;
    g_excl[g_excl_n].buf_id = buf_id;
    g_excl_n++;

    /* Keep sorted by host_start so sf_excluded is a binary search. */
    for (size_t i = g_excl_n - 1; i > 0; i--) {
        if (g_excl[i - 1].host_start > g_excl[i].host_start) {
            SfExclRange tmp = g_excl[i - 1];
            g_excl[i - 1] = g_excl[i];
            g_excl[i] = tmp;
        } else {
            break;
        }
    }
}

static int sf_excl_find(uint64_t host)
{
    /* Lower-bound binary search; then check the candidate range. */
    size_t lo = 0, hi = g_excl_n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (host < g_excl[mid].host_start) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    /* lo points just past the candidate; the candidate is lo-1. */
    if (lo == 0) {
        return -1;
    }
    size_t i = lo - 1;
    if (host >= g_excl[i].host_start && host < g_excl[i].host_end) {
        return (int)i;
    }
    return -1;
}

bool sf_excluded(const void *host)
{
    if (g_excl_n == 0) {
        return false;
    }
    return sf_excl_find((uint64_t)(uintptr_t)host) >= 0;
}