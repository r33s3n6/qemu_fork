/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 * RAM dirty-page engine. See engine.h + ARCHITECTURE.md §4/§5.
 *
 * Model (design §C):
 *   snapshot()  shadow every RAMBlock + start dirty logging clean.
 *   collect()   drain KVM dirty ring into per-slot bitmaps, union the dirtied
 *               guest pages into a to-restore set. Reading the accumulated
 *               bitmap (not the live ring) is what makes ring-full first-class
 *               and zero-loss — pages already reaped by the background reaper
 *               or a KVM_EXIT_DIRTY_RING_FULL exit are still seen.
 *   restore()   copy the shadow back for the to-restore set ∪ all HOT pages.
 *   reset()     clear per-slot bitmaps for the next round.
 *
 * Clean-room: no QEMU-Nyx code. Nyx read only as design reference.
 */
#include "qemu/osdep.h"
#include "qemu/rcu.h"
#include "qapi/error.h"
#include "exec/cpu-common.h"
#include "system/ramblock.h"
#include "system/ramlist.h"
#include "system/memory.h"
#include "system/kvm.h"
#include "qemu/bitmap.h"
#include "sf/dirty/engine.h"

/* One shadow copy per RAMBlock (host-contiguous). */
typedef struct SfRamShadow {
    void    *host;   /* live RAMBlock host base */
    uint64_t len;    /* used_length at snapshot time */
    uint8_t *shadow; /* our copy of [host, host+len) */
    bool     owned;  /* true when dirty/engine allocated shadow */
} SfRamShadow;

static SfRamShadow *g_shadows;
static size_t       g_n_shadows;
static bool         g_have_snapshot;
static bool         g_log_started;

/* Single restore vector, partitioned as [HOT prefix | dirty-only suffix].
 * Bitmap membership makes ring-full duplicate harvests cheap without a hash
 * table; the vector is the only iterable state. */
static void **g_restore;
static size_t g_restore_n;
static size_t g_restore_cap;
static size_t g_hot_n;
static unsigned long *g_in_restore_bmap;
static unsigned long *g_hot_bmap;

static inline size_t sf_page_size(void)
{
    return qemu_real_host_page_size();
}

static SfResetPolicy sf_reset_policy(void)
{
    const char *s = getenv("SF_BLIND");

    return (s && *s) ? SF_RESET_ALL_HOT : SF_RESET_FULL;
}

static long sf_shadow_npages(const SfRamShadow *s)
{
    return DIV_ROUND_UP(s->len, sf_page_size());
}

static bool sf_dirty_page_index(void *host, long *idxp)
{
    long base = 0;

    for (size_t i = 0; i < g_n_shadows; i++) {
        SfRamShadow *s = &g_shadows[i];
        if (host >= s->host && (uint8_t *)host < (uint8_t *)s->host + s->len) {
            uint64_t off = (uint8_t *)host - (uint8_t *)s->host;
            *idxp = base + off / sf_page_size();
            return true;
        }
        base += sf_shadow_npages(s);
    }
    return false;
}

static void sf_restore_reserve(size_t need)
{
    if (need <= g_restore_cap) {
        return;
    }
    while (g_restore_cap < need) {
        g_restore_cap = g_restore_cap ? g_restore_cap * 2 : 4096;
    }
    g_restore = g_renew(void *, g_restore, g_restore_cap);
}

static bool sf_restore_contains(void *host, size_t start, size_t end)
{
    for (size_t i = start; i < end; i++) {
        if (g_restore[i] == host) {
            return true;
        }
    }
    return false;
}

static void sf_restore_append_dirty(void *host)
{
    long idx;

    if (g_in_restore_bmap && sf_dirty_page_index(host, &idx)) {
        if (test_and_set_bit(idx, g_in_restore_bmap)) {
            return;
        }
    } else if (sf_restore_contains(host, 0, g_restore_n)) {
        return;
    }

    sf_restore_reserve(g_restore_n + 1);
    g_restore[g_restore_n++] = host;
}

static void sf_restore_append_hot(void *host)
{
    long idx;
    bool was_in_restore = false;

    if (g_hot_bmap && sf_dirty_page_index(host, &idx)) {
        if (test_and_set_bit(idx, g_hot_bmap)) {
            return;
        }
        was_in_restore = test_bit(idx, g_in_restore_bmap);
        set_bit(idx, g_in_restore_bmap);
    } else if (sf_restore_contains(host, 0, g_hot_n)) {
        return;
    }

    if (was_in_restore || sf_restore_contains(host, g_hot_n, g_restore_n)) {
        for (size_t i = g_hot_n; i < g_restore_n; i++) {
            if (g_restore[i] == host) {
                void *tmp = g_restore[g_hot_n];
                g_restore[g_hot_n] = host;
                g_restore[i] = tmp;
                g_hot_n++;
                return;
            }
        }
    }

    sf_restore_reserve(g_restore_n + 1);
    g_restore[g_restore_n++] = host;
    if (g_hot_n != g_restore_n - 1) {
        void *tmp = g_restore[g_hot_n];
        g_restore[g_hot_n] = host;
        g_restore[g_restore_n - 1] = tmp;
    }
    g_hot_n++;
}

static void sf_dirty_clear_collected_suffix(void)
{
    for (size_t i = g_hot_n; i < g_restore_n; i++) {
        long idx;
        if (g_in_restore_bmap && sf_dirty_page_index(g_restore[i], &idx)) {
            clear_bit(idx, g_in_restore_bmap);
        }
    }
    g_restore_n = g_hot_n;
}

static void sf_dirty_rebuild_bitmaps(void)
{
    long nbits = 0;
    size_t out = 0;

    g_free(g_in_restore_bmap);
    g_free(g_hot_bmap);
    g_in_restore_bmap = NULL;
    g_hot_bmap = NULL;

    for (size_t i = 0; i < g_n_shadows; i++) {
        nbits += sf_shadow_npages(&g_shadows[i]);
    }
    if (!nbits) {
        g_restore_n = g_hot_n = 0;
        return;
    }

    g_in_restore_bmap = bitmap_new(nbits);
    g_hot_bmap = bitmap_new(nbits);

    for (size_t i = 0; i < g_hot_n; i++) {
        long idx;
        void *host = g_restore[i];

        if (!sf_dirty_page_index(host, &idx) ||
            test_and_set_bit(idx, g_hot_bmap)) {
            continue;
        }
        set_bit(idx, g_in_restore_bmap);
        g_restore[out++] = host;
    }
    g_hot_n = out;
    g_restore_n = out;
}

/* Locate the shadow that owns host page @p; return its shadow ptr + bytes
 * remaining from @p to the block end, or NULL. Exposed (sf_dirty_shadow_for)
 * for the snap layer's root owner-resolution; the shadow stays engine-owned. */
uint8_t *sf_dirty_shadow_for(void *p, uint64_t *remain)
{
    for (size_t i = 0; i < g_n_shadows; i++) {
        SfRamShadow *s = &g_shadows[i];
        if (p >= s->host && (uint8_t *)p < (uint8_t *)s->host + s->len) {
            uint64_t off = (uint8_t *)p - (uint8_t *)s->host;
            *remain = s->len - off;
            return s->shadow + off;
        }
    }
    return NULL;
}

static void sf_dirty_drop_snapshot(bool keep_hot)
{
    for (size_t i = 0; i < g_n_shadows; i++) {
        if (g_shadows[i].owned) {
            g_free(g_shadows[i].shadow);
        }
    }
    g_free(g_shadows);
    g_shadows = NULL;
    g_n_shadows = 0;
    g_free(g_in_restore_bmap);
    g_free(g_hot_bmap);
    g_in_restore_bmap = NULL;
    g_hot_bmap = NULL;
    sf_dirty_clear_collected_suffix();
    if (!keep_hot) {
        g_free(g_restore);
        g_restore = NULL;
        g_restore_n = g_restore_cap = g_hot_n = 0;
    }
    g_have_snapshot = false;
}

void sf_dirty_destroy(void)
{
    sf_dirty_drop_snapshot(true);
}

static int sf_dirty_start_tracking(Error **errp)
{
    if (!sf_kvm_dirty_ring_enabled()) {
        error_setg(errp, "KVM dirty ring not enabled "
                   "(need -accel kvm,dirty-ring-size=N)");
        return -ENOTSUP;
    }

    if (!g_log_started) {
        if (!memory_global_dirty_log_start(GLOBAL_DIRTY_MIGRATION, errp)) {
            return -EIO;
        }
        g_log_started = true;
    }
    sf_kvm_dirty_ring_set_owned(true);
    return 0;
}

static void sf_dirty_clean_slate(void)
{
    g_have_snapshot = true;

    /* Start tracking from a clean slate: re-protect pages dirtied before this
     * snapshot and align sf's private ring cursors after that baseline. */
    sf_kvm_dirty_clean_slate();
}

bool sf_dirty_have_snapshot(void)
{
    return g_have_snapshot;
}

void *const *sf_dirty_collected(size_t *n)
{
    *n = g_restore_n - g_hot_n;
    return (void *const *)(g_restore + g_hot_n);
}

void sf_dirty_iter_hot(void (*cb)(void *host_page, void *user), void *user)
{
    if (!cb) {
        return;
    }
    for (size_t i = 0; i < g_hot_n; i++) {
        cb(g_restore[i], user);
    }
}

void sf_dirty_clear_collected(void)
{
    sf_dirty_clear_collected_suffix();
}

int sf_dirty_snapshot(Error **errp)
{
    RAMBlock *block;
    size_t cap = 0, n = 0;
    SfRamShadow *shadows = NULL;

    int ret = sf_dirty_start_tracking(errp);
    if (ret < 0) {
        return ret;
    }

    /* Drop any previous snapshot, preserving the HOT prefix across roots. */
    sf_dirty_drop_snapshot(true);

    WITH_RCU_READ_LOCK_GUARD() {
        RAMBLOCK_FOREACH(block) {
            uint64_t len = block->used_length;
            if (!block->host || !len) {
                continue;
            }
            if (n == cap) {
                cap = cap ? cap * 2 : 8;
                shadows = g_renew(SfRamShadow, shadows, cap);
            }
            shadows[n].host = block->host;
            shadows[n].len = len;
            shadows[n].shadow = g_malloc(len);
            shadows[n].owned = true;
            memcpy(shadows[n].shadow, block->host, len);
            n++;
        }
    }

    g_shadows = shadows;
    g_n_shadows = n;
    sf_dirty_rebuild_bitmaps();
    sf_dirty_clean_slate();
    return 0;
}

int sf_dirty_use_external_shadows(const SfDirtyShadowDesc *descs, size_t n_descs,
                                  Error **errp)
{
    SfRamShadow *shadows;

    int ret = sf_dirty_start_tracking(errp);
    if (ret < 0) {
        return ret;
    }
    if (!descs || n_descs == 0) {
        error_setg(errp, "sf_dirty_use_external_shadows: no root backing slices");
        return -EINVAL;
    }

    sf_dirty_drop_snapshot(true);
    shadows = g_new0(SfRamShadow, n_descs);
    for (size_t i = 0; i < n_descs; i++) {
        if (!descs[i].host || !descs[i].len || !descs[i].shadow) {
            g_free(shadows);
            error_setg(errp, "sf_dirty_use_external_shadows: bad slice %zu", i);
            return -EINVAL;
        }
        shadows[i].host = descs[i].host;
        shadows[i].len = descs[i].len;
        shadows[i].shadow = descs[i].shadow;
        shadows[i].owned = false;
    }
    g_shadows = shadows;
    g_n_shadows = n_descs;
    sf_dirty_rebuild_bitmaps();
    sf_dirty_clean_slate();
    return 0;
}

/* Fault injection (selftest only): a page collect() must pretend it never saw. */
static void *g_inject_skip_page;

static void sf_dirty_drop_collected(void *host_page)
{
    size_t out = 0;
    long idx;

    for (size_t i = g_hot_n; i < g_restore_n; i++) {
        if (g_restore[i] != host_page) {
            g_restore[g_hot_n + out++] = g_restore[i];
        }
    }
    g_restore_n = g_hot_n + out;
    if (g_in_restore_bmap && sf_dirty_page_index(host_page, &idx) &&
        !test_bit(idx, g_hot_bmap)) {
        clear_bit(idx, g_in_restore_bmap);
    }
}

void sf_dirty_inject_collect_skip(void *host_page)
{
    g_inject_skip_page = host_page;
    if (host_page) {
        sf_dirty_drop_collected(host_page);
    }
}

static void sf_collect_cb(void *host, size_t page_size, void *user)
{
    (void)page_size;
    (void)user;
    if (host == g_inject_skip_page) {
        return; /* injected loss: this dirty page is dropped on the floor */
    }
    if (sf_reset_policy() == SF_RESET_ALL_HOT) {
        sf_dirty_mark_hot((uint64_t)(uintptr_t)host);
    } else {
        sf_restore_append_dirty(host);
    }
}

void sf_dirty_note_page(void *host_page, size_t page_size, void *user)
{
    sf_collect_cb(host_page, page_size, user);
}

uint64_t sf_dirty_collect(void)
{
    if (!g_have_snapshot) {
        return 0;
    }
    return sf_kvm_collect_dirty(sf_collect_cb, NULL);
}

static inline uint32_t sf_restore_one(void *page, size_t psize)
{
    uint64_t remain = 0;
    uint8_t *src = sf_dirty_shadow_for(page, &remain);
    if (!src) {
        return 0; /* page outside any shadowed block */
    }
    memcpy(page, src, MIN(psize, remain));
    return 1;
}

uint32_t sf_dirty_restore(void)
{
    size_t psize = sf_page_size();
    uint32_t copied = 0;

    if (!g_have_snapshot) {
        return 0;
    }

    for (size_t i = 0; i < g_restore_n; i++) {
        copied += sf_restore_one(g_restore[i], psize);
    }

    sf_dirty_clear_collected(); /* clear for next generation, keep capacity */
    return copied;
}

void sf_dirty_reset_ring(void)
{
    if (sf_reset_policy() == SF_RESET_ALL_HOT) {
        return;
    }
    sf_dirty_force_reset_ring();
}

void sf_dirty_force_reset_ring(void)
{
    sf_kvm_dirty_reset_all();
}

SfPagePolicy sf_reprotect_policy(uint64_t page_addr)
{
    return sf_dirty_is_hot((void *)(uintptr_t)page_addr) ? SF_PAGE_HOT :
                                                           SF_PAGE_COLD;
}

void sf_dirty_mark_hot(uint64_t page_addr)
{
    sf_restore_append_hot((void *)(uintptr_t)page_addr);
}

bool sf_dirty_is_hot(void *host_page)
{
    long idx;

    if (g_hot_bmap && sf_dirty_page_index(host_page, &idx)) {
        return test_bit(idx, g_hot_bmap);
    }
    return sf_restore_contains(host_page, 0, g_hot_n);
}
