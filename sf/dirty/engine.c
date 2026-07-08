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

/* HOT policy set: keyed by host page address, queried for membership → hash set. */
static GHashTable  *g_hot;

/* Pages dirtied this generation → a flat, append-only vector of host page
 * addresses. The KVM dirty ring logs each page at most once per generation (a
 * page enters the ring on its clean->dirty write fault, then stays writable
 * until the next reset), so there are no intra-generation duplicates to dedup.
 * Only add/iterate/clear are ever needed (never membership) → a plain vector
 * beats both a hash set (was ~150ns/page of hashing, ~500us/3000 pages) and a
 * bitmap+stack (no bitmap memory, no per-append bit test). A duplicate (a HOT
 * page also dirtied) at worst costs one redundant, harmless memcpy. */
static void   **g_dirty;      /* host page addresses, this generation */
static size_t   g_dirty_n;    /* count */
static size_t   g_dirty_cap;  /* capacity (kept across generations) */
static GHashTable *g_dirty_set; /* membership for ring-full duplicate harvests */

static inline size_t sf_page_size(void)
{
    return qemu_real_host_page_size();
}

static GHashTable *sf_set(void)
{
    return g_hash_table_new(g_direct_hash, g_direct_equal);
}

static SfResetPolicy sf_reset_policy(void)
{
    const char *s = getenv("SF_BLIND");

    return (s && *s) ? SF_RESET_ALL_HOT : SF_RESET_FULL;
}

static inline void sf_dirty_push(void *host)
{
    if (!g_dirty_set) {
        g_dirty_set = sf_set();
    }
    if (g_hash_table_contains(g_dirty_set, host)) {
        return;
    }
    g_hash_table_add(g_dirty_set, host);
    if (g_dirty_n == g_dirty_cap) {
        g_dirty_cap = g_dirty_cap ? g_dirty_cap * 2 : 4096;
        g_dirty = g_renew(void *, g_dirty, g_dirty_cap);
    }
    g_dirty[g_dirty_n++] = host;
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

void sf_dirty_destroy(void)
{
    for (size_t i = 0; i < g_n_shadows; i++) {
        if (g_shadows[i].owned) {
            g_free(g_shadows[i].shadow);
        }
    }
    g_free(g_shadows);
    g_shadows = NULL;
    g_n_shadows = 0;
    g_free(g_dirty);
    g_dirty = NULL;
    g_dirty_n = g_dirty_cap = 0;
    g_clear_pointer(&g_dirty_set, g_hash_table_destroy);
    /* g_hot (policy) intentionally persists across snapshots. */
    g_have_snapshot = false;
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
    if (!g_hot) {
        g_hot = sf_set();
    }
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
    *n = g_dirty_n;
    return g_dirty;
}

void sf_dirty_iter_hot(void (*cb)(void *host_page, void *user), void *user)
{
    if (!g_hot || !cb) {
        return;
    }
    GHashTableIter it;
    gpointer key;
    g_hash_table_iter_init(&it, g_hot);
    while (g_hash_table_iter_next(&it, &key, NULL)) {
        cb(key, user);
    }
}

void sf_dirty_clear_collected(void)
{
    g_dirty_n = 0;
    if (g_dirty_set) {
        g_hash_table_remove_all(g_dirty_set);
    }
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

    /* Drop any previous snapshot (keep HOT policy set). */
    sf_dirty_destroy();

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

    sf_dirty_destroy();
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
    sf_dirty_clean_slate();
    return 0;
}

/* Fault injection (selftest only): a page collect() must pretend it never saw. */
static void *g_inject_skip_page;

static void sf_dirty_drop_collected(void *host_page)
{
    size_t out = 0;

    for (size_t i = 0; i < g_dirty_n; i++) {
        if (g_dirty[i] != host_page) {
            g_dirty[out++] = g_dirty[i];
        }
    }
    g_dirty_n = out;
    if (g_dirty_set) {
        g_hash_table_remove(g_dirty_set, host_page);
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
    }
    sf_dirty_push(host);
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

    /* Pages dirtied this generation (flat vector, O(dirty), no hashing). */
    for (size_t i = 0; i < g_dirty_n; i++) {
        copied += sf_restore_one(g_dirty[i], psize);
    }

    /* HOT pages: restored unconditionally. May overlap the dirtied set (HOT is
     * opt-in and small) → a redundant but correct recopy, not deduped. */
    if (g_hot) {
        GHashTableIter it;
        gpointer key;
        g_hash_table_iter_init(&it, g_hot);
        while (g_hash_table_iter_next(&it, &key, NULL)) {
            copied += sf_restore_one(key, psize);
        }
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
    if (g_hot && g_hash_table_contains(g_hot, (gpointer)(uintptr_t)page_addr)) {
        return SF_PAGE_HOT;
    }
    return SF_PAGE_COLD;
}

void sf_dirty_mark_hot(uint64_t page_addr)
{
    if (!g_hot) {
        g_hot = sf_set();
    }
    g_hash_table_add(g_hot, (gpointer)(uintptr_t)page_addr);
}

bool sf_dirty_is_hot(void *host_page)
{
    return g_hot && g_hash_table_contains(g_hot, host_page);
}
