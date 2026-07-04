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
} SfRamShadow;

static SfRamShadow *g_shadows;
static size_t       g_n_shadows;
static bool         g_have_snapshot;
static bool         g_log_started;

/* Sets keyed by host page address (aligned). Values unused. */
static GHashTable  *g_hot;         /* pages with HOT policy */
static GHashTable  *g_to_restore;  /* pages dirtied this round */

static inline size_t sf_page_size(void)
{
    return qemu_real_host_page_size();
}

static GHashTable *sf_set(void)
{
    return g_hash_table_new(g_direct_hash, g_direct_equal);
}

/* Locate the shadow that owns host page @p; return its shadow ptr + bytes
 * remaining from @p to the block end, or NULL. */
static uint8_t *sf_shadow_for(void *p, uint64_t *remain)
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
        g_free(g_shadows[i].shadow);
    }
    g_free(g_shadows);
    g_shadows = NULL;
    g_n_shadows = 0;
    if (g_to_restore) {
        g_hash_table_destroy(g_to_restore);
        g_to_restore = NULL;
    }
    /* g_hot (policy) intentionally persists across snapshots. */
    g_have_snapshot = false;
}

bool sf_dirty_have_snapshot(void)
{
    return g_have_snapshot;
}

int sf_dirty_snapshot(Error **errp)
{
    RAMBlock *block;
    size_t cap = 0, n = 0;
    SfRamShadow *shadows = NULL;

    if (!sf_kvm_dirty_ring_enabled()) {
        error_setg(errp, "KVM dirty ring not enabled "
                   "(need -accel kvm,dirty-ring-size=N)");
        return -ENOTSUP;
    }

    /* Enable global dirty logging once; keeps every RAM slot tracked. */
    if (!g_log_started) {
        if (!memory_global_dirty_log_start(GLOBAL_DIRTY_MIGRATION, errp)) {
            return -EIO;
        }
        g_log_started = true;
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
            memcpy(shadows[n].shadow, block->host, len);
            n++;
        }
    }

    g_shadows = shadows;
    g_n_shadows = n;
    g_to_restore = sf_set();
    if (!g_hot) {
        g_hot = sf_set();
    }
    g_have_snapshot = true;

    /*
     * Start tracking from a clean slate: drain whatever is pending (this also
     * reprotects those pages via KVM_RESET_DIRTY_RINGS) and clear the bitmaps
     * so the next collect() only sees writes made after this snapshot.
     */
    sf_kvm_collect_dirty(NULL, NULL);
    sf_kvm_dirty_reset_all();

    return 0;
}

static void sf_collect_cb(void *host, size_t page_size, void *user)
{
    GHashTable *set = user;
    g_hash_table_add(set, host);
}

uint64_t sf_dirty_collect(void)
{
    if (!g_have_snapshot) {
        return 0;
    }
    return sf_kvm_collect_dirty(sf_collect_cb, g_to_restore);
}

uint32_t sf_dirty_restore(void)
{
    size_t psize = sf_page_size();
    GHashTableIter it;
    gpointer key;
    uint32_t copied = 0;

    if (!g_have_snapshot) {
        return 0;
    }

    /* HOT pages are restored unconditionally: fold them into the set. */
    if (g_hot) {
        g_hash_table_iter_init(&it, g_hot);
        while (g_hash_table_iter_next(&it, &key, NULL)) {
            g_hash_table_add(g_to_restore, key);
        }
    }

    g_hash_table_iter_init(&it, g_to_restore);
    while (g_hash_table_iter_next(&it, &key, NULL)) {
        uint64_t remain = 0;
        uint8_t *src = sf_shadow_for(key, &remain);
        if (!src) {
            continue; /* page outside any shadowed block */
        }
        memcpy(key, src, MIN(psize, remain));
        copied++;
    }

    g_hash_table_remove_all(g_to_restore);
    return copied;
}

void sf_dirty_reset_ring(void)
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
