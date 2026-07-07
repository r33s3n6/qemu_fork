/*
 * sf/snap/node — multi-level snapshot tree: node lifecycle, block registry,
 * page-key<->host, ramstore, owner resolution. Impl truth:
 *   research/plans/2026-07-06-04-m3-core-engine-impl.md (§1 数据结构, §3 resolve).
 *
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/queue.h"
#include "exec/cpu-common.h"
#include "system/ramblock.h"
#include "system/ramlist.h"
#include "sf/dirty/engine.h"
#include "sf/snap/node.h"
#include "sf/snap/tripwire.h"   /* disarm on root teardown */

SfSnapNode  *sf_active;
SfBlockDesc *sf_blocks;
size_t       sf_n_blocks;

static uint32_t g_next_id;

/* selftest fault injection: sf_resolve skips the node with this id (0xFFFFFFFF
 * = none). Test-only — production never sets it. */
static uint32_t g_inject_skip_node = 0xFFFFFFFFU;

void sf_resolve_inject_skip_node(uint32_t node_id)
{
    g_inject_skip_node = node_id;
}

/* ---- Node tree ---- */

SfSnapNode *sf_node_new(SfSnapNode *parent, SfSnapKind kind)
{
    SfSnapNode *n = g_new0(SfSnapNode, 1);
    n->id = g_next_id++;
    n->parent = parent;
    n->depth = parent ? parent->depth + 1 : 0;
    n->kind = kind;
    n->state = SF_SNAP_OPEN;
    QLIST_INIT(&n->children);
    n->ram.fd = -1;
    if (parent) {
        QLIST_INSERT_HEAD(&parent->children, n, sibling);
    }
    return n;
}

static void sf_node_destroy_rec(SfSnapNode *n)
{
    SfSnapNode *child, *tmp;

    /* post-order: free children first */
    QLIST_FOREACH_SAFE(child, &n->children, sibling, tmp) {
        sf_node_destroy_rec(child);
    }
    /* root (parent == NULL) is never on a sibling list, so QLIST_REMOVE would
     * deref its NULL le_prev; only unlink nodes that have a parent. */
    if (n->parent) {
        QLIST_REMOVE(n, sibling);
    }
    sf_ramstore_destroy(&n->ram);
    if (n->dev.have) {
        sf_replay_tables_destroy(&n->dev.tables);
        n->dev.have = false;
    }
    g_free(n);
}

void sf_node_destroy(SfSnapNode *n)
{
    if (!n) {
        return;
    }
    /* Tearing down the root (no parent) ends the snapshot tree → disarm the
     * tripwire (no snapshot RAM to protect anymore). */
    if (n->parent == NULL) {
        sf_tripwire_arm(false);
    }
    sf_node_destroy_rec(n);
}

static SfSnapNode *sf_tree_root(void)
{
    SfSnapNode *n = sf_active;
    if (!n) {
        return NULL;
    }
    while (n->parent) {
        n = n->parent;
    }
    return n;
}

static SfSnapNode *sf_node_find_rec(SfSnapNode *root, uint32_t id)
{
    SfSnapNode *child, *hit;

    if (root->id == id) {
        return root;
    }
    QLIST_FOREACH(child, &root->children, sibling) {
        hit = sf_node_find_rec(child, id);
        if (hit) {
            return hit;
        }
    }
    return NULL;
}

SfSnapNode *sf_node_find(uint32_t id)
{
    SfSnapNode *root = sf_tree_root();
    return root ? sf_node_find_rec(root, id) : NULL;
}

SfSnapNode *sf_node_lca(SfSnapNode *a, SfSnapNode *b)
{
    if (!a || !b) {
        return NULL;
    }
    /* align depths */
    while (a->depth > b->depth) { a = a->parent; }
    while (b->depth > a->depth) { b = b->parent; }
    while (a != b) { a = a->parent; b = b->parent; }
    return a;
}

/* ---- Block registry / key<->host ---- */

int sf_blocks_enumerate(Error **errp)
{
    RAMBlock *block;
    size_t cap = 0, n = 0;
    SfBlockDesc *descs = NULL;

    sf_blocks_destroy();

    WITH_RCU_READ_LOCK_GUARD() {
        RAMBLOCK_FOREACH(block) {
            if (!block->host || !block->used_length) {
                continue;
            }
            if (n == cap) {
                cap = cap ? cap * 2 : 8;
                descs = g_renew(SfBlockDesc, descs, cap);
            }
            descs[n].host = block->host;
            descs[n].len = block->used_length;
            g_strlcpy(descs[n].idstr, block->idstr ? block->idstr : "",
                      sizeof(descs[n].idstr));
            n++;
        }
    }

    if (n == 0) {
        error_setg(errp, "no RAMBlocks with a host mapping to snapshot");
        g_free(descs);
        return -EINVAL;
    }
    sf_blocks = descs;
    sf_n_blocks = n;
    return 0;
}

void sf_blocks_destroy(void)
{
    g_free(sf_blocks);
    sf_blocks = NULL;
    sf_n_blocks = 0;
}

bool sf_host_to_key_safe(void *host_page, SfPageKey *out)
{
    size_t psize = qemu_real_host_page_size();

    for (size_t i = 0; i < sf_n_blocks; i++) {
        SfBlockDesc *b = &sf_blocks[i];
        if (host_page >= b->host &&
            (uint8_t *)host_page < (uint8_t *)b->host + b->len) {
            uint64_t off = (uint8_t *)host_page - (uint8_t *)b->host;
            *out = SF_KEY((uint32_t)i, off / psize);
            return true;
        }
    }
    return false;
}

uint8_t *sf_key_to_host(SfPageKey key)
{
    size_t psize = qemu_real_host_page_size();
    uint32_t bid = SF_KEY_BLOCK(key);
    uint64_t pfn = SF_KEY_PFN(key);
    uint64_t off;

    if (bid >= sf_n_blocks) {
        return NULL;
    }
    off = pfn * psize;
    if (off >= sf_blocks[bid].len) {
        return NULL;
    }
    return (uint8_t *)sf_blocks[bid].host + off;
}

/* ---- Ramstore ---- */

int sf_ramstore_create_anon(SfRamStore *s, uint32_t n_pages)
{
    size_t psize = qemu_real_host_page_size();

    memset(s, 0, sizeof(*s));
    s->backing = SF_BACKING_ANON;
    s->fd = -1;
    s->n_pages = n_pages;
    if (n_pages == 0) {
        s->hdr = NULL;
        s->index = NULL;
        s->data = NULL;
        return 0;
    }
    s->hdr = g_new0(SfStoreHdr, 1);
    s->index = g_new(SfPageKey, n_pages);
    s->data = g_malloc((size_t)n_pages * psize);   /* g_* abort on OOM */
    return 0;
}

void sf_ramstore_destroy(SfRamStore *s)
{
    if (s->backing == SF_BACKING_FILE && s->data) {
        /* T6 will manage fd/unmap; for now anon-only build path. */
        munmap(s->data, (size_t)s->n_pages * qemu_real_host_page_size());
    } else {
        g_free(s->data);
    }
    g_free(s->index);
    g_free(s->hdr);
    if (s->fd >= 0) {
        close(s->fd);
    }
    memset(s, 0, sizeof(*s));
    s->fd = -1;
}

int sf_key_cmp(const void *a, const void *b)
{
    SfPageKey ka = *(const SfPageKey *)a, kb = *(const SfPageKey *)b;
    return (ka > kb) - (ka < kb);
}

int sf_ramstore_lookup(const SfRamStore *s, SfPageKey key)
{
    if (!s->index || s->n_pages == 0) {
        return -1;
    }
    SfPageKey *hit = bsearch(&key, s->index, s->n_pages, sizeof(SfPageKey),
                             sf_key_cmp);
    return hit ? (int)(hit - s->index) : -1;
}

/*
 * Owner resolution (design §3): walk dst up to root; at each node with an index,
 * bsearch for the key; first hit is the ≤dst nearest owner's data page. If none
 * along the chain owns it, fall through to the root shadow (engine-owned).
 */
uint8_t *sf_resolve(SfSnapNode *dst, SfPageKey key)
{
    size_t psize = qemu_real_host_page_size();

    for (SfSnapNode *n = dst; n; n = n->parent) {
        if (n->id == g_inject_skip_node) {
            continue;   /* test injection: pretend this layer doesn't own key */
        }
        int idx = sf_ramstore_lookup(&n->ram, key);
        if (idx >= 0 && n->ram.data) {
            return n->ram.data + (size_t)idx * psize;
        }
    }
    /* root兜底: root shadow lives in the dirty engine's per-block shadows. */
    uint8_t *host = sf_key_to_host(key);
    if (host) {
        uint64_t remain = 0;
        return sf_dirty_shadow_for(host, &remain);
    }
    return NULL;
}

bool sf_snap_have_snapshot(void)
{
    return sf_active != NULL;
}