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
#include "qemu/crc32c.h"
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
    if (s->backing == SF_BACKING_FILE) {
        /* hdr/index/data all point into one contiguous mmap; free it as a whole. */
        if (s->hdr && s->map_len) {
            munmap(s->hdr, s->map_len);
        }
        if (s->fd >= 0) {
            close(s->fd);
        }
    } else {
        g_free(s->data);
        g_free(s->index);
        g_free(s->hdr);
    }
    memset(s, 0, sizeof(*s));
    s->fd = -1;
}

/* Layout offsets (node.h): index 8-aligned after hdr, data page-aligned so a
 * MAP_SHARED data region page-shares across workers (plan 07 §4). */
static size_t sf_store_index_off(void)
{
    return ROUND_UP(sizeof(SfStoreHdr), 8);
}
static size_t sf_store_data_off(uint32_t n_pages)
{
    size_t psize = qemu_real_host_page_size();
    return ROUND_UP(sf_store_index_off() + (size_t)n_pages * sizeof(SfPageKey), psize);
}
static size_t sf_store_map_len(uint32_t n_pages)
{
    return sf_store_data_off(n_pages) + (size_t)n_pages * qemu_real_host_page_size();
}

/* Point hdr/index/data into a contiguous mapping @base of a store with n_pages. */
static void sf_store_map_ptrs(SfRamStore *s, void *base, uint32_t n_pages)
{
    s->hdr = (SfStoreHdr *)base;
    s->index = n_pages ? (SfPageKey *)((uint8_t *)base + sf_store_index_off()) : NULL;
    s->data = n_pages ? (uint8_t *)base + sf_store_data_off(n_pages) : NULL;
}

int sf_ramstore_create_file(SfRamStore *s, uint32_t n_pages, const char *path,
                            Error **errp)
{
    size_t map_len = sf_store_map_len(n_pages);
    void *base;
    int fd;

    memset(s, 0, sizeof(*s));
    s->backing = SF_BACKING_FILE;
    s->fd = -1;
    s->n_pages = n_pages;

    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        error_setg_errno(errp, errno, "sf_ramstore_create_file: open %s", path);
        return -1;
    }
    if (ftruncate(fd, map_len) < 0) {
        error_setg_errno(errp, errno, "sf_ramstore_create_file: ftruncate");
        close(fd);
        return -1;
    }
    base = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        error_setg_errno(errp, errno, "sf_ramstore_create_file: mmap");
        close(fd);
        return -1;
    }
    s->fd = fd;
    s->map_len = map_len;
    sf_store_map_ptrs(s, base, n_pages);
    s->hdr->magic = SF_STORE_MAGIC;
    s->hdr->version = SF_STORE_VERSION;
    s->hdr->n_pages = n_pages;
    s->hdr->page_size = (uint32_t)qemu_real_host_page_size();
    s->hdr->crc32c = 0;   /* filled by seal */
    return 0;
}

int sf_ramstore_seal(SfRamStore *s, Error **errp)
{
    uint8_t *base = (uint8_t *)s->hdr;
    size_t off = sizeof(SfStoreHdr);   /* crc covers everything after the hdr */

    if (s->backing != SF_BACKING_FILE || !base) {
        error_setg(errp, "sf_ramstore_seal: not a file-backed store");
        return -EINVAL;
    }
    s->hdr->crc32c = crc32c(0, base + off, s->map_len - off);
    if (msync(base, s->map_len, MS_SYNC) < 0) {
        error_setg_errno(errp, errno, "sf_ramstore_seal: msync");
        return -1;
    }
    if (mprotect(base, s->map_len, PROT_READ) < 0) {
        error_setg_errno(errp, errno, "sf_ramstore_seal: mprotect RO");
        return -1;
    }
    return 0;
}

int sf_ramstore_open_file(SfRamStore *s, const char *path, Error **errp)
{
    size_t off = sizeof(SfStoreHdr);
    struct stat st;
    void *base;
    SfStoreHdr *hdr;
    size_t want;
    uint32_t crc;
    int fd;

    memset(s, 0, sizeof(*s));
    s->backing = SF_BACKING_FILE;
    s->fd = -1;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        error_setg_errno(errp, errno, "sf_ramstore_open_file: open %s", path);
        return -1;
    }
    if (fstat(fd, &st) < 0 || (size_t)st.st_size < sizeof(SfStoreHdr)) {
        error_setg(errp, "sf_ramstore_open_file: %s too small / stat failed", path);
        close(fd);
        return -1;
    }
    base = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        error_setg_errno(errp, errno, "sf_ramstore_open_file: mmap");
        close(fd);
        return -1;
    }
    hdr = base;
    want = sf_store_map_len(hdr->n_pages);
    if (hdr->magic != SF_STORE_MAGIC || hdr->version != SF_STORE_VERSION ||
        hdr->page_size != qemu_real_host_page_size() ||
        (size_t)st.st_size != want) {
        error_setg(errp, "sf_ramstore_open_file: bad magic/version/page/size "
                   "(size %zu want %zu)", (size_t)st.st_size, want);
        munmap(base, st.st_size);
        close(fd);
        return -1;
    }
    crc = crc32c(0, (uint8_t *)base + off, want - off);
    if (crc != hdr->crc32c) {
        error_setg(errp, "sf_ramstore_open_file: crc mismatch (%08x vs %08x)",
                   crc, hdr->crc32c);
        munmap(base, st.st_size);
        close(fd);
        return -1;
    }
    s->fd = fd;
    s->map_len = want;
    s->n_pages = hdr->n_pages;
    sf_store_map_ptrs(s, base, hdr->n_pages);
    return 0;
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