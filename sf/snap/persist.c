/*
 * sf/snap/persist — snapshot-tree persistence. See persist.h.
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/crc32c.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "qobject/qjson.h"
#include "sf/dirty/engine.h"
#include "sf/snap/node.h"
#include "sf/snap/tripwire.h"
#include "sf/snap/persist.h"

#define SF_MANIFEST_VERSION 1

/* ---- write side ---- */

static int sf_write_file(const char *path, const void *buf, size_t len,
                         Error **errp)
{
    GError *gerr = NULL;
    if (!g_file_set_contents(path, buf, len, &gerr)) {
        error_setg(errp, "sf_persist: write %s: %s", path, gerr->message);
        g_error_free(gerr);
        return -1;
    }
    return 0;
}

/* root.ram = each block's engine shadow concatenated in block_id order (raw, no
 * header — the layout lives in the manifest). */
static int sf_persist_root_ram(const char *dir, uint64_t *out_len,
                               uint32_t *out_crc, Error **errp)
{
    uint64_t total = 0, off = 0;
    uint8_t *buf;
    char *path;
    int ret;

    for (size_t i = 0; i < sf_n_blocks; i++) {
        total += sf_blocks[i].len;
    }
    buf = g_malloc(total);
    for (size_t i = 0; i < sf_n_blocks; i++) {
        uint64_t remain = 0;
        uint8_t *shadow = sf_dirty_shadow_for(sf_blocks[i].host, &remain);
        if (!shadow || remain < sf_blocks[i].len) {
            g_free(buf);
            error_setg(errp, "sf_persist: root shadow missing/short for block %zu", i);
            return -1;
        }
        memcpy(buf + off, shadow, sf_blocks[i].len);
        off += sf_blocks[i].len;
    }
    *out_len = total;
    *out_crc = crc32c(0, buf, total);
    path = g_build_filename(dir, "root.ram", NULL);
    ret = sf_write_file(path, buf, total, errp);
    g_free(path);
    g_free(buf);
    return ret;
}

/* Copy a node's (anon) diff store into nodes/<id>.ram in FILE format + seal. */
static int sf_persist_node_ram(const char *dir, SfSnapNode *n, Error **errp)
{
    size_t psize = qemu_real_host_page_size();
    char name[32];
    char *path;
    SfRamStore fs;
    int ret;

    snprintf(name, sizeof(name), "nodes/%u.ram", n->id);
    path = g_build_filename(dir, name, NULL);
    ret = sf_ramstore_create_file(&fs, n->ram.n_pages, path, errp);
    if (ret == 0) {
        if (n->ram.n_pages) {
            memcpy(fs.index, n->ram.index,
                   (size_t)n->ram.n_pages * sizeof(SfPageKey));
            memcpy(fs.data, n->ram.data, (size_t)n->ram.n_pages * psize);
        }
        ret = sf_ramstore_seal(&fs, errp);
        sf_ramstore_destroy(&fs);
    }
    g_free(path);
    return ret;
}

/* Write a device stream (方案 B) to <dir>/<name>; record its crc. No-op (*out_crc
 * = 0) when the node has no stream (RUN, or capture failed) — load treats 0 as
 * "no .dev". Caller records len separately (dev.stream_len). */
static int sf_persist_dev(const char *dir, const char *name,
                          const SfDevCapture *dev, uint32_t *out_crc,
                          Error **errp)
{
    char *path;
    int ret;

    if (!dev->stream) {
        *out_crc = 0;
        return 0;
    }
    *out_crc = crc32c(0, dev->stream, dev->stream_len);
    path = g_build_filename(dir, name, NULL);
    ret = sf_write_file(path, dev->stream, dev->stream_len, errp);
    g_free(path);
    return ret;
}

/* Append @n and its subtree (pre-order) to the manifest node list, writing each
 * non-root node's diff store + device stream. Sets *ret on the first failure. */
static void sf_persist_walk(SfSnapNode *n, QList *nodes, const char *dir,
                            Error **errp, int *ret)
{
    SfSnapNode *child;
    QDict *nd;
    uint32_t dev_crc = 0;
    char dname[32];

    if (*ret) {
        return;
    }
    if (n->parent && sf_persist_node_ram(dir, n, errp) < 0) {
        *ret = -1;
        return;
    }
    if (n->parent) {
        snprintf(dname, sizeof(dname), "nodes/%u.dev", n->id);
    } else {
        /* root's device stream lives next to root.ram (cold start feeds it to
         * qemu_load_device_state / sf_preparse_stream). */
        snprintf(dname, sizeof(dname), "root.dev");
    }
    if (sf_persist_dev(dir, dname, &n->dev, &dev_crc, errp) < 0) {
        *ret = -1;
        return;
    }

    nd = qdict_new();
    qdict_put_int(nd, "id", n->id);
    qdict_put_int(nd, "parent", n->parent ? (int64_t)n->parent->id : -1);
    qdict_put_int(nd, "kind", n->kind);
    qdict_put_int(nd, "depth", n->depth);
    qdict_put_int(nd, "kvm_tsc", (int64_t)n->kvm.tsc);
    qdict_put_int(nd, "dev_len", (int64_t)n->dev.stream_len);
    qdict_put_int(nd, "dev_crc", dev_crc);
    qlist_append_obj(nodes, QOBJECT(nd));

    QLIST_FOREACH(child, &n->children, sibling) {
        sf_persist_walk(child, nodes, dir, errp, ret);
    }
}

int sf_snap_persist(SfSnapNode *root, const char *dir, Error **errp)
{
    uint64_t root_len = 0;
    uint32_t root_crc = 0;
    QDict *man;
    QList *blocks, *nodes;
    char *ndir, *mpath;
    GString *json;
    int ret;

    if (!root || root->parent) {
        error_setg(errp, "sf_snap_persist: need the root node");
        return -EINVAL;
    }
    if (g_mkdir_with_parents(dir, 0700) < 0) {
        error_setg_errno(errp, errno, "sf_snap_persist: mkdir %s", dir);
        return -1;
    }
    ndir = g_build_filename(dir, "nodes", NULL);
    ret = g_mkdir_with_parents(ndir, 0700);
    g_free(ndir);
    if (ret < 0) {
        error_setg_errno(errp, errno, "sf_snap_persist: mkdir nodes/");
        return -1;
    }
    if (sf_persist_root_ram(dir, &root_len, &root_crc, errp) < 0) {
        return -1;
    }

    man = qdict_new();
    qdict_put_int(man, "version", SF_MANIFEST_VERSION);
    qdict_put_int(man, "page_size", qemu_real_host_page_size());
    qdict_put_int(man, "root_ram_len", (int64_t)root_len);
    qdict_put_int(man, "root_ram_crc", root_crc);

    blocks = qlist_new();
    for (size_t i = 0; i < sf_n_blocks; i++) {
        QDict *b = qdict_new();
        qdict_put_str(b, "idstr", sf_blocks[i].idstr);
        qdict_put_int(b, "len", (int64_t)sf_blocks[i].len);
        qlist_append_obj(blocks, QOBJECT(b));
    }
    qdict_put(man, "blocks", blocks);

    nodes = qlist_new();
    ret = 0;
    sf_persist_walk(root, nodes, dir, errp, &ret);
    qdict_put(man, "nodes", nodes);

    if (ret == 0) {
        json = qobject_to_json_pretty(QOBJECT(man), true);
        mpath = g_build_filename(dir, "manifest.json", NULL);
        ret = sf_write_file(mpath, json->str, json->len, errp);
        g_free(mpath);
        g_string_free(json, TRUE);
    }
    qobject_unref(man);
    return ret;
}

/* ---- load side ---- */

static SfSnapNode *sf_load_node(QDict *nd, GHashTable *byid, Error **errp)
{
    SfSnapNode *n = g_new0(SfSnapNode, 1);
    int64_t parent_id = qdict_get_try_int(nd, "parent", -1);

    n->id = (uint32_t)qdict_get_try_int(nd, "id", 0);
    n->kind = (SfSnapKind)qdict_get_try_int(nd, "kind", 0);
    n->depth = (uint32_t)qdict_get_try_int(nd, "depth", 0);
    n->kvm.tsc = (uint64_t)qdict_get_try_int(nd, "kvm_tsc", 0);
    n->state = SF_SNAP_SEALED;
    n->ram.fd = -1;
    QLIST_INIT(&n->children);

    if (parent_id >= 0) {
        SfSnapNode *parent = g_hash_table_lookup(byid,
                                                 GUINT_TO_POINTER(parent_id));
        if (!parent) {
            error_setg(errp, "sf_snap_load: node %u parent %" PRId64 " not seen "
                       "yet (manifest not pre-order?)", n->id, parent_id);
            g_free(n);
            return NULL;
        }
        n->parent = parent;
        QLIST_INSERT_HEAD(&parent->children, n, sibling);
    }
    g_hash_table_insert(byid, GUINT_TO_POINTER(n->id), n);
    return n;
}

static int sf_load_validate_blocks(QDict *man, Error **errp)
{
    QList *blocks = qobject_to(QList, qdict_get(man, "blocks"));
    const QListEntry *e;
    size_t i = 0;

    if (!blocks) {
        error_setg(errp, "sf_snap_load: manifest 'blocks' missing");
        return -1;
    }
    QLIST_FOREACH_ENTRY(blocks, e) {
        QDict *b = qobject_to(QDict, qlist_entry_obj(e));
        const char *idstr;
        if (i >= sf_n_blocks || !b) {
            error_setg(errp, "sf_snap_load: block count/type mismatch vs live");
            return -1;
        }
        idstr = qdict_get_try_str(b, "idstr");
        if (!idstr || strcmp(idstr, sf_blocks[i].idstr) != 0 ||
            (uint64_t)qdict_get_try_int(b, "len", -1) != sf_blocks[i].len) {
            error_setg(errp, "sf_snap_load: block %zu '%s' differs from live",
                       i, idstr ? idstr : "(null)");
            return -1;
        }
        i++;
    }
    if (i != sf_n_blocks) {
        error_setg(errp, "sf_snap_load: manifest has %zu blocks, live has %zu",
                   i, sf_n_blocks);
        return -1;
    }
    return 0;
}

static int sf_load_check_root_ram(const char *dir, QDict *man, Error **errp)
{
    char *path = g_build_filename(dir, "root.ram", NULL);
    gchar *buf = NULL;
    gsize len = 0;
    GError *gerr = NULL;
    uint64_t want_len = (uint64_t)qdict_get_try_int(man, "root_ram_len", -1);
    uint32_t want_crc = (uint32_t)qdict_get_try_int(man, "root_ram_crc", 0);
    int ret = -1;

    if (!g_file_get_contents(path, &buf, &len, &gerr)) {
        error_setg(errp, "sf_snap_load: read root.ram: %s", gerr->message);
        g_error_free(gerr);
        goto out;
    }
    if (len != want_len) {
        error_setg(errp, "sf_snap_load: root.ram len %zu != manifest %" PRIu64,
                   (size_t)len, want_len);
        goto out;
    }
    if (crc32c(0, (const uint8_t *)buf, len) != want_crc) {
        error_setg(errp, "sf_snap_load: root.ram crc mismatch");
        goto out;
    }
    ret = 0;
out:
    g_free(buf);
    g_free(path);
    return ret;
}

/* Read <dir>/<name>, verify its crc against @want_crc, and re-preparse the device
 * stream into @dev->tables (方案 B cold-start重建). want_crc == 0 means the node
 * had no persisted stream (RUN / capture failed) → dev.have stays false, no file
 * read. The stream bytes are freed after parsing: the replay tables are
 * self-contained, and a loaded node doesn't need to re-persist. */
static int sf_load_dev(const char *dir, const char *name, uint32_t want_crc,
                       SfDevCapture *dev, Error **errp)
{
    char *path;
    gchar *buf = NULL;
    gsize len = 0;
    GError *gerr = NULL;
    int ret = -1;

    if (want_crc == 0) {
        dev->have = false;
        return 0;
    }
    path = g_build_filename(dir, name, NULL);
    if (!g_file_get_contents(path, &buf, &len, &gerr)) {
        error_setg(errp, "sf_snap_load: read %s: %s", name, gerr->message);
        g_error_free(gerr);
        goto out;
    }
    if (crc32c(0, (const uint8_t *)buf, len) != want_crc) {
        error_setg(errp, "sf_snap_load: %s crc mismatch", name);
        goto out;
    }
    if (sf_preparse_stream((const uint8_t *)buf, len, &dev->tables, errp) < 0) {
        goto out;
    }
    dev->have = true;
    ret = 0;
out:
    g_free(buf);
    g_free(path);
    return ret;
}

/* Load a node's device stream based on its manifest entry: root → root.dev,
 * non-root → nodes/<id>.dev. want_crc comes from the node's "dev_crc" field. */
static int sf_load_node_dev(const char *dir, SfSnapNode *n, QDict *nd,
                            Error **errp)
{
    uint32_t want_crc = (uint32_t)qdict_get_try_int(nd, "dev_crc", 0);
    char dname[32];

    if (n->parent) {
        snprintf(dname, sizeof(dname), "nodes/%u.dev", n->id);
    } else {
        snprintf(dname, sizeof(dname), "root.dev");
    }
    return sf_load_dev(dir, dname, want_crc, &n->dev, errp);
}

int sf_snap_load(const char *dir, SfSnapNode **root_out, Error **errp)
{
    char *mpath = g_build_filename(dir, "manifest.json", NULL);
    gchar *jstr = NULL;
    gsize jlen = 0;
    GError *gerr = NULL;
    QObject *o = NULL;
    QDict *man;
    QList *nodes;
    const QListEntry *e;
    GHashTable *byid = NULL;
    SfSnapNode *root = NULL;
    int ret = -1;

    if (!g_file_get_contents(mpath, &jstr, &jlen, &gerr)) {
        error_setg(errp, "sf_snap_load: read manifest: %s", gerr->message);
        g_error_free(gerr);
        g_free(mpath);
        return -1;
    }
    g_free(mpath);

    o = qobject_from_json(jstr, errp);
    g_free(jstr);
    if (!o) {
        return -1;
    }
    man = qobject_to(QDict, o);
    if (!man) {
        error_setg(errp, "sf_snap_load: manifest is not a JSON object");
        goto out;
    }
    if (qdict_get_try_int(man, "version", -1) != SF_MANIFEST_VERSION) {
        error_setg(errp, "sf_snap_load: manifest version unsupported");
        goto out;
    }
    if (qdict_get_try_int(man, "page_size", -1) !=
        (int64_t)qemu_real_host_page_size()) {
        error_setg(errp, "sf_snap_load: page_size mismatch");
        goto out;
    }
    if (sf_load_validate_blocks(man, errp) < 0 ||
        sf_load_check_root_ram(dir, man, errp) < 0) {
        goto out;
    }

    nodes = qobject_to(QList, qdict_get(man, "nodes"));
    if (!nodes) {
        error_setg(errp, "sf_snap_load: manifest 'nodes' missing");
        goto out;
    }
    byid = g_hash_table_new(g_direct_hash, g_direct_equal);
    QLIST_FOREACH_ENTRY(nodes, e) {
        QDict *nd = qobject_to(QDict, qlist_entry_obj(e));
        SfSnapNode *n;
        if (!nd) {
            error_setg(errp, "sf_snap_load: node entry not an object");
            goto out;
        }
        n = sf_load_node(nd, byid, errp);
        if (!n) {
            goto out;
        }
        if (!n->parent) {
            root = n;
        } else {
            char name[32];
            char *rpath;
            int r;
            snprintf(name, sizeof(name), "nodes/%u.ram", n->id);
            rpath = g_build_filename(dir, name, NULL);
            r = sf_ramstore_open_file(&n->ram, rpath, errp);
            g_free(rpath);
            if (r < 0) {
                goto out;   /* ret stays -1 */
            }
        }
        /* Re-preparse this node's persisted device stream into replay tables
         * (方案 B). No-op (dev.have=false) when dev_crc==0. Pre-order manifest
         * → root first; each parse re-loads live device state, last one wins. */
        if (sf_load_node_dev(dir, n, nd, errp) < 0) {
            goto out;
        }
    }
    if (!root) {
        error_setg(errp, "sf_snap_load: no root node in manifest");
        goto out;
    }
    *root_out = root;
    ret = 0;
    root = NULL;   /* transferred to caller */
out:
    if (root) {
        sf_snap_free_loaded(root);
    }
    if (byid) {
        g_hash_table_destroy(byid);
    }
    qobject_unref(o);
    return ret;
}

/* Post-order free of a loaded subtree; no tripwire touch (loaded trees are not
 * the active armed tree). */
void sf_snap_free_loaded(SfSnapNode *root)
{
    SfSnapNode *child, *tmp;

    if (!root) {
        return;
    }
    QLIST_FOREACH_SAFE(child, &root->children, sibling, tmp) {
        sf_snap_free_loaded(child);
    }
    sf_ramstore_destroy(&root->ram);
    g_free(root->dev.stream);    /* NULL for loaded trees (stream freed after parse) */
    if (root->dev.have) {
        sf_replay_tables_destroy(&root->dev.tables);
    }
    g_free(root);
}
