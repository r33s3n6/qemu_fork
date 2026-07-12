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
#include "sf/snap/node.h"
#include "sf/snap/tripwire.h"
#include "sf/snap/exclude.h"
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

static int sf_write_all(int fd, const void *buf, size_t len);  /* defined below */

/* root.ram = root node backing: each block concatenated in block_id order (raw,
 * no header — the layout lives in the manifest). File-backed root created in
 * the target dir seals in place; anon/debug root falls back to one O(RAM) write. */
static int sf_persist_root_ram(SfSnapNode *root, const char *dir,
                               uint64_t *out_len, Error **errp)
{
    char *path;
    int ret;

    if (!root->ram.data || root->ram.map_len != sf_blocks_root_len()) {
        error_setg(errp, "sf_persist: root backing missing/short");
        return -1;
    }
    *out_len = root->ram.map_len;
    path = g_build_filename(dir, "root.ram", NULL);
    if (root->ram.backing == SF_BACKING_FILE && root->ram.path &&
        !strcmp(root->ram.path, path)) {
        ret = sf_rootstore_seal(&root->ram, errp);
    } else {
        ret = sf_write_file(path, root->ram.data, root->ram.map_len, errp);
    }
    g_free(path);
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

/* Write a device stream (方案 B) to <dir>/<name> and fsync it. The fsync is the
 * commit-point ordering guarantee for promote: the .dev must be durable BEFORE
 * its nodes.log line is appended (snapshot-tree.md §5.2), otherwise a crash after
 * the (fsync'd) log append but before the .dev pages hit disk would leave the log
 * referencing a lost/short .dev → hard load failure. No-op when the node has no
 * stream (RUN, or capture failed): no file is written, the record's dev_len stays
 * 0, and load treats it as absent. Integrity is the record's dev_crc
 * (sf_dev_crc), recomputed by sf_node_record_line — no out param here. */
static int sf_persist_dev(const char *dir, const char *name,
                          const SfDevCapture *dev, Error **errp)
{
    char *path;
    int fd, ret = -1;

    if (!dev->stream) {
        return 0;
    }
    path = g_build_filename(dir, name, NULL);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        error_setg_errno(errp, errno, "sf_persist: open %s", path);
        goto out;
    }
    if (sf_write_all(fd, dev->stream, dev->stream_len) < 0) {
        error_setg_errno(errp, errno, "sf_persist: write %s", path);
        goto out;
    }
    if (fsync(fd) < 0) {
        error_setg_errno(errp, errno, "sf_persist: fsync %s", path);
        goto out;
    }
    ret = 0;
out:
    if (fd >= 0) {
        close(fd);
    }
    g_free(path);
    return ret;
}

static uint32_t sf_dev_crc(const SfDevCapture *dev)
{
    return dev->stream ? crc32c(0, dev->stream, dev->stream_len) : 0;
}

/* ---- manifest field builders (single source of truth for the on-disk schema;
 * both sf_snap_persist (full tree) and sf_snap_promote (connected prefix) use
 * these so the node/block/exclude layout only ever lives in one place). ---- */

static void sf_manifest_put_blocks(QDict *man)
{
    QList *blocks = qlist_new();

    for (size_t i = 0; i < sf_n_blocks; i++) {
        QDict *b = qdict_new();
        qdict_put_str(b, "idstr", sf_blocks[i].idstr);
        qdict_put_int(b, "len", (int64_t)sf_blocks[i].len);
        qlist_append_obj(blocks, QOBJECT(b));
    }
    qdict_put(man, "blocks", blocks);
}

/*
 * Node records live in an append-only log (<dir>/nodes.log), one node per line,
 * NOT in manifest.json. manifest.json keeps only the tree-level header
 * (version/page_size/blocks/root_ram_len/exclude). The record is the single
 * on-disk contract shared by sf_snap_persist (full-tree sequential write) and
 * sf_snap_promote (one-line append = commit point) — snapshot-tree.md §5.1.
 *
 * Line = "<id> <parent> <kind> <depth> <kvm_tsc> <dev_len> <dev_crc> <crc08x>\n"
 * where <crc> = crc32c over the payload bytes (the 7 fields up to the last
 * space). parent is the full composite id, or -1 for the root. A crash can
 * truncate the final line; load verifies each line's crc and drops a残缺 tail.
 */
#define SF_NODE_LOG_NAME "nodes.log"

/* Format the 7-field payload (no crc, no newline) into @buf; return its length. */
static int sf_node_record_payload(const SfSnapNode *n, char *buf, size_t bufsz)
{
    return snprintf(buf, bufsz,
                    "%u %lld %d %u %" PRIu64 " %" PRIu64 " %u",
                    n->id,
                    (long long)(n->parent ? (int64_t)n->parent->id : -1LL),
                    (int)n->kind, n->depth,
                    (uint64_t)n->kvm.tsc,
                    /* dev_len is the presence signal (load keys on it, not crc):
                     * both fields track stream != NULL together so a real stream
                     * whose crc happens to be 0 is not misread as absent. */
                    (uint64_t)(n->dev.stream ? n->dev.stream_len : 0),
                    sf_dev_crc(&n->dev));
}

/* Full record line (payload + crc + newline) into @buf; return its length. */
static int sf_node_record_line(const SfSnapNode *n, char *buf, size_t bufsz)
{
    char payload[160];
    int plen = sf_node_record_payload(n, payload, sizeof(payload));
    uint32_t crc = crc32c(0, (const uint8_t *)payload, plen);

    return snprintf(buf, bufsz, "%s %08x\n", payload, crc);
}

static char *sf_node_log_path(const char *dir)
{
    return g_build_filename(dir, SF_NODE_LOG_NAME, NULL);
}

static int sf_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += w;
        len -= (size_t)w;
    }
    return 0;
}

/* Append one node record to nodes.log (O_APPEND → commit point for promote).
 * fsyncs the log so the record survives a crash right after. */
static int sf_node_log_append(const char *dir, const SfSnapNode *n, Error **errp)
{
    char line[192];
    int llen = sf_node_record_line(n, line, sizeof(line));
    char *path = sf_node_log_path(dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    int ret = -1;

    if (fd < 0) {
        error_setg_errno(errp, errno, "sf_persist: open %s", path);
        goto out;
    }
    if (sf_write_all(fd, line, llen) < 0) {
        error_setg_errno(errp, errno, "sf_persist: append %s", path);
        goto out;
    }
    if (fsync(fd) < 0) {
        error_setg_errno(errp, errno, "sf_persist: fsync %s", path);
        goto out;
    }
    ret = 0;
out:
    if (fd >= 0) {
        close(fd);
    }
    g_free(path);
    return ret;
}

/* NO_RESTORE table → manifest as block-relative offsets (defined below; forward
 * declared so the header writer can call it). */
static void sf_manifest_put_exclude(QDict *man);

/* manifest.json header (NO nodes — those are in nodes.log). Written atomically
 * (tmp+rename via g_file_set_contents). Used by sf_snap_persist and by promote
 * on the root (the first promote of a workdir, which establishes the header).
 * @common_ref != NULL marks a two-dir private manifest (plan 04 §2.2): it records
 * the read-only common base dir instead of a self-contained root.ram, so a
 * cold-start given only this private_dir can still find its common base. */
static int sf_manifest_write_header(const char *dir, uint64_t root_ram_len,
                                    const char *common_ref, Error **errp)
{
    QDict *man = qdict_new();
    GString *json;
    char *mpath;
    int ret;

    qdict_put_int(man, "version", SF_MANIFEST_VERSION);
    qdict_put_int(man, "page_size", qemu_real_host_page_size());
    if (common_ref) {
        qdict_put_str(man, "common", common_ref);
    } else {
        qdict_put_int(man, "root_ram_len", (int64_t)root_ram_len);
    }
    sf_manifest_put_blocks(man);
    sf_manifest_put_exclude(man);

    json = qobject_to_json_pretty(QOBJECT(man), true);
    mpath = g_build_filename(dir, "manifest.json", NULL);
    ret = sf_write_file(mpath, json->str, json->len, errp);
    g_free(mpath);
    g_string_free(json, TRUE);
    qobject_unref(man);
    return ret;
}

/* NO_RESTORE table → manifest as block-relative offsets (block,off,size,buf_id).
 * Content is NOT persisted here: every registered NO_RESTORE buffer is file-backed
 * (bufs/<buf_id>.buf via sf_buf_remap) and its content is restored from that shared
 * file by sf_cold_remap_bufs after reload. Host bases differ per process, so a
 * cold-started worker rebuilds host addresses from (block,off). §4.2-3: without the
 * table a worker resuming from snapshot X has an empty exclude set and restore rolls
 * back its task buffer. */
static void sf_manifest_put_exclude(QDict *man)
{
    QList *ex = qlist_new();
    size_t psize = qemu_real_host_page_size();
    size_t n = sf_exclude_count();

    for (size_t i = 0; i < n; i++) {
        uint64_t host_start, size;
        uint32_t buf_id;
        SfPageKey key;
        QDict *e;

        if (!sf_exclude_get(i, &host_start, &size, &buf_id) ||
            !sf_host_to_key_safe((void *)(uintptr_t)host_start, &key)) {
            continue;
        }
        e = qdict_new();
        qdict_put_int(e, "block", SF_KEY_BLOCK(key));
        qdict_put_int(e, "off", (int64_t)(SF_KEY_PFN(key) * psize));
        qdict_put_int(e, "size", (int64_t)size);
        qdict_put_int(e, "buf_id", buf_id);
        qlist_append_obj(ex, QOBJECT(e));
    }
    qdict_put(man, "exclude", ex);
}

/* Walk @n's subtree pre-order: write each non-root diff store + device stream,
 * and append the node record to nodes.log (@log_fd). Parent is always written
 * before its children, so the log is loadable in file order. Sets *ret on first
 * failure. */
static void sf_persist_walk(SfSnapNode *n, int log_fd, const char *dir,
                            bool skip_common, Error **errp, int *ret)
{
    SfSnapNode *child;
    char line[192];
    int llen;
    char dname[32];

    if (*ret) {
        return;
    }
    /* Two-dir private persist: the common prefix (worker-0 nodes) already lives
     * read-only in common_dir — don't re-copy it. Skip writing this node but
     * still recurse so private descendants hanging off it are written; their
     * records reference the common parent id, resolved via the loaded common
     * tree at cold-start (plan 04 §2.2/§2.4). */
    if (skip_common && SF_NODE_IS_COMMON(n)) {
        QLIST_FOREACH(child, &n->children, sibling) {
            sf_persist_walk(child, log_fd, dir, skip_common, errp, ret);
        }
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
    if (sf_persist_dev(dir, dname, &n->dev, errp) < 0) {
        *ret = -1;
        return;
    }

    llen = sf_node_record_line(n, line, sizeof(line));
    if (sf_write_all(log_fd, line, llen) < 0) {
        error_setg_errno(errp, errno, "sf_snap_persist: write nodes.log");
        *ret = -1;
        return;
    }

    QLIST_FOREACH(child, &n->children, sibling) {
        sf_persist_walk(child, log_fd, dir, skip_common, errp, ret);
    }
}

int sf_snap_persist(SfSnapNode *root, const char *dir,
                    const char *common_ref, Error **errp)
{
    bool skip_common = (common_ref != NULL);
    uint64_t root_len = 0;
    char *ndir, *lpath;
    int log_fd = -1;
    int ret = -1;

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
    /* Two-dir private persist skips the common root.ram (it stays read-only in
     * common_dir); the header records @common_ref instead. */
    if (!skip_common && sf_persist_root_ram(root, dir, &root_len, errp) < 0) {
        return -1;
    }
    /* Header (no nodes) first; nodes go to a fresh nodes.log below. */
    if (sf_manifest_write_header(dir, root_len, common_ref, errp) < 0) {
        return -1;
    }

    lpath = sf_node_log_path(dir);
    log_fd = open(lpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    g_free(lpath);
    if (log_fd < 0) {
        error_setg_errno(errp, errno, "sf_snap_persist: open nodes.log");
        return -1;
    }

    ret = 0;
    sf_persist_walk(root, log_fd, dir, skip_common, errp, &ret);
    if (ret == 0 && (fsync(log_fd) < 0)) {
        error_setg_errno(errp, errno, "sf_snap_persist: fsync nodes.log");
        ret = -1;
    }
    close(log_fd);
    return ret;
}

/* ---- promote side (connected prefix, in-place backing switch) ---- */

static int sf_persist_ensure_dirs(const char *dir, Error **errp)
{
    char *ndir;
    int ret;

    if (g_mkdir_with_parents(dir, 0700) < 0) {
        error_setg_errno(errp, errno, "sf_snap_promote: mkdir %s", dir);
        return -1;
    }
    ndir = g_build_filename(dir, "nodes", NULL);
    ret = g_mkdir_with_parents(ndir, 0700);
    g_free(ndir);
    if (ret < 0) {
        error_setg_errno(errp, errno, "sf_snap_promote: mkdir nodes/");
        return -1;
    }
    return 0;
}

static int sf_promote_root_ram(SfSnapNode *root, const char *dir, Error **errp)
{
    char *path = g_build_filename(dir, "root.ram", NULL);
    SfRamStore fs;
    int ret;

    if (!root->ram.data || root->ram.map_len != sf_blocks_root_len()) {
        error_setg(errp, "sf_snap_promote: root backing missing/short");
        g_free(path);
        return -1;
    }
    if (root->ram.backing == SF_BACKING_FILE && root->ram.path &&
        !strcmp(root->ram.path, path)) {
        ret = sf_rootstore_seal(&root->ram, errp);
        if (ret == 0) {
            root->state = SF_SNAP_PERSISTED;
        }
        g_free(path);
        return ret;
    }

    ret = sf_rootstore_create_file(&fs, path, errp);
    if (ret == 0) {
        memcpy(fs.data, root->ram.data, root->ram.map_len);
        ret = sf_rootstore_seal(&fs, errp);
    }
    if (ret == 0) {
        /* Swap the root backing in place; sf_resolve reads root->ram.data live,
         * so no re-registration is needed (the tracker keys off live RAM, not a
         * separate shadow pointer). */
        sf_ramstore_destroy(&root->ram);
        root->ram = fs;
        root->state = SF_SNAP_PERSISTED;
    } else {
        sf_ramstore_destroy(&fs);
    }
    g_free(path);
    return ret;
}

static int sf_promote_node_ram(SfSnapNode *n, const char *dir, Error **errp)
{
    size_t psize = qemu_real_host_page_size();
    char name[32];
    char *path;
    SfRamStore fs;
    int ret;

    snprintf(name, sizeof(name), "nodes/%u.ram", n->id);
    path = g_build_filename(dir, name, NULL);
    if (n->ram.backing == SF_BACKING_FILE && n->ram.path &&
        !strcmp(n->ram.path, path)) {
        ret = sf_ramstore_seal(&n->ram, errp);
        if (ret == 0) {
            n->state = SF_SNAP_PERSISTED;
        }
        g_free(path);
        return ret;
    }

    ret = sf_ramstore_create_file(&fs, n->ram.n_pages, path, errp);
    if (ret == 0) {
        if (n->ram.n_pages) {
            memcpy(fs.index, n->ram.index,
                   (size_t)n->ram.n_pages * sizeof(SfPageKey));
            memcpy(fs.data, n->ram.data, (size_t)n->ram.n_pages * psize);
        }
        ret = sf_ramstore_seal(&fs, errp);
    }
    if (ret == 0) {
        sf_ramstore_destroy(&n->ram);
        n->ram = fs;
        n->state = SF_SNAP_PERSISTED;
    } else {
        sf_ramstore_destroy(&fs);
    }
    g_free(path);
    return ret;
}

static int sf_promote_check_parent_prefix(SfSnapNode *parent, const char *dir,
                                          bool skip_common, Error **errp)
{
    for (SfSnapNode *n = parent; n; n = n->parent) {
        char name[32];
        char *path;
        bool exists;

        /* Two-dir promote only: a common ancestor's prefix lives read-only in
         * common_dir, not here — stop checking once we reach it (the whole rest
         * of the chain up to root is common; plan 04 §2.2 does not re-validate
         * the common base). In single-dir promote (skip_common=false) every node
         * is worker 0, so this must stay off or the disconnected-parent tooth
         * (an absent prefix .ram) would be skipped instead of rejected. */
        if (skip_common && SF_NODE_IS_COMMON(n)) {
            break;
        }
        if (!n->parent) {
            path = g_build_filename(dir, "root.ram", NULL);
        } else {
            snprintf(name, sizeof(name), "nodes/%u.ram", n->id);
            path = g_build_filename(dir, name, NULL);
        }
        exists = g_file_test(path, G_FILE_TEST_IS_REGULAR);
        if (!exists) {
            error_setg(errp, "sf_snap_promote: parent prefix missing %s", path);
            g_free(path);
            return -EINVAL;
        }
        g_free(path);
    }
    return 0;
}

int sf_snap_promote(SfSnapNode *node, const char *dir, const char *common_ref,
                    Error **errp)
{
    bool skip_common = (common_ref != NULL);
    char dname[32];

    if (!node) {
        error_setg(errp, "sf_snap_promote: node required");
        return -EINVAL;
    }
    if (node->parent && node->parent->state != SF_SNAP_PERSISTED) {
        error_setg(errp, "sf_snap_promote: parent %u is not persisted",
                   node->parent->id);
        return -EINVAL;
    }
    if (sf_persist_ensure_dirs(dir, errp) < 0) {
        return -1;
    }

    if (!node->parent) {
        if (sf_promote_root_ram(node, dir, errp) < 0) {
            return -1;
        }
        /* Root promote establishes the workdir: write the header (manifest.json)
         * once. Non-root promotes inherit it — the header is tree-level and
         * stable, so they only append their node record. */
        if (sf_manifest_write_header(dir, sf_blocks_root_len(), NULL,
                                     errp) < 0) {
            return -1;
        }
        snprintf(dname, sizeof(dname), "root.dev");
    } else {
        if (sf_promote_check_parent_prefix(node->parent, dir, skip_common,
                                           errp) < 0) {
            return -EINVAL;
        }
        if (sf_promote_node_ram(node, dir, errp) < 0) {
            return -1;
        }
        snprintf(dname, sizeof(dname), "nodes/%u.dev", node->id);
    }
    /* Write + fsync the device stream BEFORE the commit point (sf_persist_dev
     * fsyncs). Ordering: durable .ram (seal msync) + durable .dev, THEN the log
     * append. A crash before the append leaves an orphan .dev/.ram the log never
     * references (harmless); a crash after it finds both data files already on
     * disk. */
    if (sf_persist_dev(dir, dname, &node->dev, errp) < 0) {
        return -1;
    }
    /* Commit point: append THIS node's record only. We never rewrite the log, so
     * sibling branches promoted before/after are preserved (snapshot-tree.md
     * §5.1 — the bug where a later promote rewrote manifest.json to a single
     * lineage and erased the sibling). fsync makes the append durable. */
    return sf_node_log_append(dir, node, errp);
}

/* ---- load side ---- */

/* Parsed node record (one nodes.log line). Mirrors sf_node_record_payload. */
typedef struct SfNodeRec {
    uint32_t id;
    int64_t  parent;     /* -1 for root */
    int      kind;
    uint32_t depth;
    uint64_t tsc;
    uint64_t dev_len;
    uint32_t dev_crc;
} SfNodeRec;

/* Parse one record line (WITHOUT the trailing '\n', @len bytes). Splits off the
 * trailing crc token, verifies it against crc32c of the payload, and parses the
 * 7 payload fields into @rec. *crc_ok = false on crc mismatch. Returns 0 on a
 * structurally-valid line (caller still checks *crc_ok), -1 on a malformed line
 * (wrong token count / non-numeric). */
static int sf_node_record_parse(const char *line, size_t len, SfNodeRec *rec,
                                bool *crc_ok)
{
    char *copy = g_strndup(line, len);
    char **tok = NULL;
    char *p;
    uint32_t want, got;
    int ret = -1;

    *crc_ok = false;
    /* The crc is the last whitespace-separated token; the payload is everything
     * before its separating space. Find the last space in the line. */
    p = NULL;
    for (ssize_t i = (ssize_t)len - 1; i >= 0; i--) {
        if (copy[i] == ' ') {
            p = &copy[i];
            break;
        }
    }
    if (!p) {
        goto out;
    }
    want = (uint32_t)g_ascii_strtoull(p + 1, NULL, 16);
    got = crc32c(0, (const uint8_t *)copy, (size_t)(p - copy));
    *crc_ok = (want == got);

    /* Truncate at the separating space so g_strsplit yields exactly the 7
     * payload fields. */
    *p = '\0';
    tok = g_strsplit_set(copy, " ", 7);
    if (!tok || g_strv_length(tok) != 7) {
        goto out;
    }
    rec->id      = (uint32_t)g_ascii_strtoull(tok[0], NULL, 10);
    rec->parent  = (int64_t)g_ascii_strtoll(tok[1], NULL, 10);
    rec->kind    = (int)g_ascii_strtoll(tok[2], NULL, 10);
    rec->depth   = (uint32_t)g_ascii_strtoull(tok[3], NULL, 10);
    rec->tsc     = (uint64_t)g_ascii_strtoull(tok[4], NULL, 10);
    rec->dev_len = (uint64_t)g_ascii_strtoull(tok[5], NULL, 10);
    rec->dev_crc = (uint32_t)g_ascii_strtoull(tok[6], NULL, 10);
    ret = 0;
out:
    g_strfreev(tok);
    g_free(copy);
    return ret;
}

static SfSnapNode *sf_load_node_rec(const SfNodeRec *rec, GHashTable *byid,
                                    Error **errp)
{
    SfSnapNode *n = g_new0(SfSnapNode, 1);

    n->id = rec->id;
    sf_node_observe_id(n->id);
    n->kind = (SfSnapKind)rec->kind;
    n->depth = rec->depth;
    n->kvm.tsc = rec->tsc;
    n->state = SF_SNAP_PERSISTED;
    n->ram.fd = -1;
    QLIST_INIT(&n->children);

    if (rec->parent >= 0) {
        SfSnapNode *parent = g_hash_table_lookup(byid,
                                                 GUINT_TO_POINTER((uint32_t)rec->parent));
        if (!parent) {
            error_setg(errp, "sf_snap_load: node %u parent %" PRId64 " not seen "
                       "yet (log not parent-before-child?)", n->id, rec->parent);
            g_free(n);
            return NULL;
        }
        n->parent = parent;
        QLIST_INSERT_HEAD(&parent->children, n, sibling);
    }
    g_hash_table_insert(byid, GUINT_TO_POINTER(n->id), n);
    return n;
}

/* Open a non-root node's diff store (nodes/<id>.ram); root's ram stays empty
 * (the cold-start core maps root.ram as the backing). */
static int sf_load_node_ram(const char *dir, SfSnapNode *n, Error **errp)
{
    char name[32];
    char *rpath;
    int r;

    snprintf(name, sizeof(name), "nodes/%u.ram", n->id);
    rpath = g_build_filename(dir, name, NULL);
    r = sf_ramstore_open_file(&n->ram, rpath, errp);
    g_free(rpath);
    return r;
}

/* Read <dir>/<name>, verify length + crc, and re-preparse the device stream into
 * @dev->tables (方案 B cold-start重建). Presence is keyed on @want_len (the
 * record's dev_len): want_len == 0 means the node had no persisted stream (RUN /
 * capture failed) → dev.have stays false, no file read. @want_crc gates integrity
 * only (a real stream whose crc is 0 is still read, because want_len > 0). The
 * stream bytes are freed after parsing: the replay tables are self-contained, and
 * a loaded node doesn't need to re-persist. */
static int sf_load_dev(const char *dir, const char *name, uint64_t want_len,
                       uint32_t want_crc, SfDevCapture *dev, Error **errp)
{
    char *path;
    gchar *buf = NULL;
    gsize len = 0;
    GError *gerr = NULL;
    int ret = -1;

    if (want_len == 0) {
        dev->have = false;
        return 0;
    }
    path = g_build_filename(dir, name, NULL);
    if (!g_file_get_contents(path, &buf, &len, &gerr)) {
        error_setg(errp, "sf_snap_load: read %s: %s", name, gerr->message);
        g_error_free(gerr);
        goto out;
    }
    if (len != want_len) {
        error_setg(errp, "sf_snap_load: %s len %" G_GSIZE_FORMAT " != record %"
                   PRIu64, name, len, want_len);
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

static int sf_load_node_dev_rec(const char *dir, SfSnapNode *n,
                                const SfNodeRec *rec, Error **errp)
{
    char dname[32];

    if (n->parent) {
        snprintf(dname, sizeof(dname), "nodes/%u.dev", n->id);
    } else {
        snprintf(dname, sizeof(dname), "root.dev");
    }
    return sf_load_dev(dir, dname, rec->dev_len, rec->dev_crc, &n->dev, errp);
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
    uint64_t want_len = (uint64_t)qdict_get_try_int(man, "root_ram_len", -1);
    struct stat st;
    int ret = -1;

    /* root.ram is full guest RAM; only its length is validated here (§4.2-5: no
     * crc). Stat it — reading the whole file just to check size is O(RAM) waste,
     * and the cold-start core fstat+mmaps it again right after. */
    if (stat(path, &st) < 0) {
        error_setg_errno(errp, errno, "sf_snap_load: stat root.ram");
        goto out;
    }
    if ((uint64_t)st.st_size != want_len) {
        error_setg(errp, "sf_snap_load: root.ram len %" PRIu64 " != manifest %"
                   PRIu64, (uint64_t)st.st_size, want_len);
        goto out;
    }
    ret = 0;
out:
    g_free(path);
    return ret;
}

/*
 * Read <dir>/nodes.log and rebuild the tree into @byid / @root_out. Each
 * complete line (terminated by '\n') must pass crc — a crc failure there is hard
 * corruption. The bytes after the final '\n' are a possibly-truncated tail: if
 * empty, fine; if it parses and crcs, accept it; if not, drop it (a crash wrote
 * a half line — snapshot-tree.md §5.1/§5.2). Parent records precede their
 * children in the log (enforced by promote's PERSISTED-ancestor invariant and
 * persist's pre-order walk), so file order is loadable.
 *
 * For each node: link to parent, open non-root .ram, re-preparse .dev.
 */
static int sf_node_log_load(const char *dir, GHashTable *byid,
                            SfSnapNode **root_out, bool require_root,
                            Error **errp)
{
    char *lpath = sf_node_log_path(dir);
    gchar *buf = NULL;
    gsize blen = 0;
    GError *gerr = NULL;
    SfSnapNode *root = NULL;
    const char *p, *nl;
    int ret = -1;

    if (!g_file_get_contents(lpath, &buf, &blen, &gerr)) {
        error_setg(errp, "sf_snap_load: read nodes.log: %s", gerr->message);
        g_error_free(gerr);
        g_free(lpath);
        return -1;
    }
    g_free(lpath);

    p = buf;
    nl = buf;
    while (nl < buf + blen) {
        const char *next = memchr(nl, '\n', (size_t)(buf + blen - nl));
        if (!next) {
            break;   /* trailing partial line — handled after the loop */
        }
        size_t line_len = (size_t)(next - nl);
        SfNodeRec rec;
        bool crc_ok;
        SfSnapNode *n;

        if (sf_node_record_parse(nl, line_len, &rec, &crc_ok) < 0) {
            error_setg(errp, "sf_snap_load: nodes.log malformed line");
            goto out;
        }
        if (!crc_ok) {
            error_setg(errp, "sf_snap_load: nodes.log crc mismatch (corrupt "
                       "record, not a crash tail)");
            goto out;
        }
        n = sf_load_node_rec(&rec, byid, errp);
        if (!n) {
            goto out;
        }
        if (!n->parent) {
            root = n;
        } else if (sf_load_node_ram(dir, n, errp) < 0) {
            goto out;
        }
        if (sf_load_node_dev_rec(dir, n, &rec, errp) < 0) {
            goto out;
        }
        nl = next + 1;
        p = nl;
    }

    /* Trailing tail after the last '\n': a crash may have written a partial
     * line here. Accept it only if it parses AND crcs; otherwise drop it. */
    if (p < buf + blen) {
        SfNodeRec rec;
        bool crc_ok;
        if (sf_node_record_parse(p, (size_t)(buf + blen - p), &rec, &crc_ok) == 0
            && crc_ok) {
            SfSnapNode *n = sf_load_node_rec(&rec, byid, errp);
            if (!n) {
                goto out;
            }
            if (!n->parent) {
                root = n;
            } else if (sf_load_node_ram(dir, n, errp) < 0) {
                goto out;
            }
            if (sf_load_node_dev_rec(dir, n, &rec, errp) < 0) {
                goto out;
            }
        }
        /* else: incomplete tail — drop silently. */
    }

    if (require_root && !root) {
        error_setg(errp, "sf_snap_load: no root node in nodes.log");
        goto out;
    }
    if (root_out) {
        *root_out = root;
    }
    root = NULL;
    ret = 0;
out:
    if (root) {
        sf_snap_free_loaded(root);
    }
    g_free(buf);
    return ret;
}

int sf_snap_load(const char *dir, SfSnapNode **root_out, Error **errp)
{
    char *mpath = g_build_filename(dir, "manifest.json", NULL);
    gchar *jstr = NULL;
    gsize jlen = 0;
    GError *gerr = NULL;
    QObject *o = NULL;
    QDict *man;
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

    /* Nodes live in nodes.log now (append-only), not in manifest.json. */
    byid = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (sf_node_log_load(dir, byid, &root, true, errp) < 0) {
        goto out;
    }
    *root_out = root;
    root = NULL;   /* transferred to caller */
    ret = 0;
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

/* Index an already-loaded tree by id (for overlay parent resolution). */
static void sf_index_tree(SfSnapNode *n, GHashTable *byid)
{
    SfSnapNode *child;
    g_hash_table_insert(byid, GUINT_TO_POINTER(n->id), n);
    QLIST_FOREACH(child, &n->children, sibling) {
        sf_index_tree(child, byid);
    }
}

/* Two-dir cold-start (plan 04 §2.2): load a worker's private overlay from @dir
 * and graft it onto the already-loaded common tree @base_root. Private nodes'
 * parent ids resolve against the common tree (or an earlier private node), so
 * the common tree MUST be loaded first. Only nodes.log + nodes/<id>.{ram,dev}
 * are read here — the private manifest is not needed (its blocks match live and
 * its 'common' ref was already consumed to pick @base_root). */
int sf_snap_load_overlay(const char *dir, SfSnapNode *base_root, Error **errp)
{
    char *lpath = sf_node_log_path(dir);
    bool has_log = g_file_test(lpath, G_FILE_TEST_IS_REGULAR);
    GHashTable *byid;
    int ret;

    g_free(lpath);
    /* An empty private_dir (no nodes.log) is the valid first-boot state: it is
     * the worker's write target, not yet an overlay. No overlay to graft. */
    if (!has_log) {
        return 0;
    }
    byid = g_hash_table_new(g_direct_hash, g_direct_equal);
    sf_index_tree(base_root, byid);
    ret = sf_node_log_load(dir, byid, NULL, false, errp);
    g_hash_table_destroy(byid);
    return ret;
}

/* Peek a private manifest's 'common' base-dir reference (plan 04 §2.2). Returns
 * a newly-allocated string, or NULL if the dir has no manifest / no 'common'
 * field (a self-contained single-dir tree). Never errors — a missing manifest
 * just means "no ref". */
char *sf_snap_read_common_ref(const char *dir)
{
    char *mpath = g_build_filename(dir, "manifest.json", NULL);
    gchar *jstr = NULL;
    gsize jlen = 0;
    QObject *o;
    QDict *man;
    char *ref = NULL;

    if (g_file_get_contents(mpath, &jstr, &jlen, NULL)) {
        o = qobject_from_json(jstr, NULL);
        man = o ? qobject_to(QDict, o) : NULL;
        if (man) {
            const char *c = qdict_get_try_str(man, "common");
            if (c && *c) {
                ref = g_strdup(c);
            }
        }
        qobject_unref(o);
        g_free(jstr);
    }
    g_free(mpath);
    return ref;
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

int sf_exclude_reload(const char *dir, Error **errp)
{
    char *mpath = g_build_filename(dir, "manifest.json", NULL);
    gchar *jstr = NULL;
    gsize jlen = 0;
    GError *gerr = NULL;
    QObject *o;
    QDict *man;
    QList *ex;
    const QListEntry *e;
    int ret = -1;

    if (!g_file_get_contents(mpath, &jstr, &jlen, &gerr)) {
        error_setg(errp, "sf_exclude_reload: read manifest: %s", gerr->message);
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
        error_setg(errp, "sf_exclude_reload: manifest is not a JSON object");
        goto out;
    }
    ex = qobject_to(QList, qdict_get(man, "exclude"));

    /* Rebuild the exclude table from a clean slate: block-relative (block,off) →
     * live host base. Content is NOT restored here — every registered buffer is
     * file-backed and sf_cold_remap_bufs mmaps it from bufs/<buf_id>.buf right
     * after this reload. Empty exclude → no-op. */
    sf_exclude_clear();
    if (ex) {
        QLIST_FOREACH_ENTRY(ex, e) {
            QDict *ed = qobject_to(QDict, qlist_entry_obj(e));
            uint32_t bid;
            uint64_t off, size;

            if (!ed) {
                error_setg(errp, "sf_exclude_reload: exclude entry not an object");
                goto out;
            }
            bid = (uint32_t)qdict_get_try_int(ed, "block", 0);
            off = (uint64_t)qdict_get_try_int(ed, "off", 0);
            size = (uint64_t)qdict_get_try_int(ed, "size", 0);
            if (bid >= sf_n_blocks || off + size > sf_blocks[bid].len) {
                error_setg(errp, "sf_exclude_reload: range out of block bounds");
                goto out;
            }
            sf_exclude_add((uint64_t)(uintptr_t)((uint8_t *)sf_blocks[bid].host + off),
                           size, (uint32_t)qdict_get_try_int(ed, "buf_id", 0));
        }
    }
    ret = 0;
out:
    qobject_unref(o);
    return ret;
}
