/*
 * sf/snap/cold — cold-start sequence for a persisted M3 tree.
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "system/runstate.h"
#include "system/kvm.h"
#include "sf/snap/cold.h"
#include "sf/snap/node.h"
#include "sf/snap/persist.h"
#include "sf/snap/tripwire.h"
#include "sf/kvm_tsc.h"

/*
 * Prefault host pages for root.ram (MAP_SHARED restore source), ancestor
 * diff stores, and live MAP_PRIVATE RAM after cold remap+restore.
 * Hypothesis (plan 07-10-01 维 A): first-window high pf_taken is host-side
 * cold EPT/first-touch after cold-start; warming these mappings may crush r1 pf.
 * Opt-in: SF_PREFAULT=1 (or "on"/"yes"). Touches only; no semantic change.
 */
static void sf_prefault_span(void *p, size_t len)
{
    size_t psz = qemu_real_host_page_size();
    volatile uint8_t acc = 0;
    uint8_t *base = p;

    if (!base || len == 0) {
        return;
    }
    for (size_t off = 0; off < len; off += psz) {
        acc += base[off];
    }
    /* Prevent the compiler from deleting the walk. */
    if (acc == 0xff && len == 1) {
        asm volatile("" ::: "memory");
    }
}

static void sf_prefault_ramstore(const SfRamStore *s)
{
    if (!s) {
        return;
    }
    if (s->map_base && s->map_len) {
        sf_prefault_span(s->map_base, s->map_len);
        return;
    }
    /* ANON / partial: touch data payload if present. */
    if (s->data && s->n_pages) {
        sf_prefault_span(s->data,
                         (size_t)s->n_pages * qemu_real_host_page_size());
    }
}

static void sf_prefault_after_cold_start(SfSnapNode *target)
{
    const char *e = getenv("SF_PREFAULT");
    size_t n_store = 0;
    int n_nodes = 0;

    if (!e || !*e || !strcmp(e, "0") || !strcmp(e, "off") || !strcmp(e, "no")) {
        return;
    }

    /*
     * Prefault restore *sources*. Modes (SF_PREFAULT=):
     *   diff | 1 | on | yes  — ancestor **diff** stores only (default; skip root.ram)
     *   store | all-store    — root.ram + diffs (smoke: full root thrash, r1 worse)
     *   live | all           — + live MAP_PRIVATE (known harmful in smoke)
     * Rationale: 6GiB root touch washes host cache → r1 wall/pf explode; diffs are
     * small (schema/prefix tens of MB) and are the MAP_SHARED COW parents of interest.
     */
    bool do_root = !strcmp(e, "store") || !strcmp(e, "all-store")
                   || !strcmp(e, "live") || !strcmp(e, "all");
    bool do_live = !strcmp(e, "live") || !strcmp(e, "all");

    for (SfSnapNode *n = target; n; n = n->parent) {
        bool is_root = (n->parent == NULL);
        if (is_root && !do_root) {
            continue;
        }
        sf_prefault_ramstore(&n->ram);
        n_nodes++;
        if (n->ram.map_len) {
            n_store += n->ram.map_len;
        } else if (n->ram.n_pages) {
            n_store += (size_t)n->ram.n_pages * qemu_real_host_page_size();
        }
    }

    size_t n_live = 0;
    if (do_live) {
        for (size_t i = 0; i < sf_n_blocks; i++) {
            sf_prefault_span(sf_blocks[i].host, (size_t)sf_blocks[i].len);
            n_live += (size_t)sf_blocks[i].len;
        }
    }
    fprintf(stderr,
            "sf-prefault: store=%zuMiB nodes=%d live=%zuMiB mode=%s\n",
            n_store / (1024 * 1024), n_nodes, n_live / (1024 * 1024), e);
}

static int sf_cold_remap_live_ram(int fd, Error **errp)
{
    for (size_t i = 0; i < sf_n_blocks; i++) {
        SfBlockDesc *b = &sf_blocks[i];
        void *p;

        if (munmap(b->host, b->len) != 0) {
            error_setg_errno(errp, errno, "sf_cold_start: munmap block %zu", i);
            return -1;
        }
        p = mmap(b->host, b->len, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_FIXED, fd, b->root_off);
        if (p == MAP_FAILED) {
            error_setg_errno(errp, errno, "sf_cold_start: mmap block %zu", i);
            return -1;
        }
        if (p != b->host) {
            error_setg(errp, "sf_cold_start: mmap block %zu returned %p want %p",
                       i, p, b->host);
            return -1;
        }
    }
    return 0;
}

int sf_cold_start(const char *dir, uint32_t dst_id, bool restore_exclude,
                  bool skip_checkpoint_outl, Error **errp)
{
    SfSnapNode *loaded = NULL;
    SfSnapNode *target;
    char *root_path = NULL;
    int fd = -1;
    int ret = -1;

    if (!dir || !*dir) {
        error_setg(errp, "sf_cold_start: missing snapshot dir");
        return -EINVAL;
    }

    if (sf_active) {
        SfSnapNode *root = sf_active;
        while (root->parent) {
            root = root->parent;
        }
        sf_node_destroy(root);   /* root teardown disarms the tracker */
        sf_active = NULL;
    }
    sf_blocks_destroy();
    if (sf_blocks_enumerate(errp) < 0) {
        return -1;
    }

    root_path = g_build_filename(dir, "root.ram", NULL);
    fd = open(root_path, O_RDONLY);
    if (fd < 0) {
        error_setg_errno(errp, errno, "sf_cold_start: open %s", root_path);
        goto out;
    }

    /* Reset devices before sf_snap_load reparses .dev streams into live device
     * state. This mirrors stock loadvm's snapshot-load reset boundary. */
    qemu_system_reset(SHUTDOWN_CAUSE_SNAPSHOT_LOAD);

    if (sf_cold_remap_live_ram(fd, errp) < 0) {
        goto out;
    }
    if (sf_snap_load(dir, &loaded, errp) < 0) {
        goto out;
    }
    /* Rebuild the NO_RESTORE table from the manifest before restore, else a
     * worker resuming from a snapshot (guest not re-running REGISTER_BUF) has an
     * empty exclude table and restore rolls back its task buffer (§4.2-3). */
    if (sf_exclude_reload(dir, restore_exclude, errp) < 0) {
        goto out;
    }
    if (sf_rootstore_open_file(&loaded->ram, root_path, errp) < 0) {
        goto out;
    }
    if (sf_snap_tracker_arm(loaded, errp) < 0) {
        goto out;
    }

    sf_active = loaded;
    loaded = NULL; /* active tree now owns it */

    target = sf_node_find(dst_id);
    if (!target) {
        error_setg(errp, "sf_cold_start: target id %u not found", dst_id);
        goto out;
    }
    if (sf_snap_restore(dst_id, NULL, errp) < 0) {
        goto out;
    }
    if (skip_checkpoint_outl && kvm_enabled() &&
        sf_kvm_skip_checkpoint_outl(first_cpu) < 0) {
        error_setg(errp, "sf_cold_start: restored checkpoint RIP is invalid");
        goto out;
    }
    /* Dim-A: warm host pages before first guest race window (opt-in). */
    sf_prefault_after_cold_start(target);
    sf_tripwire_arm(true);
    ret = 0;

out:
    if (ret < 0 && loaded) {
        sf_snap_free_loaded(loaded);
    }
    if (fd >= 0) {
        close(fd);
    }
    g_free(root_path);
    return ret;
}
