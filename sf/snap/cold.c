/*
 * sf/snap/cold — cold-start sequence for a persisted M3 tree.
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "system/runstate.h"
#include "sf/snap/cold.h"
#include "sf/snap/node.h"
#include "sf/snap/persist.h"
#include "sf/snap/tripwire.h"

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
                  Error **errp)
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
