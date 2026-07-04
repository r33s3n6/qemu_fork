/*
 * sf/vmstate_replay/replay — replay tables + stock cross-check. See replay.h.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "migration/qemu-file.h"
#include "migration/savevm.h"
#include "migration/global_state.h"
#include "sf/vmstate_replay/buffer.h"
#include "sf/vmstate_replay/preparse.h"
#include "sf/vmstate_replay/replay.h"

static void run_pre_load(const SfPost *p)
{
    if (p->vmsd->pre_load_errp) {
        p->vmsd->pre_load_errp(p->opaque, NULL);
    } else if (p->vmsd->pre_load) {
        p->vmsd->pre_load(p->opaque);
    }
}

static void run_post_load(const SfPost *p)
{
    if (p->vmsd->post_load_errp) {
        p->vmsd->post_load_errp(p->opaque, p->version_id, NULL);
    } else if (p->vmsd->post_load) {
        p->vmsd->post_load(p->opaque, p->version_id);
    }
}

void sf_replay(const SfReplayTables *t)
{
    for (size_t i = 0; i < t->n_posts; i++) {
        if (t->posts[i].is_pre) {
            run_pre_load(&t->posts[i]);
        }
    }
    for (size_t i = 0; i < t->n_mblocks; i++) {
        memcpy(t->mblocks[i].ptr, t->mblocks[i].copy, t->mblocks[i].size);
    }
    for (size_t i = 0; i < t->n_gets; i++) {
        const SfGet *g = &t->gets[i];
        QEMUFile *f = sf_qemufile_from_buffer_input(g->captured, g->captured_len);
        g->info->get(f, g->ptr, g->size, g->field);
        qemu_fclose(f);
    }
    for (size_t i = 0; i < t->n_posts; i++) {
        if (!t->posts[i].is_pre) {
            run_post_load(&t->posts[i]);
        }
    }
}

/* ---- selftest ⑤: cross-check against stock load ---- */

/* Serialize current device state into a fresh owned byte buffer. */
static uint8_t *save_device_bytes(size_t *len_out, Error **errp)
{
    QEMUFile *wf = sf_qemufile_from_buffer_output();
    if (qemu_save_device_state(wf, errp) != 0) {
        qemu_fclose(wf);
        return NULL;
    }
    const uint8_t *b;
    size_t l;
    sf_qemufile_get_output(wf, &b, &l);
    uint8_t *dup = g_memdup2(b, l);
    *len_out = l;
    qemu_fclose(wf);
    return dup;
}

bool sf_replay_matches_stock(const SfReplayTables *t, Error **errp)
{
    bool ok = false;
    uint8_t *snap = NULL, *stock_bytes = NULL, *sf_bytes = NULL;
    size_t snap_len = 0, stock_len = 0, sf_len = 0;

    /* Reference snapshot stream S from the current (snapshot) device state. */
    global_state_store();
    snap = save_device_bytes(&snap_len, errp);
    if (!snap) {
        return false;
    }

    /* A deliberate perturbation both paths must undo: clobber the first mblock. */
    void *tgt = t->n_mblocks ? t->mblocks[0].ptr : NULL;
    size_t tsz = t->n_mblocks ? MIN(t->mblocks[0].size, 8u) : 0;
    uint8_t saved[8];
    if (tgt) {
        memcpy(saved, tgt, tsz);
    }

    /* Path B (stock): perturb -> qemu_load_device_state(S) -> re-serialize. */
    if (tgt) {
        memset(tgt, 0xA5, tsz);
    }
    QEMUFile *lf = sf_qemufile_from_buffer_input(snap, snap_len);
    if (qemu_load_device_state(lf, errp) != 0) {
        qemu_fclose(lf);
        goto out;
    }
    qemu_fclose(lf);
    stock_bytes = save_device_bytes(&stock_len, errp);
    if (!stock_bytes) {
        goto out;
    }

    /* Path A (sf): same perturbation -> sf_replay(t) -> re-serialize. */
    if (tgt) {
        memset(tgt, 0xA5, tsz);
    }
    sf_replay(t);
    sf_bytes = save_device_bytes(&sf_len, errp);
    if (!sf_bytes) {
        goto out;
    }

    ok = (sf_len == stock_len) && (memcmp(sf_bytes, stock_bytes, sf_len) == 0);
    if (!ok && errp && !*errp) {
        error_setg(errp, "sf_replay diverged from stock load "
                   "(sf %zu B, stock %zu B)", sf_len, stock_len);
    }

out:
    if (tgt) {
        memcpy(tgt, saved, tsz); /* leave the byte we clobbered as we found it */
    }
    g_free(snap);
    g_free(stock_bytes);
    g_free(sf_bytes);
    return ok;
}
