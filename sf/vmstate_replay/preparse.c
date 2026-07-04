/*
 * sf/vmstate_replay/preparse — build the three replay tables by a "recording
 * real load" of the device state. See preparse.h for the model.
 *
 * This clean-room mirrors the stock walk (migration/vmstate.c
 * vmstate_load_state + vmstate_subsection_load, and migration/savevm.c's
 * FULL-section loop) but records落点 into flat tables instead of only loading.
 * Nyx's state_reallocation.c was read for the recipe (record mblock copy
 * per-field before post_load; replay = pre_load hooks, memcpy mblocks, post_load
 * hooks) but no Nyx code is included or copied.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "migration/qemu-file.h"
#include "migration/qemu-file-types.h"
#include "migration/savevm.h"
#include "migration/global_state.h"
#include "sf/vmstate_replay/buffer.h"
#include "sf/vmstate_replay/preparse.h"

/* ------------------------------------------------------------------ *
 * Field classification: which VMStateInfo loads are pure byte moves    *
 * (mblock: capture memory, memcpy back) vs. side-effecting (get:        *
 * replay info->get over the captured stream slice) vs. no-state (skip). *
 * ------------------------------------------------------------------ */
static bool info_is_mblock(const VMStateInfo *i)
{
    return i == &vmstate_info_bool ||
           i == &vmstate_info_int8 || i == &vmstate_info_int16 ||
           i == &vmstate_info_int32 || i == &vmstate_info_int64 ||
           i == &vmstate_info_uint8 || i == &vmstate_info_uint16 ||
           i == &vmstate_info_uint32 || i == &vmstate_info_uint64 ||
           i == &vmstate_info_int32_equal || i == &vmstate_info_uint8_equal ||
           i == &vmstate_info_uint16_equal || i == &vmstate_info_uint32_equal ||
           i == &vmstate_info_uint64_equal || i == &vmstate_info_int32_le ||
           i == &vmstate_info_cpudouble ||
           i == &vmstate_info_buffer;
}

/* Loads nothing into device memory -> nothing to restore. */
static bool info_is_skip(const VMStateInfo *i)
{
    return i == &vmstate_info_unused_buffer || i == &vmstate_info_nullptr;
}

/* ------------------------------------------------------------------ *
 * Walk context + table builders                                       *
 * ------------------------------------------------------------------ */
typedef struct {
    QEMUFile *f;
    GArray   *mblocks;   /* SfMblock: copy captured eagerly, merged when adjacent */
    GArray   *gets;      /* SfGet    */
    GArray   *posts;     /* SfPost   */
    size_t    stream_len;
    Error   **errp;
} SfCtx;

/* Capture live memory [ptr, ptr+size) now; merge into the previous block if it
 * is physically adjacent (fewer, larger memcpys at replay time). */
static void add_mblock(SfCtx *c, void *ptr, size_t size)
{
    if (!size) {
        return;
    }
    if (c->mblocks->len) {
        SfMblock *last = &g_array_index(c->mblocks, SfMblock, c->mblocks->len - 1);
        if ((uint8_t *)last->ptr + last->size == (uint8_t *)ptr) {
            last->copy = g_realloc(last->copy, last->size + size);
            memcpy((uint8_t *)last->copy + last->size, ptr, size);
            last->size += size;
            return;
        }
    }
    SfMblock m = { .ptr = ptr, .size = size, .copy = g_malloc(size) };
    memcpy(m.copy, ptr, size);
    g_array_append_val(c->mblocks, m);
}

/* The info->get already ran and advanced the stream from @pos0 to @pos1; grab
 * that exact slice (rewind + re-read) so replay can re-run info->get on it. */
static bool add_get(SfCtx *c, const VMStateInfo *info, const VMStateField *field,
                    void *ptr, size_t size, size_t pos0, size_t pos1)
{
    size_t len = pos1 - pos0;
    void *cap = len ? g_malloc(len) : NULL;

    if (len) {
        qemu_file_skip(c->f, -(int)len);
        if (qemu_get_buffer(c->f, cap, len) != len) {
            g_free(cap);
            error_setg(c->errp, "sf_preparse: could not capture %zu get bytes for %s",
                       len, field->name);
            return false;
        }
    }
    SfGet g = { .info = info, .field = field, .ptr = ptr,
                .captured = cap, .captured_len = len, .size = size };
    g_array_append_val(c->gets, g);
    return true;
}

static void add_post(SfCtx *c, const VMStateDescription *vmsd, void *opaque,
                     bool is_pre, int version_id)
{
    SfPost p = { .vmsd = vmsd, .opaque = opaque,
                 .is_pre = is_pre, .version_id = version_id };
    g_array_append_val(c->posts, p);
}

/* Replicated from vmstate.c's static vmstate_field_exists (v11, old-version
 * branches dropped). */
static bool sf_field_exists(const VMStateField *field, void *opaque,
                            int version_id)
{
    if (field->field_exists) {
        return field->field_exists(opaque, version_id);
    }
    return field->version_id <= version_id;
}

static int sf_record_vmsd(SfCtx *c, const VMStateDescription *vmsd,
                          void *opaque, int version_id);

/* Mirror of vmstate_subsection_load with recording. */
static int sf_record_subsections(SfCtx *c, const VMStateDescription *vmsd,
                                 void *opaque)
{
    QEMUFile *f = c->f;

    while (qemu_peek_byte(f, 0) == QEMU_VM_SUBSECTION) {
        char idstr[256], *idstr_ret;
        uint8_t len, size, version_id;
        const VMStateDescription *sub;

        len = qemu_peek_byte(f, 1);
        if (len < strlen(vmsd->name) + 1) {
            return 0; /* not our subsection */
        }
        size = qemu_peek_buffer(f, (uint8_t **)&idstr_ret, len, 2);
        if (size != len) {
            return 0;
        }
        memcpy(idstr, idstr_ret, size);
        idstr[size] = 0;
        if (strncmp(vmsd->name, idstr, strlen(vmsd->name)) != 0) {
            return 0;
        }

        /* Locate the sub-VMSD by name in vmsd->subsections. */
        sub = NULL;
        for (const VMStateDescription * const *s = vmsd->subsections;
             s && *s; s++) {
            if (!strcmp(idstr, (*s)->name)) {
                sub = *s;
                break;
            }
        }
        if (!sub) {
            error_setg(c->errp, "sf_preparse: subsection '%s' in '%s' not found",
                       idstr, vmsd->name);
            return -ENOENT;
        }

        qemu_file_skip(f, 1);      /* QEMU_VM_SUBSECTION */
        qemu_file_skip(f, 1);      /* len */
        qemu_file_skip(f, len);    /* idstr */
        version_id = qemu_get_be32(f);

        int ret = sf_record_vmsd(c, sub, opaque, version_id);
        if (ret) {
            return ret;
        }
    }
    return 0;
}

/* Mirror of vmstate_load_state with recording. Runs the stock info->get for
 * each field (advancing the stream, re-applying side effects with identical
 * values) and records where to put each field back on replay. */
static int sf_record_vmsd(SfCtx *c, const VMStateDescription *vmsd,
                          void *opaque, int version_id)
{
    QEMUFile *f = c->f;
    const VMStateField *field = vmsd->fields;

    if (version_id > vmsd->version_id ||
        version_id < vmsd->minimum_version_id) {
        error_setg(c->errp, "sf_preparse: %s version_id %d out of range [%d,%d]",
                   vmsd->name, version_id, vmsd->minimum_version_id,
                   vmsd->version_id);
        return -EINVAL;
    }

    /* pre_load: run it (faithful load) and record it for replay. */
    if (vmsd->pre_load_errp) {
        if (!vmsd->pre_load_errp(opaque, c->errp)) {
            return -EINVAL;
        }
        add_post(c, vmsd, opaque, true, version_id);
    } else if (vmsd->pre_load) {
        int ret = vmsd->pre_load(opaque);
        if (ret) {
            error_setg(c->errp, "sf_preparse: pre_load failed for %s: %d",
                       vmsd->name, ret);
            return ret;
        }
        add_post(c, vmsd, opaque, true, version_id);
    }

    while (field->name) {
        if (sf_field_exists(field, opaque, version_id)) {
            void *first_elem = opaque + field->offset;
            int n_elems = vmstate_n_elems(opaque, field);
            int size = vmstate_size(opaque, field);

            vmstate_handle_alloc(first_elem, field, opaque);
            if (field->flags & VMS_POINTER) {
                first_elem = *(void **)first_elem;
                assert(first_elem || !n_elems || !size);
            }
            for (int i = 0; i < n_elems; i++) {
                void *curr_elem = first_elem + size * i;

                if (field->flags & VMS_ARRAY_OF_POINTER) {
                    curr_elem = *(void **)curr_elem;
                }
                if (!curr_elem && size) {
                    /* Null array-of-pointer entry: stock consumes a nullptr
                     * placeholder. Not expected in the M0-S device set. */
                    error_setg(c->errp, "sf_preparse: null ptr elem in %s/%s "
                               "unsupported", vmsd->name, field->name);
                    return -ENOTSUP;
                }

                if (field->flags & VMS_STRUCT) {
                    int ret = sf_record_vmsd(c, field->vmsd, curr_elem,
                                             field->vmsd->version_id);
                    if (ret) {
                        return ret;
                    }
                } else if (field->flags & VMS_VSTRUCT) {
                    int ret = sf_record_vmsd(c, field->vmsd, curr_elem,
                                             field->struct_version_id);
                    if (ret) {
                        return ret;
                    }
                } else {
                    size_t pos0 = sf_qemu_file_input_pos(f);
                    int ret = field->info->get(f, curr_elem, size, field);
                    if (ret < 0) {
                        error_setg(c->errp, "sf_preparse: get failed %s/%s: %d",
                                   vmsd->name, field->name, ret);
                        return ret;
                    }
                    ret = qemu_file_get_error(f);
                    if (ret < 0) {
                        error_setg(c->errp, "sf_preparse: stream error in %s: %d",
                                   vmsd->name, ret);
                        return ret;
                    }
                    size_t pos1 = sf_qemu_file_input_pos(f);

                    if (info_is_mblock(field->info)) {
                        add_mblock(c, curr_elem, size);
                    } else if (info_is_skip(field->info)) {
                        /* no device state to restore */
                    } else {
                        if (!add_get(c, field->info, field, curr_elem, size,
                                     pos0, pos1)) {
                            return -EIO;
                        }
                    }
                }
            }
        } else if (field->flags & VMS_MUST_EXIST) {
            error_setg(c->errp, "sf_preparse: missing must-exist %s/%s",
                       vmsd->name, field->name);
            return -EINVAL;
        }
        field++;
    }
    assert(field->flags == VMS_END);

    int ret = sf_record_subsections(c, vmsd, opaque);
    if (ret) {
        return ret;
    }

    /* post_load: run it (faithful) and record it for replay. */
    if (vmsd->post_load_errp) {
        if (!vmsd->post_load_errp(opaque, version_id, c->errp)) {
            return -EINVAL;
        }
        add_post(c, vmsd, opaque, false, version_id);
    } else if (vmsd->post_load) {
        ret = vmsd->post_load(opaque, version_id);
        if (ret < 0) {
            error_setg(c->errp, "sf_preparse: post_load failed for %s: %d",
                       vmsd->name, ret);
            return ret;
        }
        add_post(c, vmsd, opaque, false, version_id);
    }
    return 0;
}

/* ------------------------------------------------------------------ *
 * Section lookup: (idstr, instance_id) -> (vmsd, opaque)              *
 * ------------------------------------------------------------------ */
typedef struct {
    const char               *idstr;
    uint32_t                  instance_id;
    const VMStateDescription *vmsd;
    void                     *opaque;
} SfSe;

static void collect_se(const char *idstr, uint32_t instance_id,
                       const VMStateDescription *vmsd, void *opaque, void *user)
{
    GArray *a = user;
    SfSe e = { idstr, instance_id, vmsd, opaque };
    g_array_append_val(a, e);
}

static const SfSe *find_se(GArray *a, const char *idstr, uint32_t instance_id)
{
    for (guint i = 0; i < a->len; i++) {
        SfSe *e = &g_array_index(a, SfSe, i);
        if (e->instance_id == instance_id && !strcmp(e->idstr, idstr)) {
            return e;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
int sf_preparse(SfReplayTables *out, Error **errp)
{
    /* 1. Serialize current device state, reopen as a private input stream.
     * Mirror stock savevm (savevm.c): publish the current runstate into
     * global_state first, else globalstate's post_load rejects an empty one. */
    global_state_store();
    QEMUFile *wf = sf_qemufile_from_buffer_output();
    if (qemu_save_device_state(wf, errp) != 0) {
        qemu_fclose(wf);
        return -1;
    }
    const uint8_t *bytes;
    size_t len;
    sf_qemufile_get_output(wf, &bytes, &len);
    QEMUFile *f = sf_qemufile_from_buffer_input(bytes, len);
    qemu_fclose(wf); /* input holds a private copy */

    GArray *ses = g_array_new(FALSE, FALSE, sizeof(SfSe));
    sf_savevm_for_each_vmsd(collect_se, ses);

    SfCtx c = {
        .f = f,
        .mblocks = g_array_new(FALSE, FALSE, sizeof(SfMblock)),
        .gets = g_array_new(FALSE, FALSE, sizeof(SfGet)),
        .posts = g_array_new(FALSE, FALSE, sizeof(SfPost)),
        .stream_len = len,
        .errp = errp,
    };

    int ret = 0;
    bool checked_single_buffer = false;
    for (;;) {
        uint8_t type = qemu_get_byte(f);
        if (qemu_file_get_error(f)) {
            error_setg(errp, "sf_preparse: stream error reading section type");
            ret = -1;
            break;
        }
        if (!checked_single_buffer) {
            /* M0-S assumption: whole device stream fits one QEMUFile buffer,
             * so buf_index is an absolute read position (see qemu-file.c). */
            if (sf_qemu_file_input_bufsize(f) != len) {
                error_setg(errp, "sf_preparse: device stream %zu > single buffer "
                           "%zu; get-byte capture would desync", len,
                           (size_t)sf_qemu_file_input_bufsize(f));
                ret = -1;
                break;
            }
            checked_single_buffer = true;
        }
        if (type == QEMU_VM_EOF) {
            /* We must have consumed exactly the whole stream: EOF is the last
             * byte, so the read cursor now sits at stream_len. A framing drift
             * would leave it short/long. */
            if (sf_qemu_file_input_pos(f) != len) {
                error_setg(errp, "sf_preparse: consumed %zu of %zu stream bytes "
                           "at EOF (framing drift)",
                           (size_t)sf_qemu_file_input_pos(f), len);
                ret = -1;
            }
            break;
        }
        if (type != QEMU_VM_SECTION_FULL) {
            error_setg(errp, "sf_preparse: unexpected section type 0x%x "
                       "(device state should be FULL-only)", type);
            ret = -1;
            break;
        }

        (void)qemu_get_be32(f); /* section_id */
        char idstr[256];
        if (!qemu_get_counted_string(f, idstr)) {
            error_setg(errp, "sf_preparse: could not read section idstr");
            ret = -1;
            break;
        }
        uint32_t instance_id = qemu_get_be32(f);
        uint32_t sec_version = qemu_get_be32(f);

        const SfSe *se = find_se(ses, idstr, instance_id);
        if (!se || !se->vmsd) {
            error_setg(errp, "sf_preparse: no VMSD for section '%s' inst %u",
                       idstr, instance_id);
            ret = -1;
            break;
        }

        ret = sf_record_vmsd(&c, se->vmsd, se->opaque, sec_version);
        if (ret) {
            break;
        }

        /* Optional section footer (config-dependent); consume if present. */
        if (qemu_peek_byte(f, 0) == QEMU_VM_SECTION_FOOTER) {
            qemu_file_skip(f, 1);
            (void)qemu_get_be32(f);
        }
    }

    qemu_fclose(f);
    g_array_free(ses, TRUE);

    if (ret) {
        /* free partial copies then the arrays */
        for (guint i = 0; i < c.mblocks->len; i++) {
            g_free(g_array_index(c.mblocks, SfMblock, i).copy);
        }
        for (guint i = 0; i < c.gets->len; i++) {
            g_free(g_array_index(c.gets, SfGet, i).captured);
        }
        g_array_free(c.mblocks, TRUE);
        g_array_free(c.gets, TRUE);
        g_array_free(c.posts, TRUE);
        return ret;
    }

    out->n_mblocks = c.mblocks->len;
    out->n_gets = c.gets->len;
    out->n_posts = c.posts->len;
    out->mblocks = (SfMblock *)g_array_free(c.mblocks, FALSE);
    out->gets = (SfGet *)g_array_free(c.gets, FALSE);
    out->posts = (SfPost *)g_array_free(c.posts, FALSE);
    return 0;
}

void sf_replay_tables_destroy(SfReplayTables *t)
{
    if (!t) {
        return;
    }
    for (size_t i = 0; i < t->n_mblocks; i++) {
        g_free(t->mblocks[i].copy);
    }
    for (size_t i = 0; i < t->n_gets; i++) {
        g_free(t->gets[i].captured);
    }
    g_free(t->mblocks);
    g_free(t->gets);
    g_free(t->posts);
    memset(t, 0, sizeof(*t));
}
