/*
 * sf/vmstate_replay/buffer — in-memory buffer <-> QEMUFile helpers.
 * See buffer.h for the contract.
 */
#include "qemu/osdep.h"
#include "io/channel-buffer.h"
#include "migration/qemu-file.h"
#include "sf/vmstate_replay/buffer.h"

QEMUFile *sf_qemufile_from_buffer_output(void)
{
    QIOChannelBuffer *bioc = qio_channel_buffer_new(0);
    QEMUFile *f = qemu_file_new_output(QIO_CHANNEL(bioc));

    /* The QEMUFile now holds the only reference we care about. */
    object_unref(OBJECT(bioc));
    return f;
}

QEMUFile *sf_qemufile_from_buffer_input(const void *data, size_t len)
{
    QIOChannelBuffer *bioc = qio_channel_buffer_new(len);

    if (len) {
        memcpy(bioc->data, data, len);
        bioc->usage = len;
    }
    bioc->offset = 0;

    QEMUFile *f = qemu_file_new_input(QIO_CHANNEL(bioc));
    object_unref(OBJECT(bioc));
    return f;
}

void sf_qemufile_get_output(QEMUFile *f, const uint8_t **data, size_t *len)
{
    QIOChannelBuffer *bioc;

    /* Push anything still sitting in the QEMUFile's own buffer into the channel. */
    qemu_fflush(f);

    bioc = QIO_CHANNEL_BUFFER(qemu_file_get_ioc(f));
    *data = bioc->data;
    *len = bioc->usage;
}
