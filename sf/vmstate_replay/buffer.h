/*
 * sf/vmstate_replay/buffer — wrap an in-memory byte buffer as a QEMUFile.
 *
 * The pre-parse / replay path consumes a stock device-state stream once and
 * replays it many times, so it needs QEMUFiles backed by memory rather than a
 * socket/fd. v11 dropped qemu_fopen_ops, so we build directly on
 * QIOChannelBuffer + qemu_file_new_input/output.
 *
 * Include qemu/osdep.h before this header.
 */
#ifndef SF_VMSTATE_REPLAY_BUFFER_H
#define SF_VMSTATE_REPLAY_BUFFER_H

/* QEMUFile is declared in qemu/typedefs.h (pulled in by qemu/osdep.h). */

/*
 * New writable QEMUFile backed by a fresh, empty in-memory buffer. Write with
 * qemu_put_buffer()/qemu_put_byte(); recover the bytes with
 * sf_qemufile_get_output(). Free with qemu_fclose() (frees the buffer too).
 */
QEMUFile *sf_qemufile_from_buffer_output(void);

/*
 * New read-only QEMUFile over a private copy of [data, data+len). Read with
 * qemu_get_buffer()/qemu_get_byte(). Free with qemu_fclose().
 */
QEMUFile *sf_qemufile_from_buffer_input(const void *data, size_t len);

/*
 * Flush @f and hand back a view of the bytes written so far. The pointer aliases
 * the QEMUFile's internal buffer and is valid until the next write or qemu_fclose().
 * @f must have come from sf_qemufile_from_buffer_output().
 */
void sf_qemufile_get_output(QEMUFile *f, const uint8_t **data, size_t *len);

#endif /* SF_VMSTATE_REPLAY_BUFFER_H */
