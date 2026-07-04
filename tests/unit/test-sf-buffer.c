/*
 * Unit test for sf/vmstate_replay/buffer — in-memory buffer <-> QEMUFile.
 *
 * Discriminates real behaviour: bytes written to an output QEMUFile must come
 * back identical from sf_qemufile_get_output(), and an input QEMUFile built over
 * those bytes must read them back identical. A no-op helper would fail these.
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "migration/qemu-file-types.h"
#include "migration/qemu-file.h"
#include "sf/vmstate_replay/buffer.h"

/* A deterministic byte pattern that is not all-zero and spans > 1 chunk. */
static void fill_pattern(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i * 31 + 7);
    }
}

/* Write known bytes to an output QEMUFile, read them back via get_output. */
static void test_output_roundtrip(void)
{
    enum { N = 4096 + 123 };
    g_autofree uint8_t *in = g_malloc(N);
    fill_pattern(in, N);

    QEMUFile *f = sf_qemufile_from_buffer_output();
    qemu_put_buffer(f, in, N);
    qemu_put_byte(f, 0xA5);

    const uint8_t *out;
    size_t out_len;
    sf_qemufile_get_output(f, &out, &out_len);

    g_assert_cmpuint(out_len, ==, N + 1);
    g_assert_cmpint(memcmp(out, in, N), ==, 0);
    g_assert_cmpuint(out[N], ==, 0xA5);

    qemu_fclose(f);
}

/* Build an input QEMUFile over known bytes, read them back. */
static void test_input_readback(void)
{
    enum { N = 4096 + 123 };
    g_autofree uint8_t *src = g_malloc(N);
    g_autofree uint8_t *got = g_malloc(N);
    fill_pattern(src, N);

    QEMUFile *f = sf_qemufile_from_buffer_input(src, N);
    size_t r = qemu_get_buffer(f, got, N);

    g_assert_cmpuint(r, ==, N);
    g_assert_cmpint(memcmp(got, src, N), ==, 0);
    g_assert_cmpint(qemu_file_get_error(f), ==, 0);

    qemu_fclose(f);
}

/* Input file keeps a private copy: mutating the caller's buffer must not leak. */
static void test_input_is_private_copy(void)
{
    enum { N = 256 };
    g_autofree uint8_t *src = g_malloc(N);
    g_autofree uint8_t *got = g_malloc(N);
    fill_pattern(src, N);

    QEMUFile *f = sf_qemufile_from_buffer_input(src, N);
    memset(src, 0, N);                 /* clobber caller buffer after construction */

    size_t r = qemu_get_buffer(f, got, N);
    g_assert_cmpuint(r, ==, N);

    fill_pattern(src, N);              /* restore expected pattern to compare */
    g_assert_cmpint(memcmp(got, src, N), ==, 0);

    qemu_fclose(f);
}

/* Full snapshot->replay shape: output bytes feed a fresh input file. */
static void test_output_to_input(void)
{
    enum { N = 8192 };
    g_autofree uint8_t *in = g_malloc(N);
    g_autofree uint8_t *got = g_malloc(N);
    fill_pattern(in, N);

    QEMUFile *wf = sf_qemufile_from_buffer_output();
    qemu_put_buffer(wf, in, N);
    const uint8_t *bytes;
    size_t len;
    sf_qemufile_get_output(wf, &bytes, &len);
    g_assert_cmpuint(len, ==, N);

    QEMUFile *rf = sf_qemufile_from_buffer_input(bytes, len);
    g_assert_cmpuint(qemu_get_buffer(rf, got, N), ==, N);
    g_assert_cmpint(memcmp(got, in, N), ==, 0);

    qemu_fclose(rf);   /* free input copy before wf's aliased bytes go away */
    qemu_fclose(wf);
}

/* Empty output file yields zero-length, non-crashing readback. */
static void test_output_empty(void)
{
    QEMUFile *f = sf_qemufile_from_buffer_output();
    const uint8_t *out;
    size_t len;
    sf_qemufile_get_output(f, &out, &len);
    g_assert_cmpuint(len, ==, 0);
    qemu_fclose(f);
}

int main(int argc, char **argv)
{
    module_call_init(MODULE_INIT_QOM);
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/sf/buffer/output-roundtrip", test_output_roundtrip);
    g_test_add_func("/sf/buffer/input-readback", test_input_readback);
    g_test_add_func("/sf/buffer/input-private-copy", test_input_is_private_copy);
    g_test_add_func("/sf/buffer/output-to-input", test_output_to_input);
    g_test_add_func("/sf/buffer/output-empty", test_output_empty);
    return g_test_run();
}
