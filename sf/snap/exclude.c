/*
 * sf/snap/exclude — NO_RESTORE exclusion region table. See exclude.h.
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "sf/snap/exclude.h"

typedef struct SfExclRange {
    uint64_t host_start;
    uint64_t host_end;   /* exclusive */
    uint32_t buf_id;
} SfExclRange;

static SfExclRange *g_excl;
static size_t       g_excl_n;
static size_t       g_excl_cap;

void sf_exclude_clear(void)
{
    g_free(g_excl);
    g_excl = NULL;
    g_excl_n = 0;
    g_excl_cap = 0;
}

size_t sf_exclude_count(void)
{
    return g_excl_n;
}

bool sf_exclude_get(size_t i, uint64_t *host_start, uint64_t *size,
                    uint32_t *buf_id)
{
    if (i >= g_excl_n) {
        return false;
    }
    *host_start = g_excl[i].host_start;
    *size = g_excl[i].host_end - g_excl[i].host_start;
    *buf_id = g_excl[i].buf_id;
    return true;
}

void sf_exclude_add(uint64_t host_start, uint64_t size, uint32_t buf_id)
{
    size_t psize = qemu_real_host_page_size();

    /* Page-aligned registration (plan -06 §1: 页粒度断言). */
    if (host_start & (psize - 1)) {
        error_report("sf_exclude_add: host_start %lx not page-aligned", host_start);
        return;
    }
    if (size & (psize - 1)) {
        error_report("sf_exclude_add: size %lx not page-aligned", size);
        return;
    }
    if (size == 0) {
        return;
    }

    if (g_excl_n == g_excl_cap) {
        g_excl_cap = g_excl_cap ? g_excl_cap * 2 : 8;
        g_excl = g_renew(SfExclRange, g_excl, g_excl_cap);
    }
    g_excl[g_excl_n].host_start = host_start;
    g_excl[g_excl_n].host_end = host_start + size;
    g_excl[g_excl_n].buf_id = buf_id;
    g_excl_n++;

    /* Keep sorted by host_start so sf_excluded is a binary search. */
    for (size_t i = g_excl_n - 1; i > 0; i--) {
        if (g_excl[i - 1].host_start > g_excl[i].host_start) {
            SfExclRange tmp = g_excl[i - 1];
            g_excl[i - 1] = g_excl[i];
            g_excl[i] = tmp;
        } else {
            break;
        }
    }
}

static int sf_excl_find(uint64_t host)
{
    /* Lower-bound binary search; then check the candidate range. */
    size_t lo = 0, hi = g_excl_n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (host < g_excl[mid].host_start) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    /* lo points just past the candidate; the candidate is lo-1. */
    if (lo == 0) {
        return -1;
    }
    size_t i = lo - 1;
    if (host >= g_excl[i].host_start && host < g_excl[i].host_end) {
        return (int)i;
    }
    return -1;
}

bool sf_excluded(const void *host)
{
    if (g_excl_n == 0) {
        return false;
    }
    return sf_excl_find((uint64_t)(uintptr_t)host) >= 0;
}

/* ---- registered-buffer shared-file backing (plan 04 §2.4 / S5) ---- */

char *sf_buf_path(const char *dir, uint32_t buf_id)
{
    char name[32];
    snprintf(name, sizeof(name), "bufs/%u.buf", buf_id);
    return g_build_filename(dir, name, NULL);
}

static int sf_buf_write_all(int fd, const void *buf, size_t len)
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

int sf_buf_remap(uint64_t host, uint64_t size, uint32_t buf_id,
                 const char *dir, bool create, bool map_fixed, Error **errp)
{
    char *path, *bdir;
    int fd, ret = -1;
    void *p;

    if (!dir || !*dir) {
        error_setg(errp, "sf_buf_remap: no workdir for buf %u", buf_id);
        return -1;
    }
    if (create) {
        bdir = g_build_filename(dir, "bufs", NULL);
        ret = g_mkdir_with_parents(bdir, 0700);
        g_free(bdir);
        if (ret < 0) {
            error_setg_errno(errp, errno, "sf_buf_remap: mkdir bufs/");
            return -1;
        }
        ret = -1;
    }
    path = sf_buf_path(dir, buf_id);
    fd = open(path, create ? (O_RDWR | O_CREAT | O_TRUNC) : O_RDWR, 0600);
    if (fd < 0) {
        error_setg_errno(errp, errno, "sf_buf_remap: open %s", path);
        goto out;
    }
    if (create) {
        if (ftruncate(fd, (off_t)size) < 0) {
            error_setg_errno(errp, errno, "sf_buf_remap: ftruncate %s", path);
            goto out;
        }
        /* Seed the file with the buffer's current bytes before the mapping is
         * replaced, so anything the guest already wrote survives the remap. */
        if (sf_buf_write_all(fd, (const void *)(uintptr_t)host, size) < 0) {
            error_setg_errno(errp, errno, "sf_buf_remap: seed %s", path);
            goto out;
        }
    }
    if (map_fixed) {
        p = mmap((void *)(uintptr_t)host, size, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_FIXED, fd, 0);
        if (p == MAP_FAILED) {
            error_setg_errno(errp, errno, "sf_buf_remap: mmap %s", path);
            goto out;
        }
        if (p != (void *)(uintptr_t)host) {
            error_setg(errp, "sf_buf_remap: mmap moved %p != %p", p,
                       (void *)(uintptr_t)host);
            goto out;
        }
    }
    ret = 0;
out:
    if (fd >= 0) {
        close(fd);   /* the mapping keeps the file alive; a control process
                      * reopens it by path for its own MAP_SHARED view. */
    }
    g_free(path);
    return ret;
}