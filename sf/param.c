/*
 * sf/param — predefined host→guest parameter region. See param.h.
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "sf/param.h"
#include "sf/snap/node.h"        /* sf_gpa_to_host */
#include "sf/snap/exclude.h"     /* sf_exclude_add / sf_buf_remap */
#include "sf/control/config.h"   /* sf_config: tsc_khz / scale_ppm / scale_str / private_dir */

static void sf_param_write_header(void *host)
{
    const SfConfig *c = sf_config();
    uint8_t *p = host;
    uint32_t magic = SF_PARAM_MAGIC;
    uint64_t khz = c->tsc_khz;
    uint32_t ppm = c->scale_ppm;
    char str[SF_PARAM_SCALE_STR_LEN];

    memset(str, 0, sizeof(str));
    g_strlcpy(str, c->scale_str, sizeof(str)); /* NUL-terminated; rest stays 0 */

    memcpy(p + SF_PARAM_MAGIC_OFF, &magic, sizeof(magic));
    memcpy(p + SF_PARAM_TSC_KHZ_OFF, &khz, sizeof(khz));
    memcpy(p + SF_PARAM_SCALE_PPM_OFF, &ppm, sizeof(ppm));
    memcpy(p + SF_PARAM_SCALE_STR_OFF, str, sizeof(str));
}

void sf_param_stamp_header(void)
{
    void *host = sf_gpa_to_host(SF_PARAM_GPA);
    if (!host) {
        error_report("sf-param: GPA 0x%x not in RAM at stamp", SF_PARAM_GPA);
        return;
    }
    sf_param_write_header(host);
}

void sf_param_setup(void)
{
    void *host = sf_gpa_to_host(SF_PARAM_GPA);
    const char *workdir;

    if (!host) {
        error_report("sf-param: GPA 0x%x not in RAM", SF_PARAM_GPA);
        return;
    }
    sf_exclude_add((uint64_t)(uintptr_t)host, SF_PARAM_SIZE, SF_PARAM_BUF_ID);

    /* File-back the region (MAP_SHARED) when a workdir exists, so the region
     * persists as bufs/<id>.buf for cold-start remap and an out-of-process
     * controller can reach the scenario-owned TAIL. Standalone (no private_dir)
     * keeps the plain guest-RAM excluded page — enough for the HEADER read. */
    workdir = sf_config()->private_dir;
    if (workdir[0]) {
        Error *err = NULL;
        /* SF_BUF_NO_REMAP = S5 tooth: create+seed the file but skip MAP_FIXED, so a
         * host write cannot reach the guest page (proves the remap is load-bearing). */
        bool map_fixed = !getenv("SF_BUF_NO_REMAP");
        if (sf_buf_remap((uint64_t)(uintptr_t)host, SF_PARAM_SIZE, SF_PARAM_BUF_ID,
                         workdir, true, map_fixed, &err) < 0) {
            error_report("sf-param: buf remap failed: %s", error_get_pretty(err));
            error_free(err);
        }
    }
    sf_param_write_header(host);
    fprintf(stderr, "sf-param: region gpa=0x%x size=%u buf_id=%u host=%p scale=%s\n",
            SF_PARAM_GPA, SF_PARAM_SIZE, SF_PARAM_BUF_ID, host,
            sf_config()->scale_str);
}
