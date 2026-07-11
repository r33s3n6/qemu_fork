/*
 * sf/control/config — host-control startup configuration. See config.h.
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "sf/control/config.h"

static SfConfig sf_cfg;
static bool sf_cfg_loaded;

static void copy_env_str(char *dst, size_t cap, const char *env)
{
    const char *v = getenv(env);
    dst[0] = '\0';
    if (v && v[0]) {
        /* Truncation would silently point at the wrong dir; refuse instead. */
        if (strlen(v) >= cap) {
            error_report("sf-config: %s too long (>= %zu)", env, cap);
            exit(1);
        }
        g_strlcpy(dst, v, cap);
    }
}

static SfCtlGateMode parse_gate(const char *v)
{
    if (!v || !v[0]) {
        return SF_CTL_GATE_ALLOW;
    }
    switch (v[0]) {
    case 'a': return SF_CTL_GATE_ALLOW;
    case 'd': return SF_CTL_GATE_DISABLE;
    case 's': return SF_CTL_GATE_STRICT;
    default:
        error_report("sf-config: SF_GATE=%s invalid (a|d|s)", v);
        exit(1);
    }
}

void sf_config_load(void)
{
    if (sf_cfg_loaded) {
        return;
    }
    copy_env_str(sf_cfg.common_dir, sizeof(sf_cfg.common_dir), "SF_COMMON_DIR");
    copy_env_str(sf_cfg.private_dir, sizeof(sf_cfg.private_dir), "SF_PRIVATE_DIR");

    const char *t = getenv("SF_RESUME_TIMEOUT_MS");
    sf_cfg.resume_timeout_ms = (t && t[0]) ? g_ascii_strtoll(t, NULL, 10) : 0;
    if (sf_cfg.resume_timeout_ms < 0) {
        sf_cfg.resume_timeout_ms = 0;
    }

    sf_cfg.gate_mode = parse_gate(getenv("SF_GATE"));

    const char *cs = getenv("SF_COLD_START_ON_BOOT");
    sf_cfg.cold_start_on_boot = (cs && cs[0] == '1');

    const char *n = getenv("SF_INITIAL_NODE");
    sf_cfg.initial_node = (n && n[0]) ? (uint32_t)g_ascii_strtoull(n, NULL, 10) : 0;

    sf_cfg_loaded = true;
}

const SfConfig *sf_config(void)
{
    return &sf_cfg;
}

const char *sf_config_boot_dir(void)
{
    if (sf_cfg.common_dir[0]) {
        return sf_cfg.common_dir;
    }
    return sf_cfg.private_dir;   /* "" if neither set */
}

int sf_config_set(const char *key, const char *val, Error **errp)
{
    if (!strcmp(key, "common_dir")) {
        if (strlen(val) >= sizeof(sf_cfg.common_dir)) {
            error_setg(errp, "common_dir too long");
            return -1;
        }
        g_strlcpy(sf_cfg.common_dir, val, sizeof(sf_cfg.common_dir));
    } else if (!strcmp(key, "private_dir")) {
        if (strlen(val) >= sizeof(sf_cfg.private_dir)) {
            error_setg(errp, "private_dir too long");
            return -1;
        }
        g_strlcpy(sf_cfg.private_dir, val, sizeof(sf_cfg.private_dir));
    } else if (!strcmp(key, "resume_timeout_ms")) {
        int64_t ms = g_ascii_strtoll(val, NULL, 10);
        sf_cfg.resume_timeout_ms = ms < 0 ? 0 : ms;
    } else if (!strcmp(key, "gate")) {
        if (val[0] != 'a' && val[0] != 'd' && val[0] != 's') {
            error_setg(errp, "gate must be a|d|s");
            return -1;
        }
        sf_cfg.gate_mode = parse_gate(val);
    } else if (!strcmp(key, "cold_start_on_boot")) {
        sf_cfg.cold_start_on_boot = (val[0] == '1');
    } else if (!strcmp(key, "initial_node")) {
        sf_cfg.initial_node = (uint32_t)g_ascii_strtoull(val, NULL, 10);
    } else {
        error_setg(errp, "unknown config key: %s", key);
        return -1;
    }
    return 0;
}
