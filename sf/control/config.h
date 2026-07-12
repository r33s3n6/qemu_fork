/*
 * sf/control/config — host-control startup configuration (M3 control-plane v2).
 * Design: research/plans/2026-07-11-04-host-control-v2-binary-pipe-common-private.md §2.1.
 *
 * The high-speed pipe (channel.c/gate.c) carries only the hot per-boundary verbs
 * with no dir argument. The low-frequency, set-once configuration — snapshot
 * dirs, resume timeout, gate mode, whether/where to cold-start at boot — lives
 * here, read from the environment at machine_init_done (the same env idiom as
 * SF_ROOT_DIR/SF_CP_SKIP; the experiment wrapper sets these before launch). A
 * debug HMP (sf_config) can change them at runtime for flexibility.
 *
 * Env keys (all optional):
 *   SF_COMMON_DIR          read-only shared base dir (empty = none; single-dir
 *                          when == SF_PRIVATE_DIR or when only one is set)
 *   SF_PRIVATE_DIR         worker's writable dir (persist/promote target)
 *   SF_RESUME_TIMEOUT_MS   next-resume timeout, 0 = infinite (default 0)
 *   SF_GATE                a=ALLOW (default) / d=DISABLE / s=STRICT
 *   SF_RESTORE_FAIL_POLICY panic (default) / notify / pause — how a restore
 *                          failure (bad id / engine error) is handled. A failed
 *                          restore is never papered over with a guest sentinel:
 *                          the guest is powerless, so fail loud at the host level.
 *   SF_COLD_START_ON_BOOT  1 = auto cold-start at boot; 0 = fresh boot (default 0)
 *   SF_INITIAL_NODE        cold-start restore target node id (default 0)
 *
 * Include qemu/osdep.h before this header. Clean-room: no QEMU-Nyx code.
 */
#ifndef SF_CONTROL_CONFIG_H
#define SF_CONTROL_CONFIG_H

#include "sf/control/channel.h"   /* SfCtlGateMode */

/* How a restore failure is handled (SF_RESTORE_FAIL_POLICY). A failed restore
 * (bad id / engine error) is fatal to the run — never a guest-visible sentinel. */
typedef enum {
    SF_RFP_PANIC = 0,   /* default: error_report + abort */
    SF_RFP_NOTIFY,      /* reply SF_ST_ERROR to the host pipe + park; no chardev -> panic */
    SF_RFP_PAUSE,       /* vm_stop(PAUSED) — freeze the VM for manual triage (HMP/gdb) */
} SfRestoreFailPolicy;

typedef struct {
    char          common_dir[1024];
    char          private_dir[1024];
    int64_t       resume_timeout_ms;   /* 0 = infinite */
    SfCtlGateMode gate_mode;
    SfRestoreFailPolicy restore_fail_policy;
    bool          cold_start_on_boot;
    uint32_t      initial_node;
} SfConfig;

/* Load config from the environment (once, at machine_init_done). Idempotent. */
void sf_config_load(void);

/* The live config (never NULL after sf_config_load; zero-valued before). */
const SfConfig *sf_config(void);

/* Runtime setter for the debug HMP `sf_config <key> <val>`. Returns 0 on success,
 * -1 on unknown key / bad value (errp set). Keys match the env suffix lowercased:
 * common_dir/private_dir/resume_timeout_ms/gate/cold_start_on_boot/initial_node. */
int sf_config_set(const char *key, const char *val, Error **errp);

#endif /* SF_CONTROL_CONFIG_H */
