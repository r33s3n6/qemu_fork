/*
 * sf/control/channel — host control channel transport (M3 control-plane).
 * Design: research/plans/2026-07-07-m3-control-channel.md §1/§2, §5.6.
 *
 * One chardev (unix socket; host = client, QEMU = endpoint) carries newline-framed
 * host commands and QEMU responses. This file is the WIRING only: chardev
 * frontend, line buffer, command parse, and the response write. The BRAIN — the
 * parking state machine, gate, timeout timer, and the two dispatch contexts —
 * lives in gate.c. The vcpu boundary (sf/checkpoint.c) parks via sf_gate_recv;
 * the chardev read callback hands a parsed line to sf_gate_route, which decides
 * whether to dispatch it on the main loop (STOPPED_TIMEOUT) or hand it to the
 * parked vcpu (PARKED_*). Attach = a -chardev with id "sfctl" exists.
 *
 * Include qemu/osdep.h before this header.
 *
 * Clean-room: no QEMU-Nyx code.
 */
#ifndef SF_CONTROL_CHANNEL_H
#define SF_CONTROL_CHANNEL_H

/* Binary pipe (v2, §2.1): fixed 5-byte command frame [op:u8][arg:u32 LE]; the
 * op byte reuses the ASCII verb letter for debuggability. gate mode + resume
 * timeout are now startup config (sf/control/config.h), not pipe commands;
 * cold-start is a boot action (§2.3), not a pipe command. */
typedef enum {
    SF_CTL_CONTINUE = 'c',   /* resume to next boundary */
    SF_CTL_SNAPSHOT = 's',   /* save here (RAM), stay parked; reply s <id> */
    SF_CTL_SNAPSHOT_PERSIST = 'S', /* save here straight to disk (durable, non-root);
                                    * skips promote's 2nd copy. stay parked; reply s <id> */
    SF_CTL_RESTORE  = 'r',   /* restore [arg=id, 0xFFFFFFFF=active] + resume */
    /* v2.1 letter swap: promote is the hot single-node op → lowercase; persist is
     * the low-frequency batch op → uppercase. Enum value IS the wire byte, so the
     * dispatch (by enum name) follows automatically. */
    SF_CTL_PROMOTE  = 'p',   /* promote [arg=id/active] to private_dir; stay parked */
    SF_CTL_PERSIST  = 'P',   /* persist tree to configured private_dir; stay parked */
    SF_CTL_BAD      = 0,     /* unknown op */
} SfCtlCmdKind;

/* Guest-agency gate at a checkpoint boundary. Startup config (SF_GATE); no longer
 * a pipe command. */
typedef enum {
    SF_CTL_GATE_ALLOW,     /* default: guest may self snapshot/restore/stop */
    SF_CTL_GATE_DISABLE,    /* any guest cmd yields -> 'c' (host decides) */
    SF_CTL_GATE_STRICT,     /* non-stop guest cmd panics -> 'x' */
} SfCtlGateMode;

/* arg sentinel: "no id, use active". Node ids are small, 0xFFFFFFFF is safe. */
#define SF_CTL_NO_ID 0xFFFFFFFFu

typedef struct {
    SfCtlCmdKind kind;
    bool         has_id;
    uint32_t     id;
} SfCtlCmd;

/* Response status byte (payload u32: node id for 's', SfCtlErr for 'e', else 0). */
typedef enum {
    SF_ST_CHECKPOINT = 'c',   /* parked at boundary; host decides next */
    SF_ST_TIMEOUT    = 't',   /* mid-flight timeout stop */
    SF_ST_CRASH      = 'x',   /* STRICT panic / crash */
    SF_ST_SNAPSHOT   = 's',   /* snapshot done; payload = new node id */
    SF_ST_OK         = 'o',   /* config-class ok (persist/promote) */
    SF_ST_ERROR      = 'e',   /* payload = SfCtlErr */
} SfCtlStatus;

typedef enum {
    SF_ERR_NONE = 0,
    SF_ERR_INVALID_STATE,
    SF_ERR_NO_SNAPSHOT,
    SF_ERR_RESTORE_FAILED,
    SF_ERR_PERSIST_FAILED,
    SF_ERR_PROMOTE_FAILED,
    SF_ERR_BAD_COMMAND,
    SF_ERR_BAD_FRAME,
} SfCtlErr;

/* Look for the control chardev (id "sfctl") and attach handlers. Called once at
 * machine_init_done (from sf/checkpoint.c). No-op if the chardev is absent. */
void sf_control_init(void);

/* True once the control channel is attached. When false the guest CHECKPOINT port
 * keeps its standalone guest-driven behavior (sf/checkpoint.c). */
bool sf_control_active(void);

/* Send a 5-byte response frame [status:u8][payload:u32 LE]. Called from gate.c
 * (both dispatch contexts). */
void sf_control_reply(uint8_t status, uint32_t payload);

#endif /* SF_CONTROL_CHANNEL_H */