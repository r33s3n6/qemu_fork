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

typedef enum {
    SF_CTL_CONTINUE,     /* c / continue       — resume to next boundary */
    SF_CTL_SNAPSHOT,     /* s / snapshot        — save here, stay parked */
    SF_CTL_RESTORE,      /* r / restore [id]    — restore + resume */
    SF_CTL_COLDSTART,    /* C / cold-start <dir> [id] — load from disk + resume */
    SF_CTL_GATE,         /* g / gate <a|d|s>    — set guest checkpoint gate */
    SF_CTL_TIMEOUT,       /* T / timeout <ms>    — set next resume timeout (0=inf) */
    SF_CTL_BAD,          /* unparseable / unknown */
} SfCtlCmdKind;

typedef enum {
    SF_CTL_GATE_ALLOW,     /* default: guest may self snapshot/restore/stop */
    SF_CTL_GATE_DISABLE,    /* any guest cmd yields -> 'c' (host decides) */
    SF_CTL_GATE_STRICT,     /* non-stop guest cmd panics -> 'x' */
} SfCtlGateMode;

typedef struct {
    SfCtlCmdKind   kind;
    bool           has_id;
    uint32_t       id;
    char           dir[1024];    /* cold-start dir; empty otherwise */
    SfCtlGateMode  gmode;         /* SF_CTL_GATE */
    int64_t        timeout_ms;    /* SF_CTL_TIMEOUT (0 = infinite) */
} SfCtlCmd;

/* Look for the control chardev (id "sfctl") and attach handlers. Called once at
 * machine_init_done (from sf/checkpoint.c). No-op if the chardev is absent. */
void sf_control_init(void);

/* True once the control channel is attached. When false the guest CHECKPOINT port
 * keeps its standalone guest-driven behavior (sf/checkpoint.c). */
bool sf_control_active(void);

/* Send a response line (must include '\n'). Called from gate.c (both dispatch
 * contexts). */
void sf_control_reply(const char *line);

#endif /* SF_CONTROL_CHANNEL_H */