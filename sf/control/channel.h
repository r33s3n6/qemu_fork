/*
 * sf/control/channel — host control channel (M3 control-plane, slice 6b).
 * Design: research/plans/2026-07-07-m3-control-channel.md §1–§4, §5.6.
 *
 * One chardev (unix socket; host = client, QEMU = endpoint) carries newline-framed
 * host commands and QEMU responses. The vcpu boundary (sf/checkpoint.c) parks the
 * guest and drives the command loop via the primitives here. The socket is owned by
 * the main loop (chardev read/event callbacks); the vcpu thread only waits on a
 * condvar — so the boundary can block for a command WITHOUT holding the BQL (slice
 * 6a made the boundary BQL-free). Attach = a -chardev with id "sfctl" exists.
 *
 * Include qemu/osdep.h before this header.
 *
 * Clean-room: no QEMU-Nyx code.
 */
#ifndef SF_CONTROL_CHANNEL_H
#define SF_CONTROL_CHANNEL_H

typedef enum {
    SF_CTL_CONTINUE,     /* c / continue   — resume to next boundary */
    SF_CTL_SNAPSHOT,     /* s / snapshot   — save here, stay parked */
    SF_CTL_RESTORE,      /* r / restore [id] — restore + resume */
    SF_CTL_COLDSTART,    /* C / cold-start <dir> [id] — load from disk + resume */
    SF_CTL_BAD,          /* unparseable / unknown */
} SfCtlCmdKind;

typedef struct {
    SfCtlCmdKind kind;
    bool         has_id;
    uint32_t     id;
    char         dir[1024];   /* cold-start dir; empty otherwise */
} SfCtlCmd;

/* Look for the control chardev (id "sfctl") and attach handlers. Called once at
 * machine_init_done (from sf/checkpoint.c). No-op if the chardev is absent. */
void sf_control_init(void);

/* True once the control channel is attached. When false the guest CHECKPOINT port
 * keeps its standalone guest-driven behavior (sf/checkpoint.c). */
bool sf_control_active(void);

/* ---- vcpu-thread boundary primitives (called from sf_cp_write; BQL not held) ---- */
void sf_control_boundary_enter(void);    /* mark at-boundary; (re)send 'c' once connected */
void sf_control_boundary_exit(void);     /* leaving the boundary (guest resumes) */
void sf_control_recv(SfCtlCmd *out);     /* block until one command line is parsed */
void sf_control_reply(const char *line); /* send a response line (must include '\n') */

#endif /* SF_CONTROL_CHANNEL_H */
