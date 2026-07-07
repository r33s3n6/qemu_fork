/*
 * sf/control/gate — guest-agency gate + QEMU-internal timeout (M3 control-plane
 * slice 7). Design: research/plans/2026-07-07-m3-control-channel.md §3/§4/§5
 * (slice 7), arch/control-channel.md §3/§4.
 *
 * Slice 6 parked the vcpu at the CHECKPOINT boundary and let the host drive,
 * ignoring the guest's port-write value. Slice 7 gives that value meaning via the
 * gate (ALLOW/DISABLE/STRICT) and adds a timeout timer whose fire is a mid-flight
 * stop distinct from a checkpoint boundary.
 *
 * Two dispatch contexts (plan gap this file closes): the boundary dispatch runs on
 * the vcpu thread (the guest wrote the port, parked in cond_wait); the stopped
 * dispatch runs on the main loop (the timer fired vm_stop, so the vcpu is parked
 * in stock QEMU's cpu-run loop, NOT in our cond_wait — §5.6 forbids patching
 * kvm-all.c to re-route it). Both are driven by the same channel; the host sees a
 * single serialized stop reason and never the race (plan §4).
 *
 * The state machine (below) lives here and is guarded by the channel's mutex
 * (sf_channel_lock/unlock, see channel.c). channel.c's read callback routes a
 * parsed command by state: STOPPED_TIMEOUT -> sf_gate_stopped_cmd here;
 * PARKED_* -> condvar handoff to the vcpu boundary loop; RUNNING -> dropped.
 *
 * Include qemu/osdep.h before this header. Clean-room: no QEMU-Nyx code.
 */
#ifndef SF_CONTROL_GATE_H
#define SF_CONTROL_GATE_H

#include "sf/control/channel.h"   /* SfCtlCmd */

/* Parking state of the control plane (guarded by the channel mutex). */
typedef enum {
    SF_CS_RUNNING,            /* resume in flight, timer armed; no host cmd accepted */
    SF_CS_PARKED_CHECKPOINT,   /* vcpu at boundary cond_wait; snapshot OK; owed reply 'c' */
    SF_CS_PARKED_SNAPSHOT,     /* vcpu at boundary after ALLOW self-snapshot; snapshot OK; owed 's <id>' */
    SF_CS_PARKED_CRASH,        /* vcpu at boundary after STRICT panic; snapshot rejected; owed 'x' */
    SF_CS_STOPPED_TIMEOUT,     /* timer fired -> vm_stop; main-loop dispatch; snapshot rejected; owed 't' */
} SfCtlState;

typedef enum {
    SF_GATE_ALLOW,            /* default: guest may self snapshot/restore/stop */
    SF_GATE_DISABLE,           /* any guest cmd yields -> 'c' (host decides) */
    SF_GATE_STRICT,            /* non-stop guest cmd panics -> 'x' */
} SfGateMode;

/* One-time init (timer_new + defaults: ALLOW, timeout 0 = infinite). Called from
 * sf_control_init once the chardev is attached. */
void sf_gate_init(void);

/* Block the vcpu boundary loop until a command is delivered by sf_gate_route.
 * Called from sf/checkpoint.c. */
void sf_gate_recv(SfCtlCmd *out);

/* Route a parsed command line (channel.c read callback) by state: PARKED_* ->
 * condvar handoff to the vcpu; STOPPED_TIMEOUT -> main-loop dispatch; RUNNING ->
 * drop (protocol violation). */
void sf_gate_route(const SfCtlCmd *cmd);

/* Current state. Caller must hold sf_channel_lock(). */
SfCtlState sf_gate_state_locked(void);

/* True iff snapshot is allowed at the current parked state (plan §4: only a
 * checkpoint/snapshot boundary is persistable; timeout/crash stops reject).
 * Caller must hold sf_channel_lock(). */
bool sf_gate_snapshot_ok_locked(void);

/* ---- vcpu-thread boundary (called from sf/checkpoint.c) ---- */

/* Apply the gate to the guest's port-write value, emit the boundary's initial
 * response, and perform side effects (BQL save for ALLOW self-snapshot, BQL
 * restore for ALLOW self-restore). Disarms the timeout timer (we reached a
 * boundary before it fired). Returns true iff the guest resumes (ALLOW self-
 * restore: sf/checkpoint.c returns); false iff parked (sf/checkpoint.c enters
 * the command loop). If the timer already won the race (state STOPPED), defers:
 * returns true so the vcpu returns and the in-flight vm_stop parks it. */
bool sf_gate_boundary_enter(uint64_t guest_cmd);

/* Per-command decision in the boundary loop (vcpu parked). Executes the command
 * (BQL save/restore/cold-start or config/reply) and returns true iff the guest
 * resumes (c/r/C: sf/checkpoint.c returns), false to stay parked. */
bool sf_gate_boundary_cmd(const SfCtlCmd *cmd);

/* ---- main-loop stopped dispatch (called from channel.c read callback) ---- */

/* Execute one command in the STOPPED_TIMEOUT state. Resume-class (c/r/C) does
 * vm_start (+ restore/cold-start under BQL first) + arm timer + return (reply is
 * deferred to the next stop). snapshot -> 'e invalid-state'; gate/timeout config
 * -> 'o'; bad -> 'e'. */
void sf_gate_stopped_cmd(const SfCtlCmd *cmd);

/* ---- timer + connection (main loop) ---- */

/* QEMUTimer callback: if still RUNNING (boundary didn't disarm first), vm_stop +
 * state=STOPPED_TIMEOUT + reply 't'. Serialized vs the boundary by the channel
 * mutex (plan §4: the channel never sees the race). */
void sf_gate_timer_fire(void *opaque);

/* chardev connection events (channel.c event callback). OPENED flushes the owed
 * boundary/stopped reply; CLOSED while parked/stopped re-marks it for resend. */
void sf_gate_on_connect(void);
void sf_gate_on_disconnect(void);

#endif /* SF_CONTROL_GATE_H */