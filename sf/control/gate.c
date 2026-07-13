/*
 * sf/control/gate — guest-agency gate + QEMU-internal timeout (M3 slice 7).
 * See gate.h for the two-dispatch-context design + plan §3/§4/§5.
 *
 * Threading: the state machine + the condvar handoff live here, guarded by
 * sf_gate_mtx. The vcpu boundary (sf/checkpoint.c) calls sf_gate_recv (cond_wait)
 * and the sf_gate_boundary_* deciders; the main-loop chardev read callback
 * (channel.c) calls sf_gate_route, which for a STOPPED_TIMEOUT state dispatches
 * directly (sf_gate_stopped_cmd) and for a PARKED_* state hands the cmd to the
 * vcpu via the condvar. The timer fires on the main loop and is the only path
 * that calls vm_stop; the boundary never does (plan §4.4: no vm_stop crutch at
 * the I/O-exit boundary). The boundary disarms the timer under the mutex before
 * claiming; the timer fires only if it sees state==RUNNING, so the two are
 * serialized and the channel never observes the race (plan §4).
 *
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/main-loop.h"      /* bql_lock/bql_unlock */
#include "qemu/timer.h"
#include "qemu/error-report.h"   /* error_report */
#include "system/runstate.h"
#include "qapi/error.h"
#include "sf/sf.h"                /* sf_checkpoint_snapshot */
#include "sf/checkpoint.h"        /* SF_CP_SNAPSHOT/RESTORE */
#include "sf/snap/node.h"         /* sf_snap_restore / sf_active / have_snapshot */
#include "sf/snap/persist.h"      /* sf_snap_persist / sf_snap_promote */
#include "sf/control/channel.h"   /* sf_control_reply */
#include "sf/control/config.h"    /* sf_config: default gate/timeout */
#include "sf/control/gate.h"

/* ---- sync + state (all under sf_gate_mtx) ---- */
static QemuMutex sf_gate_mtx;
static QemuCond  sf_gate_cond;
static bool      sf_gate_have_cmd;
static SfCtlCmd  sf_gate_cmd;

static SfCtlState sf_gate_state = SF_CS_RUNNING;
static QEMUTimer *sf_gate_timer;
/* Gate mode + resume timeout live in sf_config() (§2.1) and are read at point of
 * use, so an HMP sf_config change takes effect on the next boundary/resume. The
 * reads race benignly with the main-loop writer (int/enum config knobs; a stale
 * value costs at most one boundary). ponytail: no lock for config knobs. */

/* Owed response at the current parked/stopped state (re-sent on reconnect). */
static uint8_t  sf_gate_pending_status;
static uint32_t sf_gate_pending_payload;
static bool sf_gate_pending;
static bool sf_gate_connected;

/* The guest's sf_cp intent at the current boundary (SNAPSHOT/RESTORE/NOP-park).
 * Set on the vcpu thread in sf_gate_boundary_enter, read by the command loop on
 * the same thread. Guards a host-driven (DISABLE) self-drive guest from having
 * its setjmp assumptions silently broken (plan 2026-07-13-03 ①b). */
static uint64_t sf_gate_guest_intent;

/* ---- helpers (caller holds sf_gate_mtx) ---- */

static void sf_gate_arm_locked(void)
{
    int64_t ms = sf_config()->resume_timeout_ms;
    if (ms > 0) {
        timer_mod(sf_gate_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + ms);
    }
}

static void sf_gate_disarm_locked(void)
{
    timer_del(sf_gate_timer);
}

/* Record the owed reply (status + payload) for the parked/stopped state. */
static void sf_gate_owe_locked(uint8_t status, uint32_t payload)
{
    sf_gate_pending_status = status;
    sf_gate_pending_payload = payload;
    sf_gate_pending = true;
}

/* Park the vcpu at @state with @status/@payload owed (the flush is the caller's
 * job). Takes the mutex itself — callers are BQL-holding side-effect paths that
 * must not nest sf_gate_mtx under the BQL for longer than the state write. */
static void sf_gate_park(SfCtlState state, uint8_t status, uint32_t payload)
{
    qemu_mutex_lock(&sf_gate_mtx);
    sf_gate_state = state;
    sf_gate_owe_locked(status, payload);
    qemu_mutex_unlock(&sf_gate_mtx);
}

/* Send the owed reply if connected; callable from vcpu (boundary) or main loop
 * (on_connect). Reads state under the lock, writes the chardev outside it. */
static void sf_gate_flush(void)
{
    uint8_t status;
    uint32_t payload;
    bool go;

    qemu_mutex_lock(&sf_gate_mtx);
    go = sf_gate_pending && sf_gate_connected;
    if (go) {
        status = sf_gate_pending_status;
        payload = sf_gate_pending_payload;
        sf_gate_pending = false;
    }
    qemu_mutex_unlock(&sf_gate_mtx);
    if (go) {
        sf_control_reply(status, payload);
    }
}

/* Transition to RUNNING (a resume is starting) + arm the timer. Caller holds
 * the lock. No owed reply (the next stop reports the resume's outcome). */
static void sf_gate_begin_resume_locked(void)
{
    sf_gate_state = SF_CS_RUNNING;
    sf_gate_pending = false;
    sf_gate_arm_locked();
}

/* ---- restore-failure policy (shared by every restore-failure site) ---- */

bool sf_restore_fail(uint32_t id, const char *reason)
{
    SfRestoreFailPolicy pol = sf_config()->restore_fail_policy;

    error_report("sf-restore: restore(id=%u) failed: %s", id, reason);

    switch (pol) {
    case SF_RFP_NOTIFY:
        /* notify needs the host pipe; without a chardev there is no one to tell,
         * so a silent continue is impossible — fall through to panic. */
        if (sf_control_active()) {
            sf_control_reply(SF_ST_ERROR, SF_ERR_RESTORE_FAILED);
            return false;   /* stay parked; host decides next */
        }
        break;
    case SF_RFP_PAUSE:
        /* A direct vm_stop from the vcpu io-exit boundary (or a timer) self-
         * deadlocks pause_all_vcpus; request it on the main loop (same pattern as
         * sf_gate_timer_fire). Return true so a gate-boundary caller leaves its
         * park loop and the vcpu re-enters KVM_RUN where the deferred stop lands. */
        qemu_system_vmstop_request_prepare();
        qemu_system_vmstop_request(RUN_STATE_PAUSED);
        return true;
    case SF_RFP_PANIC:
        break;
    }

    error_report("sf-restore: fatal — aborting (policy=panic%s)",
                 pol == SF_RFP_NOTIFY ? ", notify without chardev" : "");
    abort();
}

/* ---- vcpu-thread boundary primitives ---- */

void sf_gate_recv(SfCtlCmd *out)
{
    qemu_mutex_lock(&sf_gate_mtx);
    while (!sf_gate_have_cmd) {
        qemu_cond_wait(&sf_gate_cond, &sf_gate_mtx);
    }
    *out = sf_gate_cmd;
    sf_gate_have_cmd = false;
    qemu_mutex_unlock(&sf_gate_mtx);
}

/* True iff snapshot is allowed at the current parked state (plan §4: only a
 * checkpoint/snapshot boundary is persistable; timeout/crash stops reject).
 * Caller holds sf_gate_mtx. */
static bool sf_gate_snapshot_ok_locked(void)
{
    return sf_gate_state == SF_CS_PARKED_CHECKPOINT
        || sf_gate_state == SF_CS_PARKED_SNAPSHOT;
}

/*
 * Apply the gate to the guest's port-write value and emit the boundary's initial
 * response. Returns true if the guest resumes (ALLOW self-restore), false if it
 * stays parked. The claim (set a non-RUNNING state + disarm the timer) happens
 * under the lock first so the timer fire callback can't race-claim; the heavy
 * BQL save/restore runs outside the lock.
 */
bool sf_gate_boundary_enter(uint64_t val)
{
    SfCtlGateMode mode;

    qemu_mutex_lock(&sf_gate_mtx);
    if (sf_gate_state != SF_CS_RUNNING) {
        /* The timer already won (STOPPED_TIMEOUT). Defer: return so the vcpu
         * leaves the MMIO handler; the in-flight vm_stop parks it. The timer
         * already sent 't'. */
        qemu_mutex_unlock(&sf_gate_mtx);
        return true;
    }
    sf_gate_disarm_locked();            /* we reached a boundary before it fired */
    sf_gate_state = SF_CS_PARKED_CHECKPOINT;   /* tentative claim */
    sf_gate_have_cmd = false;           /* no command may predate this boundary */
    mode = sf_config()->gate_mode;
    qemu_mutex_unlock(&sf_gate_mtx);

    sf_gate_guest_intent = val;   /* what the guest asked for at this boundary (①b) */
    bool resume = false;

    switch (mode) {
    case SF_CTL_GATE_ALLOW:
        /* Guest agency: snapshot/restore self-execute exactly like the standalone
         * path (id/gen pushed to %rax, self-return, restore failure → policy) so an
         * ALLOW guest with the chardev attached is indistinguishable from no host.
         * Only a STOP/yield parks, so the host still gets that boundary. The timer
         * was disarmed above; begin_resume re-arms it, so a host-set deadline still
         * fires during the next spin. */
        if (val == SF_CP_SNAPSHOT || val == SF_CP_RESTORE) {
            if (sf_cp_execute_and_reply(val)) {
                qemu_mutex_lock(&sf_gate_mtx);
                sf_gate_begin_resume_locked();
                qemu_mutex_unlock(&sf_gate_mtx);
                resume = true;
            }
            /* else: a notify-policy restore failure already replied 'e' and left
             * the vcpu parked (resume stays false → command loop). */
        } else {
            /* stop (0) or any unrecognized value: park as a checkpoint */
            sf_gate_park(SF_CS_PARKED_CHECKPOINT, SF_ST_CHECKPOINT, 0);
        }
        break;

    case SF_CTL_GATE_DISABLE:
        /* any guest cmd yields -> 'c', host decides */
        sf_gate_park(SF_CS_PARKED_CHECKPOINT, SF_ST_CHECKPOINT, 0);
        break;

    case SF_CTL_GATE_STRICT:
        if (val == SF_CP_SNAPSHOT || val == SF_CP_RESTORE) {
            /* non-stop intent -> panic -> 'x' (snapshot now rejected) */
            sf_gate_park(SF_CS_PARKED_CRASH, SF_ST_CRASH, 0);
        } else {
            sf_gate_park(SF_CS_PARKED_CHECKPOINT, SF_ST_CHECKPOINT, 0);
        }
        break;
    }

    if (!resume) {
        sf_gate_flush();   /* emit the boundary's initial response ('c'/'s <id>'/'x'/'e ...') */
    }
    return resume;
}

/* ---- persist / promote to the configured private_dir (host-side disk ops;
 * guest stays parked). Shared by boundary + stopped dispatch. ---- */

static void sf_gate_do_persist(void)
{
    const SfConfig *c = sf_config();
    const char *dir = c->private_dir;
    /* Two-dir when a distinct read-only common base is configured: persist only
     * this worker's private nodes, back-referencing common (plan 04 §2.4). */
    const char *common_ref = (c->common_dir[0] && strcmp(c->common_dir, dir))
                             ? c->common_dir : NULL;
    SfSnapNode *root;
    Error *err = NULL;

    if (!dir[0]) {
        sf_control_reply(SF_ST_ERROR, SF_ERR_PERSIST_FAILED);
        return;
    }
    if (!sf_active) {
        sf_control_reply(SF_ST_ERROR, SF_ERR_NO_SNAPSHOT);
        return;
    }
    for (root = sf_active; root->parent; root = root->parent) {
        /* walk to root */
    }
    if (sf_snap_persist(root, dir, common_ref, &err) < 0) {
        fprintf(stderr, "sf-gate: persist %s failed: %s\n",
                dir, error_get_pretty(err));
        error_free(err);
        sf_control_reply(SF_ST_ERROR, SF_ERR_PERSIST_FAILED);
        return;
    }
    sf_control_reply(SF_ST_OK, 0);
}

static void sf_gate_do_promote(const SfCtlCmd *cmd)
{
    const SfConfig *c = sf_config();
    const char *dir = c->private_dir;
    const char *common_ref = (c->common_dir[0] && strcmp(c->common_dir, dir))
                             ? c->common_dir : NULL;
    SfSnapNode *node = cmd->has_id ? sf_node_find(cmd->id) : sf_active;
    Error *err = NULL;

    if (!dir[0] || !node) {
        sf_control_reply(SF_ST_ERROR, SF_ERR_PROMOTE_FAILED);
        return;
    }
    if (sf_snap_promote(node, dir, common_ref, &err) < 0) {
        fprintf(stderr, "sf-gate: promote %s failed: %s\n",
                dir, error_get_pretty(err));
        error_free(err);
        sf_control_reply(SF_ST_ERROR, SF_ERR_PROMOTE_FAILED);
        return;
    }
    sf_control_reply(SF_ST_OK, 0);
}

/* One command in the boundary loop (vcpu parked). Returns true if the guest
 * resumes (c/r), false to stay parked. */
bool sf_gate_boundary_cmd(const SfCtlCmd *cmd)
{
    switch (cmd->kind) {
    case SF_CTL_CONTINUE:
        /* ①b guest-intent guard: a bare continue must not break a self-drive
         * guest's setjmp assumptions. If the guest asked to RESTORE it expects a
         * longjmp (its code after the call is unreachable); if it asked to
         * SNAPSHOT it expects a real node id back. Reject the continue unless the
         * host already honored the intent (a SNAPSHOT leaves PARKED_SNAPSHOT).
         * A NOP/park boundary carries no such expectation → free. */
        if (sf_gate_guest_intent == SF_CP_RESTORE ||
            (sf_gate_guest_intent == SF_CP_SNAPSHOT &&
             sf_gate_state != SF_CS_PARKED_SNAPSHOT)) {
            sf_control_reply(SF_ST_ERROR, SF_ERR_INVALID_STATE);
            return false;   /* stay parked; host must snapshot/restore first */
        }
        qemu_mutex_lock(&sf_gate_mtx);
        sf_gate_begin_resume_locked();
        qemu_mutex_unlock(&sf_gate_mtx);
        return true;

    case SF_CTL_SNAPSHOT: {
        qemu_mutex_lock(&sf_gate_mtx);
        bool ok = sf_gate_snapshot_ok_locked();
        qemu_mutex_unlock(&sf_gate_mtx);
        if (!ok) {
            sf_control_reply(SF_ST_ERROR, SF_ERR_INVALID_STATE);
            return false;
        }
        bql_lock();
        sf_checkpoint_snapshot();
        bql_unlock();
        sf_gate_park(SF_CS_PARKED_SNAPSHOT, SF_ST_SNAPSHOT,
                     sf_active ? sf_active->id : 0);
        sf_gate_flush();
        return false;
    }

    case SF_CTL_SNAPSHOT_PERSIST: {
        /* Durable snapshot: build the diff straight into private_dir + promote in one
         * pass (skips promote's 2nd copy). Non-root only — needs an active base. */
        const SfConfig *c = sf_config();
        const char *dir = c->private_dir;
        const char *common_ref = (c->common_dir[0] && strcmp(c->common_dir, dir))
                                 ? c->common_dir : NULL;
        Error *err = NULL;
        qemu_mutex_lock(&sf_gate_mtx);
        bool ok = sf_gate_snapshot_ok_locked();
        qemu_mutex_unlock(&sf_gate_mtx);
        if (!ok || !sf_active) {
            sf_control_reply(SF_ST_ERROR, SF_ERR_INVALID_STATE);
            return false;
        }
        if (!dir[0]) {
            sf_control_reply(SF_ST_ERROR, SF_ERR_PERSIST_FAILED);
            return false;
        }
        int r = sf_snap_persist_prepare(dir, common_ref, &err);  /* dirs+header, no bql */
        if (r == 0) {
            bql_lock();   /* ponytail: promote disk I/O runs under bql (guest parked,
                           * single-vcpu); split out if bql contention ever matters */
            r = sf_checkpoint_snapshot_persist(dir, common_ref);
            bql_unlock();
        }
        if (r < 0) {
            if (err) {
                fprintf(stderr, "sf-gate: snapshot-persist %s failed: %s\n",
                        dir, error_get_pretty(err));
                error_free(err);
            }
            sf_control_reply(SF_ST_ERROR, SF_ERR_PERSIST_FAILED);
            return false;
        }
        sf_gate_park(SF_CS_PARKED_SNAPSHOT, SF_ST_SNAPSHOT,
                     sf_active ? sf_active->id : 0);
        sf_gate_flush();
        return false;
    }

    case SF_CTL_RESTORE: {
        uint32_t id = cmd->has_id ? cmd->id : (sf_active ? sf_active->id : 0);
        if (!sf_snap_have_snapshot()) {
            return sf_restore_fail(id, "no snapshot");
        }
        Error *err = NULL;
        bql_lock();
        int r = sf_snap_restore(id, NULL, &err);
        bql_unlock();
        if (r < 0) {
            fprintf(stderr, "sf-gate: restore %u failed: %s\n",
                    id, error_get_pretty(err));
            error_free(err);
            return sf_restore_fail(id, "restore engine error");
        }
        qemu_mutex_lock(&sf_gate_mtx);
        sf_gate_begin_resume_locked();
        qemu_mutex_unlock(&sf_gate_mtx);
        return true;
    }

    case SF_CTL_PERSIST:
        sf_gate_do_persist();   /* stays parked; replies o / e */
        return false;

    case SF_CTL_PROMOTE:
        sf_gate_do_promote(cmd);
        return false;

    case SF_CTL_BAD:
    default:
        sf_control_reply(SF_ST_ERROR, SF_ERR_BAD_COMMAND);
        return false;
    }
}

/* ---- main-loop stopped dispatch (after timeout) ---- */

/* Resume-class from the stopped state: vm_start (+ restore under BQL first if
 * any), transition to RUNNING, arm the timer. The reply is deferred to the next
 * stop. Returns true if a resume started. */
static bool sf_gate_stopped_resume(const SfCtlCmd *cmd)
{
    /* The chardev read callback runs in the main loop; it may or may not hold
     * the BQL depending on the dispatch path. Take the BQL only if not already
     * held (an unconditional bql_lock would assert) — same pattern as the
     * standalone sf_cp_write. Restore/cold-start + vm_start then run under it,
     * mirroring the HMP crutch (vm_stop done by the timer + restore + vm_start). */
    bool take_bql = !bql_locked();

    if (cmd->kind == SF_CTL_RESTORE) {
        if (!sf_snap_have_snapshot()) {
            sf_restore_fail(cmd->has_id ? cmd->id : 0, "no snapshot");
            return false;   /* stopped stays stopped; pause is already the state */
        }
        uint32_t id = cmd->has_id ? cmd->id : (sf_active ? sf_active->id : 0);
        Error *err = NULL;
        if (take_bql) { bql_lock(); }
        int r = sf_snap_restore(id, NULL, &err);
        if (r < 0) {
            if (take_bql) { bql_unlock(); }
            fprintf(stderr, "sf-gate: stopped restore %u failed: %s\n",
                    id, error_get_pretty(err));
            error_free(err);
            sf_restore_fail(id, "restore engine error");
            return false;   /* stopped stays stopped */
        }
        /* vm_start with the BQL held (matches HMP); release before the gate
         * mutex to keep sf_gate_mtx never nested under the BQL. */
        vm_start();
        if (take_bql) { bql_unlock(); }
    } else {
        /* SF_CTL_CONTINUE: just resume. */
        vm_start();
    }
    qemu_mutex_lock(&sf_gate_mtx);
    sf_gate_begin_resume_locked();
    qemu_mutex_unlock(&sf_gate_mtx);
    return true;
}

void sf_gate_stopped_cmd(const SfCtlCmd *cmd)
{
    switch (cmd->kind) {
    case SF_CTL_CONTINUE:
    case SF_CTL_RESTORE:
        sf_gate_stopped_resume(cmd);   /* deferred reply; stay stopped on error */
        break;

    case SF_CTL_SNAPSHOT:
        /* timeout stop is not a persistable boundary (plan §4) */
        sf_control_reply(SF_ST_ERROR, SF_ERR_INVALID_STATE);
        break;

    case SF_CTL_PERSIST:
        sf_gate_do_persist();   /* tree serialize; valid at a timeout stop too */
        break;

    case SF_CTL_PROMOTE:
        sf_gate_do_promote(cmd);
        break;

    case SF_CTL_BAD:
    default:
        sf_control_reply(SF_ST_ERROR, SF_ERR_BAD_COMMAND);
        break;
    }
}

/* ---- timer + connection (main loop) ---- */

/*
 * vm_stop can't run inside a QEMUTimer callback: pause_all_vcpus ->
 * qemu_clock_enable(QEMU_CLOCK_VIRTUAL, false) waits on the timer list's
 * timers_done_ev, which is only set after this timerlist_run_timers iteration
 * returns — i.e. after we return — so a direct vm_stop here self-deadlocks. So
 * the timer just claims the stop (state + owed 't') and defers the vm_stop to
 * the main loop via qemu_system_vmstop_request; a vm_change_state_handler
 * (sf_gate_vm_state_cb) flushes 't' once the deferred vm_stop completes and the
 * vcpu is actually parked. The boundary disarming the timer before this callback
 * runs is the only other contender; the channel mutex serializes them (plan §4).
 */
static void sf_gate_vm_state_cb(void *opaque, bool running, RunState state)
{
    bool owe;

    if (running || state != RUN_STATE_PAUSED) {
        return;
    }
    qemu_mutex_lock(&sf_gate_mtx);
    owe = (sf_gate_state == SF_CS_STOPPED_TIMEOUT) && sf_gate_pending;
    qemu_mutex_unlock(&sf_gate_mtx);
    if (owe) {
        sf_gate_flush();   /* the deferred timeout vm_stop finished -> send 't' */
    }
}

void sf_gate_timer_fire(void *opaque)
{
    qemu_mutex_lock(&sf_gate_mtx);
    if (sf_gate_state != SF_CS_RUNNING) {
        /* the boundary claimed first (disarmed) — no-op */
        qemu_mutex_unlock(&sf_gate_mtx);
        return;
    }
    sf_gate_state = SF_CS_STOPPED_TIMEOUT;
    sf_gate_owe_locked(SF_ST_TIMEOUT, 0);
    qemu_mutex_unlock(&sf_gate_mtx);

    /* Defer vm_stop to the main loop (see comment above). The owed 't' is sent
     * by sf_gate_vm_state_cb once the stop completes. */
    qemu_system_vmstop_request_prepare();
    qemu_system_vmstop_request(RUN_STATE_PAUSED);
}

void sf_gate_on_connect(void)
{
    qemu_mutex_lock(&sf_gate_mtx);
    sf_gate_connected = true;
    qemu_mutex_unlock(&sf_gate_mtx);
    sf_gate_flush();   /* if parked/stopped with an owed reply, announce it */
}

void sf_gate_on_disconnect(void)
{
    qemu_mutex_lock(&sf_gate_mtx);
    sf_gate_connected = false;
    /* Re-owe the current boundary/stopped reply so a reconnect re-sends it. */
    if (sf_gate_state != SF_CS_RUNNING) {
        sf_gate_pending = true;
    }
    qemu_mutex_unlock(&sf_gate_mtx);
}

/* ---- init (from sf_control_init, once chardev attached) ---- */

void sf_gate_init(void)
{
    qemu_mutex_init(&sf_gate_mtx);
    qemu_cond_init(&sf_gate_cond);
    sf_gate_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, sf_gate_timer_fire, NULL);
    sf_gate_state = SF_CS_RUNNING;
    /* gate mode + timeout are read live from sf_config() (§2.1) at each
     * boundary/arm — nothing to cache here. */
    sf_gate_have_cmd = false;
    sf_gate_connected = false;
    /* Flush the owed 't' once the deferred timeout vm_stop completes. */
    qemu_add_vm_change_state_handler(sf_gate_vm_state_cb, NULL);
}

/* ---- channel.c read-callback routing (called with a parsed line) ---- */

void sf_gate_route(const SfCtlCmd *cmd)
{
    SfCtlState st;

    qemu_mutex_lock(&sf_gate_mtx);
    st = sf_gate_state;
    if (st == SF_CS_PARKED_CHECKPOINT || st == SF_CS_PARKED_SNAPSHOT
        || st == SF_CS_PARKED_CRASH) {
        /* hand the command to the parked vcpu via the condvar */
        sf_gate_cmd = *cmd;
        sf_gate_have_cmd = true;
        qemu_cond_signal(&sf_gate_cond);
        qemu_mutex_unlock(&sf_gate_mtx);
        return;
    }
    qemu_mutex_unlock(&sf_gate_mtx);

    if (st == SF_CS_STOPPED_TIMEOUT) {
        sf_gate_stopped_cmd(cmd);   /* main-loop dispatch */
    } else {
        /* SF_CS_RUNNING: host sent a command mid-flight — protocol violation.
         * ponytail: a hard 'e busy' reply is a deferred refinement; for now the
         * rig never sends during flight, so drop + log. */
        fprintf(stderr, "sf-gate: cmd '%d' during running — dropped\n",
                (int)cmd->kind);
    }
}
