/*
 * sf/control/channel — host control channel transport + handoff. See channel.h.
 *
 * Threading: the chardev read/event callbacks run on the MAIN LOOP; they only
 * touch this file's buffer + the handoff mutex, never BQL-protected state. The
 * vcpu thread (boundary) waits on a condvar with sf_ctl_mtx (NOT the BQL), so the
 * main loop stays free to receive commands while the guest is parked. Responses
 * are written from the vcpu thread (chardev has its own write lock); Nyx does the
 * same from its vcpu boundary.
 *
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "sf/control/channel.h"

#define SF_CTL_CHARDEV_ID "sfctl"

static CharFrontend sf_ctl_fe;
static bool         sf_ctl_inited;

/* Receive line buffer — main-loop-only (chardev read callback). */
static char   sf_ctl_rx[1024];
static size_t sf_ctl_rxlen;

/* Handoff between main loop (producer) and vcpu boundary (consumer). */
static QemuMutex sf_ctl_mtx;
static QemuCond  sf_ctl_cond;
static bool      sf_ctl_have_cmd;
static SfCtlCmd  sf_ctl_cmd;

/* Connection + boundary state (all under sf_ctl_mtx). */
static bool sf_ctl_connected;
static bool sf_ctl_at_boundary;
static bool sf_ctl_pending_c;   /* boundary reached; 'c' owed once connected */

bool sf_control_active(void)
{
    return sf_ctl_inited;
}

static void sf_ctl_write(const char *s)
{
    qemu_chr_fe_write_all(&sf_ctl_fe, (const uint8_t *)s, (int)strlen(s));
}

/* Emit the boundary 'c' iff we're parked, it's owed, and a client is connected.
 * Callable from the vcpu (boundary_enter) or the main loop (event OPENED); the
 * decision is made under the lock, the write happens outside it. */
static void sf_ctl_flush_c(void)
{
    bool go;

    qemu_mutex_lock(&sf_ctl_mtx);
    go = sf_ctl_at_boundary && sf_ctl_pending_c && sf_ctl_connected;
    if (go) {
        sf_ctl_pending_c = false;
    }
    qemu_mutex_unlock(&sf_ctl_mtx);
    if (go) {
        sf_ctl_write("c\n");
    }
}

/* ---- command parse (main loop) — first-version space-separated grammar
 * (plan §2/§45): long or short verb, optional numeric id, cold-start dir (no
 * embedded spaces). ---- */
static void sf_ctl_parse(char *line, SfCtlCmd *c)
{
    char **tok;
    guint ntok;
    const char *verb;
    size_t n = strlen(line);

    memset(c, 0, sizeof(*c));
    while (n && (line[n - 1] == '\r' || line[n - 1] == ' ')) {
        line[--n] = '\0';
    }
    tok = g_strsplit_set(line, " ", 0);
    ntok = tok ? g_strv_length(tok) : 0;
    verb = ntok ? tok[0] : "";

    if (!strcmp(verb, "c") || !strcmp(verb, "continue")) {
        c->kind = SF_CTL_CONTINUE;
    } else if (!strcmp(verb, "s") || !strcmp(verb, "snapshot")) {
        c->kind = SF_CTL_SNAPSHOT;
    } else if (!strcmp(verb, "r") || !strcmp(verb, "restore")) {
        c->kind = SF_CTL_RESTORE;
        if (ntok >= 2 && tok[1][0]) {
            c->has_id = true;
            c->id = (uint32_t)g_ascii_strtoull(tok[1], NULL, 10);
        }
    } else if (!strcmp(verb, "C") || !strcmp(verb, "cold-start")) {
        c->kind = SF_CTL_COLDSTART;
        if (ntok >= 2 && tok[1][0]) {
            g_strlcpy(c->dir, tok[1], sizeof(c->dir));
        }
        if (ntok >= 3 && tok[2][0]) {
            c->has_id = true;
            c->id = (uint32_t)g_ascii_strtoull(tok[2], NULL, 10);
        }
    } else {
        c->kind = SF_CTL_BAD;
    }
    g_strfreev(tok);
}

/* ---- chardev callbacks (main loop) ---- */

static int sf_ctl_can_read(void *opaque)
{
    /* Always leave room for a NUL; a line that overflows is dropped in read. */
    return (int)(sizeof(sf_ctl_rx) - 1 - sf_ctl_rxlen);
}

static void sf_ctl_read(void *opaque, const uint8_t *buf, int size)
{
    for (int i = 0; i < size; i++) {
        char ch = (char)buf[i];
        if (ch == '\n') {
            sf_ctl_rx[sf_ctl_rxlen] = '\0';
            SfCtlCmd c;
            sf_ctl_parse(sf_ctl_rx, &c);
            sf_ctl_rxlen = 0;
            qemu_mutex_lock(&sf_ctl_mtx);
            sf_ctl_cmd = c;
            sf_ctl_have_cmd = true;
            qemu_cond_signal(&sf_ctl_cond);
            qemu_mutex_unlock(&sf_ctl_mtx);
        } else if (ch != '\r' && sf_ctl_rxlen < sizeof(sf_ctl_rx) - 1) {
            sf_ctl_rx[sf_ctl_rxlen++] = ch;
        } else if (ch != '\r') {
            sf_ctl_rxlen = 0;   /* overlong line — drop it, resync on next '\n' */
        }
    }
}

static void sf_ctl_event(void *opaque, QEMUChrEvent ev)
{
    switch (ev) {
    case CHR_EVENT_OPENED:
        qemu_mutex_lock(&sf_ctl_mtx);
        sf_ctl_connected = true;
        qemu_mutex_unlock(&sf_ctl_mtx);
        sf_ctl_flush_c();   /* if the guest is already parked, announce it */
        break;
    case CHR_EVENT_CLOSED:
        qemu_mutex_lock(&sf_ctl_mtx);
        sf_ctl_connected = false;
        sf_ctl_rxlen = 0;
        if (sf_ctl_at_boundary) {
            sf_ctl_pending_c = true;   /* re-announce the boundary on reconnect */
        }
        qemu_mutex_unlock(&sf_ctl_mtx);
        break;
    default:
        break;
    }
}

/* ---- vcpu-thread boundary primitives ---- */

void sf_control_boundary_enter(void)
{
    qemu_mutex_lock(&sf_ctl_mtx);
    sf_ctl_at_boundary = true;
    sf_ctl_pending_c = true;
    sf_ctl_have_cmd = false;   /* no command may predate this boundary (sync protocol) */
    qemu_mutex_unlock(&sf_ctl_mtx);
    sf_ctl_flush_c();
}

void sf_control_boundary_exit(void)
{
    qemu_mutex_lock(&sf_ctl_mtx);
    sf_ctl_at_boundary = false;
    sf_ctl_pending_c = false;
    qemu_mutex_unlock(&sf_ctl_mtx);
}

/* ponytail: while parked here the vcpu sits in cond_wait, so a normal QEMU
 * shutdown/SIGTERM can't stop it — the rig tears QEMU down with SIGKILL. Fine for
 * a single-purpose fuzzing rig; add a shutdown-notifier that broadcasts the cond +
 * returns a detach sentinel if graceful teardown is ever needed. */
void sf_control_recv(SfCtlCmd *out)
{
    qemu_mutex_lock(&sf_ctl_mtx);
    while (!sf_ctl_have_cmd) {
        qemu_cond_wait(&sf_ctl_cond, &sf_ctl_mtx);
    }
    *out = sf_ctl_cmd;
    sf_ctl_have_cmd = false;
    qemu_mutex_unlock(&sf_ctl_mtx);
}

void sf_control_reply(const char *line)
{
    sf_ctl_write(line);
}

/* ---- init (main thread, machine_init_done) ---- */

void sf_control_init(void)
{
    Chardev *chr = qemu_chr_find(SF_CTL_CHARDEV_ID);

    if (!chr) {
        return;   /* no control channel configured */
    }
    qemu_mutex_init(&sf_ctl_mtx);
    qemu_cond_init(&sf_ctl_cond);
    if (!qemu_chr_fe_init(&sf_ctl_fe, chr, &error_abort)) {
        return;
    }
    qemu_chr_fe_set_handlers(&sf_ctl_fe, sf_ctl_can_read, sf_ctl_read,
                             sf_ctl_event, NULL, NULL, NULL, true);
    sf_ctl_inited = true;
    fprintf(stderr, "sf-ctl: control channel attached to chardev '%s'\n",
            SF_CTL_CHARDEV_ID);
}
