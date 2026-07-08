/*
 * sf/control/channel — host control channel transport + parse. See channel.h.
 *
 * Threading: the chardev read/event callbacks run on the MAIN LOOP; they only
 * touch this file's line buffer (rx) and delegate to gate.c (sf_gate_route /
 * sf_gate_on_connect / sf_gate_on_disconnect), never BQL-protected state
 * directly. Responses are written from gate.c via sf_control_reply (chardev write
 * lock). The vcpu boundary waits in gate.c's condvar, not here.
 *
 * Clean-room: no QEMU-Nyx code.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "sf/control/channel.h"
#include "sf/control/gate.h"

#define SF_CTL_CHARDEV_ID "sfctl"

/* Longest legal line: a cold-start dir (SfCtlCmd.dir) + verb/id/spaces slack. A
 * line past this is rejected with 'e line-too-long' rather than silently split. */
#define SF_CTL_LINE_MAX (sizeof(((SfCtlCmd *)0)->dir) + 128)

static CharFrontend sf_ctl_fe;
static bool         sf_ctl_inited;

/* Receive line buffer — main-loop-only (chardev read callback). */
static char   sf_ctl_rx[SF_CTL_LINE_MAX];
static size_t sf_ctl_rxlen;
static bool   sf_ctl_overflow;   /* current line exceeded SF_CTL_LINE_MAX; drop to next '\n' */

bool sf_control_active(void)
{
    return sf_ctl_inited;
}

void sf_control_reply(const char *line)
{
    qemu_chr_fe_write_all(&sf_ctl_fe, (const uint8_t *)line, (int)strlen(line));
}

/* ---- command parse (main loop) — space-separated grammar (plan §2/§45):
 * long or short verb, optional numeric id, cold-start dir (no embedded spaces),
 * gate mode letter, timeout ms. ---- */
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
    } else if (!strcmp(verb, "g") || !strcmp(verb, "gate")) {
        c->kind = SF_CTL_GATE;
        if (ntok >= 2 && tok[1][0]) {
            switch (tok[1][0]) {
            case 'a': c->gmode = SF_CTL_GATE_ALLOW; break;
            case 'd': c->gmode = SF_CTL_GATE_DISABLE; break;
            case 's': c->gmode = SF_CTL_GATE_STRICT; break;
            default:  c->kind = SF_CTL_BAD; break;
            }
        } else {
            c->kind = SF_CTL_BAD;
        }
    } else if (!strcmp(verb, "T") || !strcmp(verb, "timeout")) {
        c->kind = SF_CTL_TIMEOUT;
        if (ntok >= 2 && tok[1][0]) {
            c->timeout_ms = (int64_t)g_ascii_strtoull(tok[1], NULL, 10);
        } else {
            c->kind = SF_CTL_BAD;
        }
    } else {
        c->kind = SF_CTL_BAD;
    }
    g_strfreev(tok);
}

/* ---- chardev callbacks (main loop) ---- */

static int sf_ctl_can_read(void *opaque)
{
    /* Fixed hint: sf_ctl_read bounds the line itself and keeps draining even
     * while dropping an overlong one, so we must never return 0 mid-line. */
    return 512;
}

static void sf_ctl_read(void *opaque, const uint8_t *buf, int size)
{
    for (int i = 0; i < size; i++) {
        char ch = (char)buf[i];
        if (ch == '\n') {
            if (sf_ctl_overflow) {
                sf_control_reply("e line-too-long\n");
                sf_ctl_overflow = false;
            } else {
                sf_ctl_rx[sf_ctl_rxlen] = '\0';
                SfCtlCmd c;
                sf_ctl_parse(sf_ctl_rx, &c);
                sf_gate_route(&c);   /* brain routes by parking state */
            }
            sf_ctl_rxlen = 0;
        } else if (ch == '\r') {
            /* strip CR */
        } else if (sf_ctl_overflow) {
            /* swallow the rest of the overlong line until '\n' */
        } else if (sf_ctl_rxlen < sizeof(sf_ctl_rx) - 1) {
            sf_ctl_rx[sf_ctl_rxlen++] = ch;
        } else {
            sf_ctl_overflow = true;   /* line exceeds bound → reject on '\n' */
        }
    }
}

static void sf_ctl_event(void *opaque, QEMUChrEvent ev)
{
    switch (ev) {
    case CHR_EVENT_OPENED:
        sf_gate_on_connect();
        break;
    case CHR_EVENT_CLOSED:
        sf_gate_on_disconnect();
        break;
    default:
        break;
    }
}

/* ---- init (main thread, machine_init_done) ---- */

void sf_control_init(void)
{
    Chardev *chr = qemu_chr_find(SF_CTL_CHARDEV_ID);

    if (!chr) {
        return;   /* no control channel configured */
    }
    if (!qemu_chr_fe_init(&sf_ctl_fe, chr, &error_abort)) {
        return;
    }
    qemu_chr_fe_set_handlers(&sf_ctl_fe, sf_ctl_can_read, sf_ctl_read,
                             sf_ctl_event, NULL, NULL, NULL, true);
    sf_gate_init();          /* state machine + timer + condvar */
    sf_ctl_inited = true;
    fprintf(stderr, "sf-ctl: control channel attached to chardev '%s'\n",
            SF_CTL_CHARDEV_ID);
}