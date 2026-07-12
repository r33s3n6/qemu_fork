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
#include "qemu/bswap.h"           /* stl_le_p / ldl_le_p */
#include "qapi/error.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "sf/control/channel.h"
#include "sf/control/gate.h"

#define SF_CTL_CHARDEV_ID "sfctl"

#define SF_CTL_FRAME_LEN 5   /* [op:u8][arg:u32 LE] */

static CharFrontend sf_ctl_fe;
static bool         sf_ctl_inited;

/* Receive frame accumulator — main-loop-only (chardev read callback). */
static uint8_t sf_ctl_rx[SF_CTL_FRAME_LEN];
static size_t  sf_ctl_rxlen;

bool sf_control_active(void)
{
    return sf_ctl_inited;
}

void sf_control_reply(uint8_t status, uint32_t payload)
{
    uint8_t frame[SF_CTL_FRAME_LEN];
    frame[0] = status;
    stl_le_p(&frame[1], payload);
    qemu_chr_fe_write_all(&sf_ctl_fe, frame, SF_CTL_FRAME_LEN);
}

/* Decode one 5-byte frame into a command (main loop). Unknown op -> SF_CTL_BAD.
 * arg 0xFFFFFFFF means "no id" (restore/promote to active). */
static void sf_ctl_decode(const uint8_t *frame, SfCtlCmd *c)
{
    uint32_t arg = ldl_le_p(&frame[1]);

    memset(c, 0, sizeof(*c));
    switch (frame[0]) {
    case SF_CTL_CONTINUE:
    case SF_CTL_SNAPSHOT:
    case SF_CTL_SNAPSHOT_PERSIST:
    case SF_CTL_RESTORE:
    case SF_CTL_PERSIST:
    case SF_CTL_PROMOTE:
        c->kind = (SfCtlCmdKind)frame[0];
        if (arg != SF_CTL_NO_ID) {
            c->has_id = true;
            c->id = arg;
        }
        break;
    default:
        c->kind = SF_CTL_BAD;
        break;
    }
}

/* ---- chardev callbacks (main loop) ---- */

static int sf_ctl_can_read(void *opaque)
{
    return SF_CTL_FRAME_LEN;   /* one frame at a time is plenty (sync protocol) */
}

static void sf_ctl_read(void *opaque, const uint8_t *buf, int size)
{
    for (int i = 0; i < size; i++) {
        sf_ctl_rx[sf_ctl_rxlen++] = buf[i];
        if (sf_ctl_rxlen == SF_CTL_FRAME_LEN) {
            SfCtlCmd c;
            sf_ctl_decode(sf_ctl_rx, &c);
            sf_ctl_rxlen = 0;
            sf_gate_route(&c);   /* brain routes by parking state */
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