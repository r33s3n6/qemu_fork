/*
 * sf/param — the single predefined host→guest parameter region (no_restore).
 *
 * One fixed-GPA page, excluded from restore (rides the normal exclude table +
 * bufs/<id>.buf MAP_SHARED remap), established host-side by QEMU — NO guest
 * register hypercall. Split into a framework-owned HEADER (this file's schema,
 * written only by QEMU) and a scenario-owned TAIL (opaque here; default layout
 * = INPUT/OUTPUT in sfabi::buf). The guest reads the region via /dev/mem at the
 * fixed GPA (the page is memmap= reserved so /dev/mem allows it).
 *
 * HEADER is single-source (QEMU): stamped at machine_done on the setup/builder
 * run (persisted into the base snapshot), and backfilled after cold-start in the
 * worker (its own scale). Layout MUST mirror sfabi::buf (Rust guest side) — keep
 * in sync.  Clean-room: no QEMU-Nyx code.
 */
#ifndef SF_PARAM_H
#define SF_PARAM_H

/* Fixed guest-physical address + size (1 page). The guest reserves it via
 * `memmap=0x1000$0x1FFF0000`; QEMU sees it as ordinary RAM (memmap only edits
 * the guest E820), so sf_gpa_to_host resolves it. 0x1FFF0000 < 512M ⇒ valid for
 * every MEM profile (phase1.5 512M .. phase2 6G). */
#define SF_PARAM_GPA      0x1FFF0000u
#define SF_PARAM_SIZE     0x1000u
#define SF_PARAM_BUF_ID   1u

/* HEADER (mirror of sfabi::buf). magic proves QEMU stamped it (guards a consumer
 * reading an un-set-up / mis-GPA region — reads garbage instead of silent 0). */
#define SF_PARAM_MAGIC          0x53465052u   /* "SFPR" LE */
#define SF_PARAM_MAGIC_OFF      0u            /* u32 */
#define SF_PARAM_TSC_KHZ_OFF    8u            /* u64 */
#define SF_PARAM_SCALE_PPM_OFF  16u           /* u32, 1e6 = 1x (numeric, real_sleep) */
#define SF_PARAM_SCALE_STR_OFF  20u           /* char[16] ASCII (shell dd) */
#define SF_PARAM_SCALE_STR_LEN  16u

/* Full setup on the setup/builder run (machine_done, !cold_start_on_boot):
 * exclude_add + bufs file remap + stamp HEADER. Persisted into the base snapshot. */
void sf_param_setup(void);

/* HEADER-only backfill after cold-start (worker): the region is already
 * re-established by exclude reload + cold_remap_bufs; stamp this worker's scale. */
void sf_param_stamp_header(void);

#endif /* SF_PARAM_H */
