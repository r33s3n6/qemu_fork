/*
 * sf/snap/tripwire — enforce "no host-side write to snapshot-semantic RAM" at
 * runtime (plan 2026-07-06-06 §2, §7 of the design).
 *
 * Host writes to guest RAM (DMA, address_space_write, cpu_physical_memory_write)
 * bypass the KVM dirty ring, so they'd silently corrupt a snapshot. The tripwire
 * hooks the QEMU-wide set-dirty funnel (invalidate_and_set_dirty) and aborts
 * (debug) / counts (release) when such a write hits snapshot-semantic RAM that
 * isn't NO_RESTORE-excluded. The audit (plan -06 §2) proved hooking that one
 * funnel covers every host-write path; the only other direct callers of
 * physical_memory_set_dirty_range (lebitmap = KVM collect, qemu_ram_resize,
 * ram_block_add) do not touch runtime snapshot RAM.
 *
 * Our own restore memcpy writes host RAM directly (not via address_space), so it
 * never enters this funnel — the tripwire stays armed across restore with no
 * false fire. Guest writes go through EPT → KVM ring, also not this funnel.
 *
 * Include qemu/osdep.h before this header.
 */
#ifndef SF_SNAP_TRIPWIRE_H
#define SF_SNAP_TRIPWIRE_H

#include "exec/hwaddr.h"

struct MemoryRegion;

/* Arm/disarm. Armed when a snapshot tree exists (root built); disarmed on tree
 * teardown. Disarmed → the hook is one global load + predicted branch. */
void sf_tripwire_arm(bool arm);
bool sf_tripwire_armed(void);

/*
 * Called from invalidate_and_set_dirty at the top (before the ramaddr math). @mr
 * is the (RAM) memory region, @addr the offset within it, @length the write. If
 * armed and the write hits snapshot-semantic RAM that isn't excluded, record a
 * violation (abort in debug mode, count + log in release mode).
 */
void sf_tripwire_hit(struct MemoryRegion *mr, hwaddr addr, hwaddr length);

/* Violation counter + recent-log (release mode / selftest). */
unsigned long sf_tripwire_count(void);
void          sf_tripwire_reset_count(void);

/* Test inject (selftest only): make the hook a no-op so a check can prove the
 * tripwire itself has teeth (a host write then goes undetected → RED). */
void sf_tripwire_inject_disable(bool disable);

/* Override the violation mode (selftest uses count so a trigger doesn't abort
 * the process). @abort_mode true → abort (production default), false → count.
 * Call with true to restore the env default. */
void sf_tripwire_set_mode(bool abort_mode);

#endif /* SF_SNAP_TRIPWIRE_H */