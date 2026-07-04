/*
 * sf/ — stalefuzz fresh-backend restore engine (M0-S spike).
 * Discriminating restore-correctness selftest (design spec §G, cases ①–⑤).
 * Triggered by HMP sf_selftest. Clean-room (no Nyx).
 */
#ifndef SF_SELFTEST_H
#define SF_SELFTEST_H

#include "qapi/error.h"
#include "monitor/monitor.h"

/*
 * Run every restore-correctness case, printing per-case GREEN/RED to @mon.
 * Returns true iff every case had its expected outcome (positive cases pass,
 * fault-injection cases are correctly detected). Device cases (④⑤) run under
 * TCG or KVM; RAM cases (①②③) need the KVM dirty ring + the sf-rig dirty
 * workload running (skipped with a note otherwise).
 */
bool sf_selftest_all(Monitor *mon, Error **errp);

#endif /* SF_SELFTEST_H */
