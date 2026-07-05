#ifndef HW_I386_VAPIC_H
#define HW_I386_VAPIC_H

bool vapic_sf_guard_inactive(void *opaque);
void vapic_sf_reactivate(void *opaque);

#endif /* HW_I386_VAPIC_H */
