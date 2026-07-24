/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Build the session-pool implementation with a controllable PKCS#11 method
 * table for the focused concurrency test.
 */

#define _POSIX_C_SOURCE 200809L
#include "libp11-int.h"
#include <time.h>

#ifdef HAVE_PTHREAD
static PKCS11_SLOT_private *delayed_slot;
static pthread_t delayed_thread;
static int delay_armed;

/* Force the transition-owner scheduling window used by the mixed-wakeup
 * regression: another transition queues before the owner selects a session. */
void session_pool_test_delay_transition_unlock(PKCS11_SLOT_private *slot)
{
	delayed_slot = slot;
	delayed_thread = pthread_self();
	delay_armed = 1;
}

static int session_pool_test_mutex_unlock(pthread_mutex_t *mutex)
{
	struct timespec delay = {0, 100000000L};
	int delay_this_unlock, rv;

	delay_this_unlock = delay_armed && delayed_slot &&
		mutex == &delayed_slot->lock && delayed_slot->transition_active &&
		pthread_equal(delayed_thread, pthread_self());
	rv = pthread_mutex_unlock(mutex);
	if (delay_this_unlock) {
		delay_armed = 0;
		nanosleep(&delay, NULL);
	}
	return rv;
}

#define pthread_mutex_unlock session_pool_test_mutex_unlock
#else /* HAVE_PTHREAD */
void session_pool_test_delay_transition_unlock(PKCS11_SLOT_private *slot)
{
	(void)slot;
}
#endif /* HAVE_PTHREAD */

#include "../src/p11_slot.c"
