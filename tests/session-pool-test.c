/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 200809L
#include "libp11-int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* p11_slot.c is compiled into this focused unit test. */
void pkcs11_destroy_keys(PKCS11_SLOT_private *slot, unsigned int type)
{
	(void)slot;
	(void)type;
}

void pkcs11_destroy_certs(PKCS11_SLOT_private *slot)
{
	(void)slot;
}

char *pkcs11_strdup(char *text, size_t size)
{
	(void)text;
	(void)size;
	return NULL;
}

int pkcs11_atomic_add(int *value, int amount, pthread_mutex_t *lock)
{
	int result;

	pthread_mutex_lock(lock);
	*value += amount;
	result = *value;
	pthread_mutex_unlock(lock);
	return result;
}

void ERR_CKR_error(int function, int reason, char *file, int line)
{
	(void)function;
	(void)reason;
	(void)file;
	(void)line;
}

void ERR_P11_error(int function, int reason, char *file, int line)
{
	(void)function;
	(void)reason;
	(void)file;
	(void)line;
}

#ifdef HAVE_PTHREAD

#define TEST_TIMEOUT_SECONDS 5

void session_pool_test_delay_transition_unlock(PKCS11_SLOT_private *slot);

struct fake_module_state {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	PKCS11_SLOT_private *slot;
	CK_SESSION_HANDLE next_session;
	unsigned int open_sessions;
	unsigned int max_sessions;
	int logged_in;
	int pause_login;
	int login_entered;
	CK_RV login_result;
	int close_while_in_use;
	int reload_reset_missing;
	int expect_reload_reset;
};

struct thread_state {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	PKCS11_SLOT_private *slot;
	CK_SESSION_HANDLE session;
	int done;
	int acquired;
	int delay_transition_unlock;
	int rv;
	int mode;
};

static struct fake_module_state fake;

static CK_RV fake_open_session(CK_SLOT_ID slot_id, CK_FLAGS flags,
		CK_VOID_PTR application, CK_NOTIFY notify,
		CK_SESSION_HANDLE_PTR session)
{
	(void)slot_id;
	(void)flags;
	(void)application;
	(void)notify;

	pthread_mutex_lock(&fake.lock);
	if (fake.expect_reload_reset &&
			(fake.slot->transition_active != 0 ||
			 fake.slot->sessions_in_use != 0 ||
			 fake.slot->num_sessions != 0 ||
			 fake.slot->session_head != 0 ||
			 fake.slot->session_tail != 0))
		fake.reload_reset_missing = 1;
	fake.expect_reload_reset = 0;
	if (fake.open_sessions >= fake.max_sessions) {
		pthread_mutex_unlock(&fake.lock);
		return CKR_SESSION_COUNT;
	}
	*session = ++fake.next_session;
	fake.open_sessions++;
	pthread_mutex_unlock(&fake.lock);
	return CKR_OK;
}

static CK_RV fake_close_session(CK_SESSION_HANDLE session)
{
	(void)session;
	pthread_mutex_lock(&fake.lock);
	if (fake.open_sessions > 0)
		fake.open_sessions--;
	pthread_mutex_unlock(&fake.lock);
	return CKR_OK;
}

static CK_RV fake_close_all_sessions(CK_SLOT_ID slot_id)
{
	(void)slot_id;
	pthread_mutex_lock(&fake.lock);
	if (fake.slot->sessions_in_use != 0)
		fake.close_while_in_use = 1;
	fake.open_sessions = 0;
	fake.logged_in = 0;
	pthread_mutex_unlock(&fake.lock);
	return CKR_OK;
}

static CK_RV fake_get_session_info(CK_SESSION_HANDLE session,
		CK_SESSION_INFO_PTR info)
{
	(void)session;
	memset(info, 0, sizeof(*info));
	return CKR_OK;
}

static CK_RV fake_login(CK_SESSION_HANDLE session, CK_USER_TYPE user_type,
		CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	CK_RV result;

	(void)session;
	(void)user_type;
	(void)pin;
	(void)pin_len;

	pthread_mutex_lock(&fake.lock);
	fake.login_entered = 1;
	pthread_cond_broadcast(&fake.cond);
	while (fake.pause_login)
		pthread_cond_wait(&fake.cond, &fake.lock);
	result = fake.login_result;
	if (result == CKR_OK)
		fake.logged_in = 1;
	pthread_mutex_unlock(&fake.lock);
	return result;
}

static void deadline_after(struct timespec *deadline, long milliseconds)
{
	clock_gettime(CLOCK_REALTIME, deadline);
	deadline->tv_sec += milliseconds / 1000;
	deadline->tv_nsec += (milliseconds % 1000) * 1000000L;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}
}

static int wait_thread_done(struct thread_state *state, long milliseconds)
{
	struct timespec deadline;
	int done;

	deadline_after(&deadline, milliseconds);
	pthread_mutex_lock(&state->lock);
	while (!state->done) {
		if (pthread_cond_timedwait(&state->cond, &state->lock,
				&deadline) != 0)
			break;
	}
	done = state->done;
	pthread_mutex_unlock(&state->lock);
	return done;
}

static int thread_done(struct thread_state *state)
{
	int done;

	pthread_mutex_lock(&state->lock);
	done = state->done;
	pthread_mutex_unlock(&state->lock);
	return done;
}

static int wait_login_entered(long milliseconds)
{
	struct timespec deadline;
	int entered;

	deadline_after(&deadline, milliseconds);
	pthread_mutex_lock(&fake.lock);
	while (!fake.login_entered) {
		if (pthread_cond_timedwait(&fake.cond, &fake.lock,
				&deadline) != 0)
			break;
	}
	entered = fake.login_entered;
	pthread_mutex_unlock(&fake.lock);
	return entered;
}

static void thread_state_init(struct thread_state *state,
		PKCS11_SLOT_private *slot)
{
	memset(state, 0, sizeof(*state));
	state->slot = slot;
	pthread_mutex_init(&state->lock, NULL);
	pthread_cond_init(&state->cond, NULL);
}

static void thread_state_destroy(struct thread_state *state)
{
	pthread_cond_destroy(&state->cond);
	pthread_mutex_destroy(&state->lock);
}

static void thread_complete(struct thread_state *state, int rv, int acquired)
{
	pthread_mutex_lock(&state->lock);
	state->rv = rv;
	state->acquired = acquired;
	state->done = 1;
	pthread_cond_broadcast(&state->cond);
	pthread_mutex_unlock(&state->lock);
}

static void *keygen_thread(void *arg)
{
	struct thread_state *state = arg;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	int rv;

	if (state->delay_transition_unlock)
		session_pool_test_delay_transition_unlock(state->slot);
	rv = pkcs11_session_pool_acquire_keygen(state->slot, &session);
	if (rv == 0)
		pkcs11_session_pool_release(state->slot, session);
	thread_complete(state, rv, rv == 0);
	return NULL;
}

static void *acquire_thread(void *arg)
{
	struct thread_state *state = arg;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	int rv;

	rv = pkcs11_session_pool_acquire(state->slot, 0, &session);
	if (rv == 0)
		pkcs11_session_pool_release(state->slot, session);
	thread_complete(state, rv, rv == 0);
	return NULL;
}

static void *mode_thread(void *arg)
{
	struct thread_state *state = arg;

	thread_complete(state,
		pkcs11_session_pool_set_mode(state->slot, state->mode), 0);
	return NULL;
}

static void fake_init(PKCS11_SLOT_private *slot, unsigned int max_sessions)
{
	memset(&fake, 0, sizeof(fake));
	fake.slot = slot;
	fake.max_sessions = max_sessions;
	pthread_mutex_init(&fake.lock, NULL);
	pthread_cond_init(&fake.cond, NULL);
}

static void fake_destroy(void)
{
	pthread_cond_destroy(&fake.cond);
	pthread_mutex_destroy(&fake.lock);
}

static void slot_init(PKCS11_SLOT_private *slot, PKCS11_CTX_private *ctx,
		CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE *pool,
		unsigned int max_sessions)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->method = method;
	memset(slot, 0, sizeof(*slot));
	slot->ctx = ctx;
	slot->rw_mode = -1;
	slot->logged_in = -1;
	slot->session_pool = pool;
	slot->session_poolsize = max_sessions + 1;
	slot->max_sessions = max_sessions;
	pthread_mutex_init(&slot->lock, NULL);
	pthread_cond_init(&slot->cond, NULL);
}

static void slot_destroy(PKCS11_SLOT_private *slot)
{
	if (slot->prev_pin) {
		OPENSSL_cleanse(slot->prev_pin, strlen(slot->prev_pin));
		OPENSSL_free(slot->prev_pin);
	}
	pthread_cond_destroy(&slot->cond);
	pthread_mutex_destroy(&slot->lock);
}

static int wait_for_transition(PKCS11_SLOT_private *slot, long milliseconds)
{
	struct timespec delay = {0, 1000000L};
	long elapsed;
	int active;

	for (elapsed = 0; elapsed < milliseconds; elapsed++) {
		pthread_mutex_lock(&slot->lock);
		active = slot->transition_active;
		pthread_mutex_unlock(&slot->lock);
		if (active)
			return 1;
		nanosleep(&delay, NULL);
	}
	return 0;
}

static int transition_waiter_test(CK_FUNCTION_LIST_PTR method)
{
	PKCS11_CTX_private ctx;
	PKCS11_SLOT_private slot;
	CK_SESSION_HANDLE pool[2], held;
	struct thread_state keygen, mode;
	pthread_t keygen_id, mode_id;
	struct timespec delay = {0, 200000000L};
	int failed = 0;

	slot_init(&slot, &ctx, method, pool, 1);
	fake_init(&slot, 1);
	slot.rw_mode = 1;
	if (pkcs11_session_pool_acquire(&slot, 1, &held) != 0) {
		fprintf(stderr, "could not acquire the initial session\n");
		failed = 1;
		goto out;
	}

	thread_state_init(&keygen, &slot);
	thread_state_init(&mode, &slot);
	keygen.delay_transition_unlock = 1;
	mode.mode = 0;
	pthread_create(&keygen_id, NULL, keygen_thread, &keygen);
	if (!wait_for_transition(&slot, 1000)) {
		fprintf(stderr, "key-generation transition did not start\n");
		failed = 1;
		goto threads_out;
	}
	pthread_create(&mode_id, NULL, mode_thread, &mode);
	/* Give the second transition time to wait on the shared condition. */
	nanosleep(&delay, NULL);
	pkcs11_session_pool_release(&slot, held);

	if (!wait_thread_done(&keygen, TEST_TIMEOUT_SECONDS * 1000) ||
			!wait_thread_done(&mode, TEST_TIMEOUT_SECONDS * 1000)) {
		fprintf(stderr, "session-pool transition waiters deadlocked\n");
		failed = 1;
		goto threads_out;
	}
	pthread_join(keygen_id, NULL);
	pthread_join(mode_id, NULL);
	if (keygen.rv != 0 || mode.rv != 0 || fake.close_while_in_use) {
		fprintf(stderr, "session-pool transition waiter test failed\n");
		failed = 1;
	}

threads_out:
	if (!thread_done(&keygen) || !thread_done(&mode))
		return 1;
	thread_state_destroy(&keygen);
	thread_state_destroy(&mode);
out:
	fake_destroy();
	slot_destroy(&slot);
	return failed;
}

static int relogin_gate_test(CK_FUNCTION_LIST_PTR method)
{
	PKCS11_CTX_private ctx;
	PKCS11_SLOT_private slot;
	CK_SESSION_HANDLE pool[3];
	struct thread_state keygen, acquire;
	pthread_t keygen_id, acquire_id;
	unsigned int open_sessions;
	int failed = 0;

	slot_init(&slot, &ctx, method, pool, 2);
	fake_init(&slot, 2);
	slot.rw_mode = 0;
	if (pkcs11_login(&slot, 0, "1234") != 0) {
		fprintf(stderr, "could not establish the initial login\n");
		failed = 1;
		goto out;
	}

	thread_state_init(&keygen, &slot);
	thread_state_init(&acquire, &slot);
	pthread_mutex_lock(&fake.lock);
	fake.login_entered = 0;
	fake.pause_login = 1;
	pthread_mutex_unlock(&fake.lock);
	pthread_create(&keygen_id, NULL, keygen_thread, &keygen);
	if (!wait_login_entered(1000)) {
		fprintf(stderr, "key-generation relogin did not start\n");
		failed = 1;
		goto threads_out;
	}

	pthread_create(&acquire_id, NULL, acquire_thread, &acquire);
	if (wait_thread_done(&acquire, 200)) {
		fprintf(stderr, "normal acquisition passed the relogin gate\n");
		failed = 1;
	}
	pthread_mutex_lock(&fake.lock);
	open_sessions = fake.open_sessions;
	fake.pause_login = 0;
	pthread_cond_broadcast(&fake.cond);
	pthread_mutex_unlock(&fake.lock);
	if (open_sessions != 1) {
		fprintf(stderr, "normal acquisition reached the module during relogin\n");
		failed = 1;
	}

	if (!wait_thread_done(&keygen, TEST_TIMEOUT_SECONDS * 1000) ||
			!wait_thread_done(&acquire, TEST_TIMEOUT_SECONDS * 1000)) {
		fprintf(stderr, "relogin gate test deadlocked\n");
		return 1;
	}
	pthread_join(keygen_id, NULL);
	pthread_join(acquire_id, NULL);
	if (keygen.rv != 0 || acquire.rv != 0 ||
			fake.close_while_in_use) {
		fprintf(stderr, "relogin gate operations failed\n");
		failed = 1;
	}

threads_out:
	if (!thread_done(&keygen) || !thread_done(&acquire))
		return 1;
	thread_state_destroy(&keygen);
	thread_state_destroy(&acquire);
out:
	fake_destroy();
	slot_destroy(&slot);
	return failed;
}

static int transition_error_test(CK_FUNCTION_LIST_PTR method)
{
	PKCS11_CTX_private ctx;
	PKCS11_SLOT_private slot;
	CK_SESSION_HANDLE pool[3], session;
	int failed = 0;

	slot_init(&slot, &ctx, method, pool, 2);
	fake_init(&slot, 2);
	slot.rw_mode = 0;
	if (pkcs11_login(&slot, 0, "1234") != 0) {
		fprintf(stderr, "could not establish login for error test\n");
		failed = 1;
		goto out;
	}
	pthread_mutex_lock(&fake.lock);
	fake.login_result = CKR_PIN_INCORRECT;
	pthread_mutex_unlock(&fake.lock);
	if (pkcs11_session_pool_acquire_keygen(&slot, &session) == 0) {
		fprintf(stderr, "key-generation relogin unexpectedly succeeded\n");
		pkcs11_session_pool_release(&slot, session);
		failed = 1;
	}
	pthread_mutex_lock(&slot.lock);
	if (slot.transition_active != 0 || slot.sessions_in_use != 0)
		failed = 1;
	pthread_mutex_unlock(&slot.lock);
	if (failed)
		fprintf(stderr, "failed transition did not restore pool state\n");

	pthread_mutex_lock(&fake.lock);
	fake.login_result = CKR_OK;
	pthread_mutex_unlock(&fake.lock);
	if (pkcs11_session_pool_acquire(&slot, 1, &session) != 0) {
		fprintf(stderr, "pool did not recover after failed relogin\n");
		failed = 1;
	} else {
		pkcs11_session_pool_release(&slot, session);
	}

out:
	fake_destroy();
	slot_destroy(&slot);
	return failed;
}

static int fork_reload_test(CK_FUNCTION_LIST_PTR method)
{
	PKCS11_CTX_private ctx;
	PKCS11_SLOT_private slot;
	CK_SESSION_HANDLE pool[3];
	int failed = 0;

	slot_init(&slot, &ctx, method, pool, 2);
	fake_init(&slot, 2);
	slot.rw_mode = 0;
	if (pkcs11_login(&slot, 0, "1234") != 0) {
		fprintf(stderr, "could not establish login before reload\n");
		failed = 1;
		goto out;
	}

	/* Model inherited parent state.  No parent thread or lease survives. */
	slot.transition_active = 1;
	slot.sessions_in_use = 1;
	slot.num_sessions = 2;
	slot.session_head = 1;
	slot.session_tail = 2;
	pthread_mutex_lock(&fake.lock);
	fake.expect_reload_reset = 1;
	pthread_mutex_unlock(&fake.lock);
	if (pkcs11_reload_slot(&slot) != 0) {
		fprintf(stderr, "slot reload failed\n");
		failed = 1;
	}
	if (slot.transition_active != 0 || slot.sessions_in_use != 0 ||
			fake.reload_reset_missing) {
		fprintf(stderr, "slot reload inherited stale transition state\n");
		failed = 1;
	}

out:
	fake_destroy();
	slot_destroy(&slot);
	return failed;
}

int main(void)
{
	CK_FUNCTION_LIST method;
	int failed = 0;

	memset(&method, 0, sizeof(method));
	method.C_OpenSession = fake_open_session;
	method.C_CloseSession = fake_close_session;
	method.C_CloseAllSessions = fake_close_all_sessions;
	method.C_GetSessionInfo = fake_get_session_info;
	method.C_Login = fake_login;

	failed = transition_waiter_test(&method);
	if (!failed)
		failed = relogin_gate_test(&method);
	if (!failed)
		failed = transition_error_test(&method);
	if (!failed)
		failed = fork_reload_test(&method);
	if (failed)
		return EXIT_FAILURE;
	printf("session-pool concurrency tests passed\n");
	return EXIT_SUCCESS;
}

#else /* HAVE_PTHREAD */

int main(void)
{
	fprintf(stderr, "Skipped: pthread support not available\n");
	return 77;
}

#endif /* HAVE_PTHREAD */

/* vim: set noexpandtab: */
