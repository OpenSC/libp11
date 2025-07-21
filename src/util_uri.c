/*
 * Copyright (c) 2001 Markus Friedl
 * Copyright (c) 2002 Juha Yrjölä
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
 * Copyright (c) 2016-2025 Michał Trojnara <Michal.Trojnara@stunnel.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "util.h"
#include "p11_pthread.h"
#include <stdio.h>
#include <string.h>

#if defined(_WIN32) && !defined(strncasecmp)
#define strncasecmp _strnicmp
#else
#include <strings.h>
#endif

/* switch to legacy call if get0 variant is not available */
#ifndef HAVE_X509_GET0_NOTBEFORE
#	define X509_get0_notBefore X509_get_notBefore
#endif

#ifndef HAVE_X509_GET0_NOTAFTER
#	define X509_get0_notAfter X509_get_notAfter
#endif

struct util_ctx_st {
	/* Configuration */
	char *module;
	char *init_args;
	UI_METHOD *ui_method;
	void *ui_data;

	/* Logging */
	int debug_level;                             /* level of debug output */
	void (*vlog)(int, const char *, va_list); /* for the logging callback */

	/*
	 * The PIN used for login, cached by the UTIL_CTX_set_pin function.
	 * The memory for this PIN is always owned internally, and may be freed
	 * as necessary. Before freeing, the PIN must be cleansed.
	 */
	char *pin;
	size_t pin_length;
	int forced_pin;
	int force_login;

	/* Current operations */
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *slot_list;
	unsigned int slot_count;
	pthread_mutex_t lock;

};

static int g_shutdown_mode = 0;

/******************************************************************************/
/* Initialization                                                             */
/******************************************************************************/

UTIL_CTX *UTIL_CTX_new()
{
	UTIL_CTX *ctx = OPENSSL_malloc(sizeof(UTIL_CTX));

	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(UTIL_CTX));
	pthread_mutex_init(&ctx->lock, 0);
	return ctx;
}

void UTIL_CTX_free(UTIL_CTX *ctx)
{
	UTIL_CTX_set_pin(ctx, NULL);
	OPENSSL_free(ctx->module);
	OPENSSL_free(ctx->init_args);
	pthread_mutex_destroy(&ctx->lock);
	OPENSSL_free(ctx);
}

int UTIL_CTX_set_module(UTIL_CTX *ctx, const char *module)
{
	OPENSSL_free(ctx->module);
	ctx->module = module ? OPENSSL_strdup(module) : NULL;
	return 1;
}

int UTIL_CTX_set_init_args(UTIL_CTX *ctx, const char *init_args)
{
	OPENSSL_free(ctx->init_args);
	ctx->init_args = init_args ? OPENSSL_strdup(init_args) : NULL;
	return 1;
}

int UTIL_CTX_set_ui_method(UTIL_CTX *ctx, UI_METHOD *ui_method, void *ui_data)
{
	ctx->ui_method = ui_method;
	ctx->ui_data = ui_data;
	if (ctx->pkcs11_ctx) /* libp11 is already initialized */
		PKCS11_set_ui_method(ctx->pkcs11_ctx, ui_method, ui_data);
	return 1;
}

static int util_ctx_enumerate_slots_unlocked(UTIL_CTX *ctx)
{
	/* PKCS11_update_slots() uses C_GetSlotList() via libp11 */
	if (PKCS11_update_slots(ctx->pkcs11_ctx, &ctx->slot_list, &ctx->slot_count) < 0) {
		UTIL_CTX_log(ctx, LOG_ERR, "Failed to enumerate slots\n");
		return 0;
	}
	if (!ctx->slot_list || ctx->slot_count < 1) {
		UTIL_CTX_log(ctx, LOG_ERR, "No slot found\n");
		return 0;
	}
	UTIL_CTX_log(ctx, LOG_INFO, "Found %u slot%s\n", ctx->slot_count,
		ctx->slot_count <= 1 ? "" : "s");
	return 1;
}

/*
 * PKCS#11 modules that register their own atexit() callbacks may already have
 * been cleaned up by the time OpenSSL's atexit() callback is executed.
 * As a result, a crash occurs with certain versions of OpenSSL and SoftHSM2.
 * The workaround skips libp11 cleanup during OpenSSL's cleanup, converting
 * the crash into a harmless memory leak at exit.
 */
static void exit_callback(void)
{
	const char *str = getenv("PKCS11_FORCE_CLEANUP");

	if (str && (!strcmp(str, "1") || !strcasecmp(str, "yes")))
		return;
	g_shutdown_mode = 1;
}

/* Initialize libp11 data: ctx->pkcs11_ctx and ctx->slot_list */
static int util_ctx_init_libp11(UTIL_CTX *ctx)
{
	if (ctx->pkcs11_ctx && ctx->slot_list && ctx->slot_count > 0)
		return 0;

	UTIL_CTX_log(ctx, LOG_NOTICE, "PKCS#11: Initializing the module: %s\n", ctx->module);

	ctx->pkcs11_ctx = PKCS11_CTX_new();
	if (!ctx->pkcs11_ctx)
		return -1;
	PKCS11_set_vlog_a_method(ctx->pkcs11_ctx, ctx->vlog);
	PKCS11_CTX_init_args(ctx->pkcs11_ctx, ctx->init_args);
	PKCS11_set_ui_method(ctx->pkcs11_ctx, ctx->ui_method, ctx->ui_data);
	if (PKCS11_CTX_load(ctx->pkcs11_ctx, ctx->module) < 0) {
		UTIL_CTX_log(ctx, LOG_ERR, "Unable to load module %s\n", ctx->module);
		UTIL_CTX_free_libp11(ctx);
		return -1;
	}
	if (util_ctx_enumerate_slots_unlocked(ctx) != 1) {
		UTIL_CTX_free_libp11(ctx);
		return -1;
	}
	atexit(exit_callback);
	return 0;
}

int UTIL_CTX_enumerate_slots(UTIL_CTX *ctx)
{
	int rv;

	pthread_mutex_lock(&ctx->lock);
	if (ctx->pkcs11_ctx)
		rv = util_ctx_enumerate_slots_unlocked(ctx);
	else
		rv = util_ctx_init_libp11(ctx) == 0;
	pthread_mutex_unlock(&ctx->lock);
	return rv;
}

void UTIL_CTX_free_libp11(UTIL_CTX *ctx)
{
	if (ctx->slot_list) {
		if (!g_shutdown_mode)
			PKCS11_release_all_slots(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count);
		ctx->slot_list = NULL;
		ctx->slot_count = 0;
	}
	if (ctx->pkcs11_ctx) {
		if (!g_shutdown_mode) {
			PKCS11_CTX_unload(ctx->pkcs11_ctx);
			PKCS11_CTX_free(ctx->pkcs11_ctx);
		}
		ctx->pkcs11_ctx = NULL;
	}
}

/******************************************************************************/
/* Utility functions                                                          */
/******************************************************************************/

void UTIL_CTX_set_vlog_a(UTIL_CTX *ctx, PKCS11_VLOG_A_CB vlog)
{
	ctx->vlog = vlog;

	if (ctx->pkcs11_ctx) /* already initialized */
		PKCS11_set_vlog_a_method(ctx->pkcs11_ctx, vlog); /* update */
}

void UTIL_CTX_set_debug_level(UTIL_CTX *ctx, int debug_level)
{
	ctx->debug_level = debug_level;
}

void UTIL_CTX_log(UTIL_CTX *ctx, int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	if (!ctx) {
		vfprintf(stderr, format, args);
	} else if (ctx->vlog) {
		/* Log messages through a custom logging function */
		const char *prefix = "util: ";
		char *vlog_format = OPENSSL_malloc(strlen(prefix) + strlen(format) + 1);

		if (!vlog_format) {
			va_end(args);
			return;
		}
		/* Copy and concatenate strings */
		strcpy(vlog_format, prefix);
		strcat(vlog_format, format);

		ctx->vlog(level, (const char *)vlog_format, args);
		OPENSSL_free(vlog_format);
	} else if (level <= ctx->debug_level) {
		if (level <= 4) { /* LOG_WARNING */
			vfprintf(stderr, format, args);
		} else {
			vprintf(format, args);
		}
	}
	va_end(args);
}

static char *dump_hex(unsigned char *val, const size_t len)
{
	int j = 0;
	size_t i, size = 2 * len + 1;
	char *hexbuf = OPENSSL_malloc((size_t)size);

	if (!hexbuf)
		return NULL;
	for (i = 0; i < len; i++) {
#ifdef WIN32
		j += sprintf_s(hexbuf + j, size - j, "%02X", val[i]);
#else
		j += sprintf(hexbuf + j, "%02X", val[i]);
#endif /* WIN32 */
	}
	return hexbuf;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static char *OPENSSL_strndup(const char *str, size_t s)
{
	size_t len;
	char *ret;

	if (!str || !s)
		return NULL;
	len = strnlen(str, s);
	ret = OPENSSL_malloc(len + 1);
	if (ret) {
		memcpy(ret, str, len);
		ret[len] = '\0';
	}
	return ret;
}
#endif

static char *dump_expiry(const PKCS11_CERT *cert)
{
	BIO *bio;
	const ASN1_TIME *exp;
	char *buf = NULL, *result;
	int len = 0;

	if (!cert || !cert->x509 || !(exp = X509_get0_notAfter(cert->x509)))
		return OPENSSL_strdup("No expiry information available");

	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		return NULL; /* Memory allocation failure */

	/* Print the expiry date into the BIO */
	if (ASN1_TIME_print(bio, exp) <= 0) {
		BIO_free(bio);
		return NULL; /* Failed to format expiry date */
	}
	/* Retrieve the data from the BIO */
	len = BIO_get_mem_data(bio, &buf);

	result = OPENSSL_strndup((const char *)buf, (size_t)len);
	BIO_free(bio);

	return result;
}

static int hex_to_bin(UTIL_CTX *ctx,
		const char *in, char *out, size_t *outlen)
{
	size_t left, count = 0;

	if (!in || *in == '\0') {
		*outlen = 0;
		return 1;
	}

	left = *outlen;

	while (*in != '\0') {
		int byte = 0, nybbles = 2;

		while (nybbles-- && *in && *in != ':') {
			char c;
			byte <<= 4;
			c = *in++;
			if ('0' <= c && c <= '9')
				c -= '0';
			else if ('a' <= c && c <= 'f')
				c = c - 'a' + 10;
			else if ('A' <= c && c <= 'F')
				c = c - 'A' + 10;
			else {
				UTIL_CTX_log(ctx, LOG_ERR,
					"hex_to_bin(): invalid char '%c' in hex string\n",
					c);
				*outlen = 0;
				return 0;
			}
			byte |= c;
		}
		if (*in == ':')
			in++;
		if (left == 0) {
			UTIL_CTX_log(ctx, LOG_ERR, "hex_to_bin(): hex string too long\n");
			*outlen = 0;
			return 0;
		}
		out[count++] = byte;
		left--;
	}

	*outlen = count;
	return 1;
}

/******************************************************************************/
/* PIN handling                                                               */
/******************************************************************************/

/**
 * Set the PIN used for login. A copy of the PIN shall be made.
 *
 * If the PIN cannot be assigned, the value 0 shall be returned
 * and errno shall be set as follows:
 *
 *   EINVAL - a NULL PIN was supplied
 *   ENOMEM - insufficient memory to copy the PIN
 *
 * @param pin the pin to use for login. Must not be NULL.
 *
 * @return 1 on success, 0 on failure.
 */
int UTIL_CTX_set_pin(UTIL_CTX *ctx, const char *pin)
{
		/* Free PIN storage in secure way. */
		if (ctx->pin) {
			OPENSSL_cleanse(ctx->pin, ctx->pin_length);
			OPENSSL_free(ctx->pin);
			ctx->pin = NULL;
			ctx->pin_length = 0;
			ctx->forced_pin = 0;
		}

		if (!pin)
			return 1; /* No new PIN to set */

		ctx->pin = OPENSSL_strdup(pin);
		if (!ctx->pin) {
				errno = ENOMEM;
				return 0;
		}
		ctx->pin_length = strlen(ctx->pin);
		ctx->forced_pin = 1;
		return 1;
}

/* Get the PIN via asking user interface. The supplied call-back data are
 * passed to the user interface implemented by an application. Only the
 * application knows how to interpret the call-back data.
 * A (strdup'ed) copy of the PIN will be stored in the pin variable. */
static int util_ctx_get_pin(UTIL_CTX *ctx, const char *token_label,
		UI_METHOD *ui_method, void *ui_data)
{
	UI *ui;
	char *prompt;

	/* call ui to ask for a pin */
	ui = UI_new_method(ui_method);
	if (!ui) {
		UTIL_CTX_log(ctx, LOG_ERR, "UI_new failed\n");
		return 0;
	}
	if (ui_data)
		UI_add_user_data(ui, ui_data);

	UTIL_CTX_set_pin(ctx, NULL);
	ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
	if (!ctx->pin)
		return 0;
	memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
	ctx->pin_length = MAX_PIN_LENGTH;
	prompt = UI_construct_prompt(ui, "PKCS#11 token PIN", token_label);
	if (!prompt)
		return 0;
	if (UI_dup_input_string(ui, prompt,
			UI_INPUT_FLAG_DEFAULT_PWD, ctx->pin, 4, MAX_PIN_LENGTH) <= 0) {
		UTIL_CTX_log(ctx, LOG_ERR, "UI_dup_input_string failed\n");
		UI_free(ui);
		OPENSSL_free(prompt);
		return 0;
	}
	OPENSSL_free(prompt);

	if (UI_process(ui)) {
		UTIL_CTX_log(ctx, LOG_ERR, "UI_process failed\n");
		UI_free(ui);
		return 0;
	}
	UI_free(ui);
	return 1;
}

void UTIL_CTX_set_force_login(UTIL_CTX *ctx, int force_login)
{
	ctx->force_login = force_login;
}

/* Return 1 if the user has already logged in */
static int slot_logged_in(UTIL_CTX *ctx, PKCS11_SLOT *slot) {
	int logged_in = 0;

	/* Check if already logged in to avoid resetting state */
	if (PKCS11_is_logged_in(slot, 0, &logged_in) != 0) {
		UTIL_CTX_log(ctx, LOG_WARNING, "Unable to check if already logged in\n");
		return 0;
	}
	return logged_in;
}

/*
 * Log-into the token if necessary.
 *
 * @slot is PKCS11 slot to log in
 * @tok is PKCS11 token to log in (??? could be derived as @slot->token)
 * @return 1 on success, 0 on error.
 */
static int util_ctx_login(UTIL_CTX *ctx, PKCS11_SLOT *slot, PKCS11_TOKEN *tok,
		UI_METHOD *ui_method, void *ui_data)
{
	if (!(ctx->force_login || tok->loginRequired) || slot_logged_in(ctx, slot))
		return 1;

	/* If the token has a secure login (i.e., an external keypad),
	 * then use a NULL PIN. Otherwise, obtain a new PIN if needed. */
	if (tok->secureLogin && !ctx->forced_pin) {
		/* Free the PIN if it has already been
		 * assigned (i.e, cached by util_ctx_get_pin) */
		UTIL_CTX_set_pin(ctx, NULL);
	} else if (!ctx->pin) {
		ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
		ctx->pin_length = MAX_PIN_LENGTH;
		if (ctx->pin == NULL) {
			UTIL_CTX_log(ctx, LOG_ERR, "Could not allocate memory for PIN\n");
			return 0;
		}
		memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
		if (!util_ctx_get_pin(ctx, tok->label, ui_method, ui_data)) {
			UTIL_CTX_set_pin(ctx, NULL);
			UTIL_CTX_log(ctx, LOG_ERR, "No PIN was entered\n");
			return 0;
		}
	}

	/* Now login in with the (possibly NULL) PIN */
	if (PKCS11_login(slot, 0, ctx->pin)) {
		/* Login failed, so free the PIN if present */
		UTIL_CTX_set_pin(ctx, NULL);
		UTIL_CTX_log(ctx, LOG_ERR, "Login failed\n");
		return 0;
	}
	return 1;
}

/******************************************************************************/
/* URI parsing                                                                */
/******************************************************************************/

/* parse string containing slot and id information */
static int parse_slot_id_string(UTIL_CTX *ctx,
		const char *slot_id, int *slot,
		char *id, size_t *id_len, char **label)
{
	int n;
	size_t i;

	/* support for several formats */
#define HEXDIGITS "01234567890ABCDEFabcdef"
#define DIGITS "0123456789"

	/* first: pure hex number (id, slot is undefined) */
	if (strspn(slot_id, HEXDIGITS) == strlen(slot_id)) {
		/* ah, easiest case: only hex. */
		if ((strlen(slot_id) + 1) / 2 > *id_len) {
			UTIL_CTX_log(ctx, LOG_ERR, "ID string too long!\n");
			return 0;
		}
		*slot = -1;
		return hex_to_bin(ctx, slot_id, id, id_len);
	}

	/* second: slot:id. slot is an digital int. */
	if (sscanf(slot_id, "%d", &n) == 1) {
		i = strspn(slot_id, DIGITS);

		if (slot_id[i] != ':') {
			UTIL_CTX_log(ctx, LOG_ERR, "Could not parse string!\n");
			return 0;
		}
		i++;
		if (slot_id[i] == 0) {
			*slot = n;
			*id_len = 0;
			return 1;
		}
		if (strspn(slot_id + i, HEXDIGITS) + i != strlen(slot_id)) {
			UTIL_CTX_log(ctx, LOG_ERR, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i + 1) / 2 > *id_len) {
			UTIL_CTX_log(ctx, LOG_ERR, "ID string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(ctx, slot_id + i, id, id_len);
	}

	/* third: id_<id>, slot is undefined */
	if (strncmp(slot_id, "id_", 3) == 0) {
		if (strspn(slot_id + 3, HEXDIGITS) + 3 != strlen(slot_id)) {
			UTIL_CTX_log(ctx, LOG_ERR, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - 3 + 1) / 2 > *id_len) {
			UTIL_CTX_log(ctx, LOG_ERR, "ID string too long!\n");
			return 0;
		}
		*slot = -1;
		return hex_to_bin(ctx, slot_id + 3, id, id_len);
	}

	/* label_<label>, slot is undefined */
	if (strncmp(slot_id, "label_", 6) == 0) {
		*slot = -1;
		*label = OPENSSL_strdup(slot_id + 6);
		*id_len = 0;
		return *label != NULL;
	}

	/* last try: it has to be slot_<slot> and then "-id_<cert>" */

	if (strncmp(slot_id, "slot_", 5) != 0) {
		UTIL_CTX_log(ctx, LOG_ERR, "Format not recognized!\n");
		return 0;
	}

	/* slot is an digital int. */
	if (sscanf(slot_id + 5, "%d", &n) != 1) {
		UTIL_CTX_log(ctx, LOG_ERR, "Could not decode slot number!\n");
		return 0;
	}

	i = strspn(slot_id + 5, DIGITS);

	if (slot_id[i + 5] == 0) {
		*slot = n;
		*id_len = 0;
		return 1;
	}

	if (slot_id[i + 5] != '-') {
		UTIL_CTX_log(ctx, LOG_ERR, "Could not parse string!\n");
		return 0;
	}

	i = 5 + i + 1;

	/* now followed by "id_" */
	if (strncmp(slot_id + i, "id_", 3) == 0) {
		if (strspn(slot_id + i + 3, HEXDIGITS) + 3 + i != strlen(slot_id)) {
			UTIL_CTX_log(ctx, LOG_ERR, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i - 3 + 1) / 2 > *id_len) {
			UTIL_CTX_log(ctx, LOG_ERR, "ID string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(ctx, slot_id + i + 3, id, id_len);
	}

	/* ... or "label_" */
	if (strncmp(slot_id + i, "label_", 6) == 0) {
		*slot = n;
		*label = OPENSSL_strdup(slot_id + i + 6);
		*id_len = 0;
		return *label != NULL;
	}

	UTIL_CTX_log(ctx, LOG_ERR, "Could not parse string!\n");
	return 0;
}

static int parse_uri_attr_len(UTIL_CTX *ctx,
		const char *attr, int attrlen, char *field,
		size_t *field_len)
{
	size_t max = *field_len, outlen = 0;
	int ret = 1;

	while (ret && attrlen && outlen < max) {
		if (*attr == '%') {
			if (attrlen < 3) {
				ret = 0;
			} else {
				char tmp[3];
				size_t l = 1;

				tmp[0] = attr[1];
				tmp[1] = attr[2];
				tmp[2] = 0;
				ret = hex_to_bin(ctx, tmp, &field[outlen++], &l);
				attrlen -= 3;
				attr += 3;
			}

		} else {
			field[outlen++] = *(attr++);
			attrlen--;
		}
	}
	if (attrlen && outlen == max)
		ret = 0;

	if (ret)
		*field_len = outlen;

	return ret;
}

static int parse_uri_attr(UTIL_CTX *ctx,
		const char *attr, int attrlen, char **field)
{
	int ret = 1;
	size_t outlen = attrlen + 1;
	char *out = OPENSSL_malloc(outlen);

	if (!out)
		return 0;

	ret = parse_uri_attr_len(ctx, attr, attrlen, out, &outlen);

	if (ret) {
		out[outlen] = 0;
		*field = out;
	} else {
		OPENSSL_free(out);
	}

	return ret;
}


static int read_from_file(UTIL_CTX *ctx,
	const char *path, char *field, size_t *field_len)
{
	BIO *fp;
	char *txt;

	fp = BIO_new_file(path, "r");
	if (!fp) {
		UTIL_CTX_log(ctx, LOG_ERR, "Could not open file %s\n", path);
		return 0;
	}

	txt = OPENSSL_malloc(*field_len + 1); /* + 1 for '\0' */
	if (!txt) {
		BIO_free(fp);
		return 0;
	}
	if (BIO_gets(fp, txt, (int)*field_len + 1) > 0) {
		size_t len = strlen(txt);

		while (len > 0 && (txt[len - 1] == '\n' || txt[len - 1] == '\r'))
			len--;
		memcpy(field, txt, len);
		*field_len = len;
	} else {
		*field_len = 0;
	}
	OPENSSL_free(txt);

	BIO_free(fp);
	return 1;
}

static int parse_pin_source(UTIL_CTX *ctx,
		const char *attr, int attrlen, char *field,
		size_t *field_len)
{
	char *val;
	int ret = 1;

	if (!parse_uri_attr(ctx, attr, attrlen, &val)) {
		return 0;
	}

	if (!strncasecmp((const char *)val, "file:", 5)) {
		ret = read_from_file(ctx, (const char *)(val + 5), field, field_len);
	} else if (*val == '|') {
		ret = 0;
		UTIL_CTX_log(ctx, LOG_ERR, "Unsupported pin-source syntax\n");
	/* 'pin-source=/foo/bar' is commonly used */
	} else {
		ret = read_from_file(ctx, (const char *)val, field, field_len);
	}
	OPENSSL_free(val);

	return ret;
}

static int parse_pkcs11_uri(UTIL_CTX *ctx,
		const char *uri, PKCS11_TOKEN **p_tok,
		char *id, size_t *id_len, char *pin, size_t *pin_len,
		char **label)
{
	PKCS11_TOKEN *tok;
	char *newlabel = NULL;
	const char *end, *p;
	int rv = 1, id_set = 0, pin_set = 0;

	tok = OPENSSL_malloc(sizeof(PKCS11_TOKEN));
	if (!tok) {
		UTIL_CTX_log(ctx, LOG_ERR, "Could not allocate memory for token info\n");
		return 0;
	}
	memset(tok, 0, sizeof(PKCS11_TOKEN));

	/* We are only ever invoked if the string starts with 'pkcs11:' */
	end = uri + 6;
	while (rv && end[0] && end[1]) {
		p = end + 1;
		end = strpbrk(p, ";?&");
		if (!end)
			end = p + strlen(p);

		if (!strncmp(p, "model=", 6)) {
			p += 6;
			rv = parse_uri_attr(ctx, p, (int)(end - p), &tok->model);
		} else if (!strncmp(p, "manufacturer=", 13)) {
			p += 13;
			rv = parse_uri_attr(ctx, p, (int)(end - p), &tok->manufacturer);
		} else if (!strncmp(p, "token=", 6)) {
			p += 6;
			rv = parse_uri_attr(ctx, p, (int)(end - p), &tok->label);
		} else if (!strncmp(p, "serial=", 7)) {
			p += 7;
			rv = parse_uri_attr(ctx, p, (int)(end - p), &tok->serialnr);
		} else if (!strncmp(p, "object=", 7)) {
			p += 7;
			rv = parse_uri_attr(ctx, p, (int)(end - p), &newlabel);
		} else if (!strncmp(p, "id=", 3)) {
			p += 3;
			rv = parse_uri_attr_len(ctx, p, (int)(end - p), id, id_len);
			id_set = 1;
		} else if (!strncmp(p, "pin-value=", 10)) {
			p += 10;
			rv = pin_set ? 0 : parse_uri_attr_len(ctx, p, (int)(end - p), pin, pin_len);
			pin_set = 1;
		} else if (!strncmp(p, "pin-source=", 11)) {
			p += 11;
			rv = pin_set ? 0 : parse_pin_source(ctx, p, (int)(end - p), pin, pin_len);
			pin_set = 1;
		} else if (!strncmp(p, "type=", 5) || !strncmp(p, "object-type=", 12)) {
			p = strchr(p, '=') + 1;

			if ((end - p == 4 && !strncmp(p, "cert", 4)) ||
					(end - p == 6 && !strncmp(p, "public", 6)) ||
					(end - p == 7 && !strncmp(p, "private", 7))) {
				/* Actually, just ignore it */
			} else {
				UTIL_CTX_log(ctx, LOG_ERR, "Unknown object type\n");
				rv = 0;
			}
		} else {
			rv = 0;
		}
	}

	if (!id_set)
		*id_len = 0;
	if (!pin_set)
		*pin_len = 0;

	if (rv) {
		*label = newlabel;
		*p_tok = tok;
	} else {
		OPENSSL_free(tok->model);
		OPENSSL_free(tok->manufacturer);
		OPENSSL_free(tok->serialnr);
		OPENSSL_free(tok->label);
		OPENSSL_free(tok);
		tok = NULL;
		OPENSSL_free(newlabel);
	}

	return rv;
}

/******************************************************************************/
/* Utilities common to public, private key and certificate handling           */
/******************************************************************************/

typedef struct {
	int slot_nr;
	char *obj_id;
	size_t obj_id_len;
	char *obj_label;
	PKCS11_SLOT **matched_slots;
	size_t matched_count;
} PARSED;

static int util_ctx_parse_uri(UTIL_CTX *ctx, PARSED *parsed,
		const char *object_typestr, const char *object_uri)
{
	PKCS11_SLOT *slot;
	PKCS11_SLOT *found_slot = NULL;
	PKCS11_TOKEN *match_tok = NULL;
	unsigned int n, m;
	char flags[64];
	int rv = 0;

	parsed->slot_nr = -1;
	if (object_uri && *object_uri) {
		parsed->obj_id_len = strlen(object_uri) + 1;
		parsed->obj_id = OPENSSL_malloc(parsed->obj_id_len);
		if (!parsed->obj_id) {
			UTIL_CTX_log(ctx, LOG_ERR, "Could not allocate memory for ID\n");
			goto cleanup;
		}
		if (!strncasecmp(object_uri, "pkcs11:", 7)) {
			char tmp_pin[MAX_PIN_LENGTH+1];
			size_t tmp_pin_len = MAX_PIN_LENGTH;

			n = parse_pkcs11_uri(ctx, object_uri, &match_tok,
				parsed->obj_id, &parsed->obj_id_len, tmp_pin, &tmp_pin_len, &parsed->obj_label);
			if (!n) {
				UTIL_CTX_log(ctx, LOG_ERR,
					"The %s ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n",
					object_typestr);
				goto cleanup;
			}
			if (tmp_pin_len > 0 && tmp_pin[0] != 0) {
				tmp_pin[tmp_pin_len] = 0;
				if (!UTIL_CTX_set_pin(ctx, tmp_pin)) {
					goto cleanup;
				}
			}
		} else {
			n = parse_slot_id_string(ctx, object_uri, &parsed->slot_nr,
				parsed->obj_id, &parsed->obj_id_len, &parsed->obj_label);
			if (!n) {
				UTIL_CTX_log(ctx, LOG_ERR,
					"The %s ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n"
					"The legacy ENGINE_pkcs11 ID format is also "
					"still accepted for now\n",
					object_typestr);
				goto cleanup;
			}
		}
	}

	parsed->matched_slots = (PKCS11_SLOT **)OPENSSL_malloc(ctx->slot_count * sizeof(PKCS11_SLOT *));
	if (!parsed->matched_slots) {
		UTIL_CTX_log(ctx, LOG_ERR, "Could not allocate memory for slots\n");
		goto cleanup;
	}

	for (n = 0; n < ctx->slot_count; n++) {
		slot = ctx->slot_list + n;
		flags[0] = '\0';
		if (slot->token) {
			if (!slot->token->initialized)
				strcat(flags, "uninitialized, ");
			else if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
		} else {
			strcpy(flags, "no token, ");
		}
		if ((m = (unsigned int)strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (parsed->slot_nr != -1 &&
			parsed->slot_nr == (int)PKCS11_get_slotid_from_slot(slot)) {
			found_slot = slot;
		}

		if (match_tok && slot->token &&
				(!match_tok->label ||
					!strcmp(match_tok->label, slot->token->label)) &&
				(!match_tok->manufacturer ||
					!strcmp(match_tok->manufacturer, slot->token->manufacturer)) &&
				(!match_tok->serialnr ||
					!strcmp(match_tok->serialnr, slot->token->serialnr)) &&
				(!match_tok->model ||
					!strcmp(match_tok->model, slot->token->model))) {
			found_slot = slot;
		}
		UTIL_CTX_log(ctx, LOG_NOTICE, "- [%lu] %-25.25s  %-36s  (%s)\n",
			PKCS11_get_slotid_from_slot(slot),
			slot->description ? slot->description : "(no description)",
			flags, slot->token && slot->token->label[0] ? slot->token->label : "no label");

		/* Ignore slots without tokens. Thales HSM (and potentially
		 * other modules) allow objects on uninitialized tokens. */
		if (found_slot && found_slot->token) {
			parsed->matched_slots[parsed->matched_count] = found_slot;
			parsed->matched_count++;
		}
		found_slot = NULL;
	}

	if (parsed->matched_count == 0) {
		if (match_tok) {
			UTIL_CTX_log(ctx, LOG_ERR, "No matching token was found for %s\n",
				object_typestr);
			goto cleanup;
		}

		/* If the legacy slot ID format was used */
		if (parsed->slot_nr != -1) {
			UTIL_CTX_log(ctx, LOG_ERR, "The %s was not found on slot %d\n",
				 object_typestr, parsed->slot_nr);
			goto cleanup;
		} else {
			found_slot = PKCS11_find_token(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count);
			/* Ignore slots without tokens. Thales HSM (and potentially
			 * other modules) allow objects on uninitialized tokens. */
			if (found_slot && found_slot->token) {
				parsed->matched_slots[parsed->matched_count] = found_slot;
				parsed->matched_count++;
			} else {
				UTIL_CTX_log(ctx, LOG_ERR, "No tokens found\n");
				goto cleanup;
			}
		}
	}

	rv = 1; /* Success */

cleanup:
	/* Free the searched token data */
	if (match_tok) {
		OPENSSL_free(match_tok->model);
		OPENSSL_free(match_tok->manufacturer);
		OPENSSL_free(match_tok->serialnr);
		OPENSSL_free(match_tok->label);
		OPENSSL_free(match_tok);
	}
	return rv;
}

/* In several tokens, certificates are marked as private */
static void *util_ctx_load_object_with_login(UTIL_CTX *ctx, PARSED *parsed,
		void *(*match_func)(UTIL_CTX *, PKCS11_TOKEN *,
				const char *, size_t, const char *),
		UI_METHOD *ui_method, void *ui_data)
{
	PKCS11_SLOT *slot, *init_slot = NULL;
	size_t init_count = 0;
	unsigned int m;

	/* Count slots with initialized tokens and keep the last one */
	for (m = 0; m < parsed->matched_count; m++) {
		slot = parsed->matched_slots[m];
		if (!slot->token) {
			UTIL_CTX_log(ctx, LOG_INFO, "Skipped empty slot: %s\n",
				slot->description ? slot->description : "(no description)");
			continue;
		}
		UTIL_CTX_log(ctx, LOG_INFO, "Found slot: %s\n",
			slot->description ? slot->description : "(no description)");
		if (!slot->token->initialized) {
			UTIL_CTX_log(ctx, LOG_INFO, "Skipped uninitialized token: %s\n",
				slot->description ? slot->description : "(no description)");
			continue;
		}
		UTIL_CTX_log(ctx, LOG_INFO, "Found initialized token: %s\n",
			slot->token->label[0] ?	slot->token->label : "no label");
		init_count++;
		init_slot = slot;
	}

	/* Only try to login if a single slot with an initialized token
	 * matched to avoiding trying the PIN against all matching slots */
	if (init_count == 0 || !init_slot) {
		UTIL_CTX_log(ctx, LOG_NOTICE, "No matching slots found\n");
	} else if (init_count == 1) {
		slot = init_slot;
		UTIL_CTX_log(ctx, LOG_NOTICE, "Found slot: %s\n",
			slot->description ? slot->description : "(no description)");
		UTIL_CTX_log(ctx, LOG_NOTICE, "Found initialized token: %s\n",
			slot->token->label[0] ?	slot->token->label : "no label");
		/* Only try to login if login is required */
		if (slot->token->loginRequired || ctx->force_login) {
			if (!util_ctx_login(ctx, slot, slot->token, ui_method, ui_data)) {
				UTIL_CTX_log(ctx, LOG_ERR, "Login to token failed\n");
				return NULL;
			}
		}
		return match_func(ctx, slot->token,
			parsed->obj_id, parsed->obj_id_len, parsed->obj_label);
	} else { /* Multiple slots with an initialized token */
		UTIL_CTX_log(ctx, LOG_WARNING, "Multiple matching slots (%zu);"
			" will not try to login\n", init_count);
		for (m = 0; m < init_count; m++) {
			slot = parsed->matched_slots[m];
			if (!slot->token || !slot->token->initialized)
				continue;
			UTIL_CTX_log(ctx, LOG_WARNING, "- [%u] %s: %s\n", m + 1,
				slot->description ? slot->description : "(no description)",
				(slot->token && slot->token->label)?
				slot->token->label: "no label");
		}
	}
	return NULL;
}

/* Find an object without logging in */
static void *util_ctx_load_object_without_login(UTIL_CTX *ctx, PARSED *parsed,
		void *(*match_func)(UTIL_CTX *, PKCS11_TOKEN *,
				const char *, size_t, const char *),
		int initialized)
{
	PKCS11_SLOT *slot;
	unsigned int n, matching_slots = 0;
	void *object = NULL;

	for (n = 0; n < parsed->matched_count; n++) {
		slot = parsed->matched_slots[n];
		if (!slot->token) {
			UTIL_CTX_log(ctx, LOG_INFO, "Skipped empty slot: %s\n",
				slot->description ? slot->description : "(no description)");
			continue;
		}
		UTIL_CTX_log(ctx, LOG_INFO, "Found slot: %s\n",
			slot->description ? slot->description : "(no description)");
		if (slot->token->initialized != initialized) {
			UTIL_CTX_log(ctx, LOG_INFO, "Skipped %s token: %s\n",
				slot->token->initialized ? "initialized" : "uninitialized",
				slot->description ? slot->description : "(no description)");
			continue;
		}
		matching_slots++;
		UTIL_CTX_log(ctx, LOG_NOTICE, "Found slot: %s\n",
			slot->description ? slot->description : "(no description)");
		UTIL_CTX_log(ctx, LOG_NOTICE, "Found %s token: %s\n",
			slot->token->initialized ? "initialized" : "uninitialized",
			slot->token && slot->token->label[0] ? slot->token->label : "no label");
		object = match_func(ctx, slot->token, parsed->obj_id, parsed->obj_id_len, parsed->obj_label);
		if (object)
			break; /* success */
	}
	if (matching_slots == 0)
		UTIL_CTX_log(ctx, LOG_NOTICE, "No matching slots found\n");
	return object;
}

void util_ctx_log_looking(UTIL_CTX *ctx, PARSED *parsed,
		const char *object_typestr, int initialized, int login)
{
	char *hexbuf = NULL;

	if (parsed->obj_id_len != 0) {
		hexbuf = dump_hex((unsigned char *)parsed->obj_id, parsed->obj_id_len);
	}
	if (parsed->slot_nr == -1) { /* RFC7512 URI */
		UTIL_CTX_log(ctx, LOG_NOTICE, "Searching slots %s login for an %s token containing %s %s%s%s%s\n",
			login ? "with" : "without",
			initialized ? "initialized" : "uninitialized",
			object_typestr,
			hexbuf ? " id=" : "",
			hexbuf ? hexbuf : "",
			parsed->obj_label ? " label=" : "",
			parsed->obj_label ? parsed->obj_label : "");
	} else { /* Legacy ENGINE_pkcs11 ID */
		UTIL_CTX_log(ctx, LOG_NOTICE, "Searching slot %d %s login for an %s token containing %s %s%s%s%s\n",
			parsed->slot_nr,
			login ? "with" : "without",
			initialized ? "initialized" : "uninitialized",
			object_typestr,
			hexbuf ? " id=" : "",
			hexbuf ? hexbuf : "",
			parsed->obj_label ? " label=" : "",
			parsed->obj_label ? parsed->obj_label : "");
	}
	OPENSSL_free(hexbuf);
}

static void *util_ctx_load_object(UTIL_CTX *ctx,
		const char *object_typestr,
		void *(*match_func)(UTIL_CTX *, PKCS11_TOKEN *,
				const char *, size_t, const char *),
		const char *object_uri, UI_METHOD *ui_method, void *ui_data)
{
	void *obj = NULL;
	PARSED parsed;

	memset(&parsed, 0, sizeof parsed);

	pthread_mutex_lock(&ctx->lock);

	if (util_ctx_init_libp11(ctx)) {
		pthread_mutex_unlock(&ctx->lock);
		return NULL;
	}

	if (util_ctx_parse_uri(ctx, &parsed, object_typestr, object_uri)) {
		/* First try without login unless FORCE_LOGIN is used */
		if (!ctx->force_login) {
			util_ctx_log_looking(ctx, &parsed, object_typestr, 1, 0);
			obj = util_ctx_load_object_without_login(ctx, &parsed, match_func, 1);
		}
		/* Then try (possibly again) with login */
		if (!obj && (!strcmp(object_typestr, "private key") || ctx->force_login)) {
			util_ctx_log_looking(ctx, &parsed, object_typestr, 1, 1);
			obj = util_ctx_load_object_with_login(ctx, &parsed, match_func,
				ui_method, ui_data);
		}
		/* Last try slots with an uninitialized token, user PIN is unset */
		if (!obj) {
			util_ctx_log_looking(ctx, &parsed, object_typestr, 0, 0);
			obj = util_ctx_load_object_without_login(ctx, &parsed, match_func, 0);
		}
	}

	pthread_mutex_unlock(&ctx->lock);

	OPENSSL_free(parsed.obj_label);
	OPENSSL_free(parsed.matched_slots);
	OPENSSL_free(parsed.obj_id);

	if (!obj) {
		UTIL_CTX_log(ctx, LOG_ERR, "The %s was not found at: %s\n",
			object_typestr, object_uri);
	}
	return obj;
}

/******************************************************************************/
/* Certificate handling                                                       */
/******************************************************************************/

static PKCS11_CERT *cert_cmp(PKCS11_CERT *a, PKCS11_CERT *b)
{
	const ASN1_TIME *a_time, *b_time;
	int pday, psec;

	/* the best certificate exists */
	if (!a || !a->x509) {
		return b;
	}
	if (!b || !b->x509) {
		return a;
	}

	a_time = X509_get0_notAfter(a->x509);
	b_time = X509_get0_notAfter(b->x509);

	/* the best certificate expires last */
	if (ASN1_TIME_diff(&pday, &psec, a_time, b_time)) {
		if (pday < 0 || psec < 0) {
			return a;
		} else if (pday > 0 || psec > 0) {
			return b;
		}
	}

	/* deterministic tie break */
	if (X509_cmp(a->x509, b->x509) < 1) {
		return b;
	} else {
		return a;
	}
}

static void *match_cert(UTIL_CTX *ctx, PKCS11_TOKEN *tok,
		const char *obj_id, size_t obj_id_len, const char *obj_label)
{
	PKCS11_CERT *certs, *selected_cert = NULL;
	PKCS11_CERT cert_template = {0};
	unsigned int m, cert_count;
	const char *which;
	char *hexbuf, *expiry;

	errno = 0;
	cert_template.label = obj_label ? OPENSSL_strdup(obj_label) : NULL;
	if (errno != 0) {
		UTIL_CTX_log(ctx, LOG_ERR, "%s", strerror(errno));
		goto cleanup;
	}
	if (obj_id_len) {
		cert_template.id = OPENSSL_malloc(obj_id_len);
		if (!cert_template.id) {
			UTIL_CTX_log(ctx, LOG_ERR, "Could not allocate memory for ID\n");
			goto cleanup;
		}
		memcpy(cert_template.id, obj_id, obj_id_len);
		cert_template.id_len = obj_id_len;
	}

	if (PKCS11_enumerate_certs_ext(tok, &cert_template, &certs, &cert_count)) {
		UTIL_CTX_log(ctx, LOG_ERR, "Unable to enumerate certificates\n");
		goto cleanup;
	}
	if (cert_count == 0) {
		UTIL_CTX_log(ctx, LOG_INFO, "No certificate found.\n");
		goto cleanup;
	}
	UTIL_CTX_log(ctx, LOG_NOTICE, "Found %u certificate%s:\n", cert_count, cert_count == 1 ? "" : "s");
	if (obj_id_len != 0 || obj_label) {
		which = "longest expiry matching";
		for (m = 0; m < cert_count; m++) {
			PKCS11_CERT *k = certs + m;

			hexbuf = dump_hex((unsigned char *)k->id, k->id_len);
			expiry = dump_expiry(k);
			UTIL_CTX_log(ctx, LOG_NOTICE, "  %2u    %s%s%s%s%s%s\n", m + 1,
				hexbuf ? " id=" : "",
				hexbuf ? hexbuf : "",
				k->label ? " label=" : "",
				k->label ? k->label : "",
				expiry ? " expiry=" : "",
				expiry ? expiry : "");
			OPENSSL_free(hexbuf);
			OPENSSL_free(expiry);

			if (obj_label && obj_id_len != 0) {
				if (k->label && strcmp(k->label, obj_label) == 0 &&
						k->id_len == obj_id_len &&
						memcmp(k->id, obj_id, obj_id_len) == 0) {
					selected_cert = cert_cmp(selected_cert, k);
				}
			} else if (obj_label && !obj_id_len) {
				if (k->label && strcmp(k->label, obj_label) == 0) {
					selected_cert = cert_cmp(selected_cert, k);
				}
			} else if (obj_id_len && !obj_label) {
				if (k->id_len == obj_id_len &&
						memcmp(k->id, obj_id, obj_id_len) == 0) {
					selected_cert = cert_cmp(selected_cert, k);
				}
			}
		}
	} else {
		which = "first (with id present)";
		for (m = 0; m < cert_count; m++) {
			PKCS11_CERT *k = certs + m;

			hexbuf = dump_hex((unsigned char *)k->id, k->id_len);
			expiry = dump_expiry(k);
			UTIL_CTX_log(ctx, LOG_NOTICE, "  %2u    %s%s%s%s%s%s\n", m + 1,
				hexbuf ? " id=" : "",
				hexbuf ? hexbuf : "",
				k->label ? " label=" : "",
				k->label ? k->label : "",
				expiry ? " expiry=" : "",
				expiry ? expiry : "");
			OPENSSL_free(hexbuf);
			OPENSSL_free(expiry);

			if (!selected_cert && k->id && *k->id) {
				selected_cert = k; /* Use the first certificate with nonempty id */
			}
		}
		if (!selected_cert) {
			which = "first";
			selected_cert = certs; /* Use the first certificate */
		}
	}

	if (selected_cert) {
		hexbuf = dump_hex((unsigned char *)selected_cert->id, selected_cert->id_len);
		expiry = dump_expiry(selected_cert);
		UTIL_CTX_log(ctx, LOG_NOTICE, "Returning %s certificate:%s%s%s%s%s%s\n", which,
			hexbuf ? " id=" : "",
			hexbuf ? hexbuf : "",
			selected_cert->label ? " label=" : "",
			selected_cert->label ? selected_cert->label : "",
			expiry ? " expiry=" : "",
			expiry ? expiry : "");
		OPENSSL_free(hexbuf);
		OPENSSL_free(expiry);
	} else {
		UTIL_CTX_log(ctx, LOG_ERR, "No matching certificate returned.\n");
	}

cleanup:
	OPENSSL_free(cert_template.label);
	OPENSSL_free(cert_template.id);
	return selected_cert;
}

X509 *UTIL_CTX_get_cert_from_uri(UTIL_CTX *ctx, const char *uri,
		UI_METHOD *ui_method, void *ui_data)
{
	PKCS11_CERT *cert;

	cert = util_ctx_load_object(ctx, "certificate",
		match_cert, uri, ui_method, ui_data);
	return cert ? X509_dup(cert->x509) : NULL;
}

/******************************************************************************/
/* Private and public key handling                                            */
/******************************************************************************/

static void *match_key(UTIL_CTX *ctx, const char *key_type,
		PKCS11_KEY *keys, unsigned int key_count,
		const char *obj_id, size_t obj_id_len, const char *obj_label)
{
	PKCS11_KEY *selected_key = NULL;
	unsigned int m;
	const char *which;
	char *hexbuf;

	if (key_count == 0) {
		UTIL_CTX_log(ctx, LOG_INFO, "No %s key found.\n", key_type);
		return NULL;
	}
	UTIL_CTX_log(ctx, LOG_NOTICE, "Found %u %s key%s:\n", key_count, key_type,
		key_count == 1 ? "" : "s");

	if (obj_id_len != 0 || obj_label) {
		which = "last matching";
		for (m = 0; m < key_count; m++) {
			PKCS11_KEY *k = keys + m;

			hexbuf = dump_hex((unsigned char *)k->id, k->id_len);
			UTIL_CTX_log(ctx, LOG_NOTICE, "  %2u %c%c%s%s%s%s\n", m + 1,
				k->isPrivate ? 'P' : ' ',
				k->needLogin ? 'L' : ' ',
				hexbuf ? " id=" : "",
				hexbuf ? hexbuf : "",
				k->label ? " label=" : "",
				k->label ? k->label : "");
			OPENSSL_free(hexbuf);

			if (obj_label && obj_id_len != 0) {
				if (k->label && strcmp(k->label, obj_label) == 0 &&
						k->id_len == obj_id_len &&
						memcmp(k->id, obj_id, obj_id_len) == 0) {
					selected_key = k;
				}
			} else if (obj_label && !obj_id_len) {
				if (k->label && strcmp(k->label, obj_label) == 0) {
					selected_key = k;
				}
			} else if (obj_id_len && !obj_label) {
				if (k->id_len == obj_id_len &&
						memcmp(k->id, obj_id, obj_id_len) == 0) {
					selected_key = k;
				}
			}
		}
	} else {
		which = "first";
		selected_key = keys; /* Use the first key */
	}

	if (selected_key) {
		hexbuf = dump_hex((unsigned char *)selected_key->id, selected_key->id_len);
		UTIL_CTX_log(ctx, LOG_NOTICE, "Returning %s %s key:%s%s%s%s\n", which, key_type,
			hexbuf ? " id=" : "",
			hexbuf ? hexbuf : "",
			selected_key->label ? " label=" : "",
			selected_key->label ? selected_key->label : "");
		OPENSSL_free(hexbuf);
	} else {
		UTIL_CTX_log(ctx, LOG_ERR, "No matching %s key returned.\n", key_type);
	}

	return selected_key;
}

static void *match_key_int(UTIL_CTX *ctx, PKCS11_TOKEN *tok,
		const unsigned int isPrivate, const char *obj_id, size_t obj_id_len, const char *obj_label)
{
	PKCS11_KEY *keys;
	PKCS11_KEY key_template = {0};
	unsigned int key_count;
	void *ret = NULL;

	key_template.isPrivate = isPrivate;
	errno = 0;
	key_template.label = obj_label ? OPENSSL_strdup(obj_label) : NULL;
	if (errno != 0) {
		UTIL_CTX_log(ctx, LOG_ERR, "%s", strerror(errno));
		goto cleanup;
	}
	if (obj_id_len) {
		key_template.id = OPENSSL_malloc(obj_id_len);
		if (!key_template.id) {
			UTIL_CTX_log(ctx, LOG_ERR, "Could not allocate memory for ID\n");
			goto cleanup;
		}
		memcpy(key_template.id, obj_id, obj_id_len);
		key_template.id_len = obj_id_len;
	}

	/* Make sure there is at least one private key on the token */
	if (key_template.isPrivate != 0 && PKCS11_enumerate_keys_ext(tok, (const PKCS11_KEY *) &key_template, &keys, &key_count)) {
		UTIL_CTX_log(ctx, LOG_ERR, "Unable to enumerate private keys\n");
		goto cleanup;
	}
	else if (key_template.isPrivate == 0 && PKCS11_enumerate_public_keys_ext(tok, (const PKCS11_KEY *) &key_template, &keys, &key_count)) {
		UTIL_CTX_log(ctx, LOG_ERR, "Unable to enumerate public keys\n");
		goto cleanup;
	}
	ret = match_key(ctx, key_template.isPrivate ? "private" : "public", keys, key_count, obj_id, obj_id_len, obj_label);
cleanup:
	OPENSSL_free(key_template.label);
	OPENSSL_free(key_template.id);
	return ret;
}

static void *match_public_key(UTIL_CTX *ctx, PKCS11_TOKEN *tok,
		const char *obj_id, size_t obj_id_len, const char *obj_label)
{
	return match_key_int(ctx, tok, 0, obj_id, obj_id_len, obj_label);
}

static void *match_private_key(UTIL_CTX *ctx, PKCS11_TOKEN *tok,
		const char *obj_id, size_t obj_id_len, const char *obj_label)
{
	return match_key_int(ctx, tok, 1, obj_id, obj_id_len, obj_label);
}

EVP_PKEY *UTIL_CTX_get_pubkey_from_uri(UTIL_CTX *ctx, const char *uri,
		UI_METHOD *ui_method, void *ui_data)
{
	PKCS11_KEY *key;

	key = util_ctx_load_object(ctx, "public key",
		match_public_key, uri, ui_method, ui_data);
	return key ? PKCS11_get_public_key(key) : NULL;
}

EVP_PKEY *UTIL_CTX_get_privkey_from_uri(UTIL_CTX *ctx, const char *uri,
		UI_METHOD *ui_method, void *ui_data)
{
	PKCS11_KEY *key;

	key = util_ctx_load_object(ctx, "private key",
		match_private_key, uri, ui_method, ui_data);
	return key ? PKCS11_get_private_key(key) : NULL;
}

/******************************************************************************/
/* Key pair generation                                                        */
/******************************************************************************/

static PKCS11_SLOT *util_ctx_find_token(UTIL_CTX *ctx, const char *tok_lbl)
{
	PKCS11_SLOT *slot = NULL;

	if (!ctx->pkcs11_ctx)
		return NULL;

	do {
		slot = PKCS11_find_next_token(ctx->pkcs11_ctx, ctx->slot_list,
			ctx->slot_count, slot);
		if (slot && slot->token && slot->token->initialized
				&& slot->token->label
				&& !strncmp(slot->token->label, tok_lbl, 32))
			return slot;
	} while (!slot);

	UTIL_CTX_log(ctx, LOG_ERR,
		"Initialized token with matching label not found...\n");
	return NULL;
}

int UTIL_CTX_keygen(UTIL_CTX *ctx, PKCS11_KGEN_ATTRS *kg_attrs)
{
	int rv;
	PKCS11_SLOT *slot = NULL;

	if (kg_attrs == NULL)
		return 0;

	/* Delayed libp11 initialization */
	if (util_ctx_init_libp11(ctx))
		return 0;

	slot = util_ctx_find_token(ctx, kg_attrs->token_label);
	if (!slot || !slot->token)
		return 0;

	/* Try logging in */
	ERR_clear_error();
	if (slot->token->loginRequired)
		if (!util_ctx_login(ctx, slot, slot->token,
				ctx->ui_method, ctx->ui_data))
			return 0;

	rv = PKCS11_keygen(slot->token, kg_attrs);
	if (rv < 0) {
		UTIL_CTX_log(ctx, LOG_ERR,
			"Failed to generate a key pair on the token. Error code: %d\n",
			rv);
		return 0;
	}

	return 1;
}

/* vim: set noexpandtab: */
