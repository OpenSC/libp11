/*
 * Copyright (c) 2002 Juha Yrjölä.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
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

#include "engine.h"
#include "libp11.h"
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>

#ifdef _WIN32
#define strncasecmp strnicmp
#endif

/** The maximum length of an internally-allocated PIN */
#define MAX_PIN_LENGTH   32

static PKCS11_CTX *ctx;

/**
 * The PIN used for login. Cache for the get_pin function.
 * The memory for this PIN is always owned internally,
 * and may be freed as necessary. Before freeing, the PIN
 * must be whitened, to prevent security holes.
 */
static char *pin = NULL;
static int pin_length = 0;

static int verbose = 0;

static char *module = NULL;

static char *init_args = NULL;

int set_module(const char *modulename)
{
	free (module);
	module = modulename ? strdup(modulename) : NULL;
	return 1;
}

/* Free PIN storage in secure way. */
static void zero_pin(void)
{
	if (pin != NULL) {
		OPENSSL_cleanse(pin, pin_length);
		free(pin);
		pin = NULL;
		pin_length = 0;
	}
}

/**
 * Set the PIN used for login. A copy of the PIN shall be made.
 *
 * If the PIN cannot be assigned, the value 0 shall be returned
 * and errno shall be set as follows:
 *
 *   EINVAL - a NULL PIN was supplied
 *   ENOMEM - insufficient memory to copy the PIN
 *
 * @param _pin the pin to use for login. Must not be NULL.
 *
 * @return 1 on success, 0 on failure.
 */
int set_pin(const char *_pin)
{
	/* Pre-condition check */
	if (_pin == NULL) {
		errno = EINVAL;
		return 0;
	}

	/* Copy the PIN. If the string cannot be copied, NULL
	 * shall be returned and errno shall be set. */
	zero_pin();
	pin = strdup(_pin);
	if (pin != NULL)
		pin_length = strlen(pin);

	return (pin != NULL);
}

int inc_verbose(void)
{
	verbose++;
	return 1;
}

/* Get the PIN via asking user interface. The supplied call-back data are
 * passed to the user interface implemented by an application. Only the
 * application knows how to interpret the call-back data.
 * A (strdup'ed) copy of the PIN code will be stored in the pin variable. */
static int get_pin(UI_METHOD * ui_method, void *callback_data)
{
	UI *ui;

	/* call ui to ask for a pin */
	ui = UI_new();
	if (ui == NULL) {
		fprintf(stderr, "UI_new failed\n");
		return 0;
	}
	if (ui_method != NULL)
		UI_set_method(ui, ui_method);
	if (callback_data != NULL)
		UI_add_user_data(ui, callback_data);

	zero_pin();
	pin = (char *)calloc(MAX_PIN_LENGTH, sizeof(char));
	if (pin == NULL)
		return 0;
	pin_length = MAX_PIN_LENGTH;
	if (!UI_add_input_string(ui, "PKCS#11 token PIN: ",
			UI_INPUT_FLAG_DEFAULT_PWD, pin, 1, MAX_PIN_LENGTH)) {
		fprintf(stderr, "UI_add_input_string failed\n");
		UI_free(ui);
		return 0;
	}
	if (UI_process(ui)) {
		fprintf(stderr, "UI_process failed\n");
		UI_free(ui);
		return 0;
	}
	UI_free(ui);
	return 1;
}

int set_init_args(const char *init_args_orig)
{
	free(init_args);
	init_args = init_args_orig ? strdup(init_args_orig) : NULL;
	return 1;
}

int pkcs11_finish(ENGINE * engine)
{
	/*
	 * TODO: Retrieve the libp11 context with:
	 *   ctx = ENGINE_get_ex_data(e, pkcs11_idx);
	 * , free it, and set to NULL with:
	 *   ENGINE_set_ex_data(e, pkcs11_idx, NULL);
	 * instead of using a global context
	 */
	(void)engine;

	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
		ctx = NULL;
	}
	zero_pin();
	return 1;
}

int pkcs11_init(ENGINE * engine)
{
	char *mod = module;

	/*
	 * TODO: Save the libp11 context with:
	 *   ENGINE_set_ex_data(e, pkcs11_idx, ctx);
	 * instead of using a global context
	 */
	(void)engine;

#ifdef DEFAULT_PKCS11_MODULE
	if (mod == NULL)
		mod = DEFAULT_PKCS11_MODULE;
#endif
	if (verbose) {
		fprintf(stderr, "Initializing engine\n");
	}
	ctx = PKCS11_CTX_new();
        PKCS11_CTX_init_args(ctx, init_args);
	if (PKCS11_CTX_load(ctx, mod) < 0) {
		fprintf(stderr, "Unable to load module %s\n", mod);
		return 0;
	}
	return 1;
}

static int hex_to_bin(const char *in, unsigned char *out, size_t * outlen)
{
	size_t left, count = 0;

	if (in == NULL || *in == '\0') {
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
				fprintf(stderr,
					"hex_to_bin(): invalid char '%c' in hex string\n",
					c);
				*outlen = 0;
				return 0;
			}
			byte |= c;
		}
		if (*in == ':')
			in++;
		if (left <= 0) {
			fprintf(stderr, "hex_to_bin(): hex string too long\n");
			*outlen = 0;
			return 0;
		}
		out[count++] = (unsigned char)byte;
		left--;
	}

	*outlen = count;
	return 1;
}

/* parse string containing slot and id information */
static int parse_slot_id_string(const char *slot_id, int *slot,
				unsigned char *id, size_t * id_len,
				char **label)
{
	int n, i;

	if (slot_id == NULL)
		return 0;

	/* support for several formats */
#define HEXDIGITS "01234567890ABCDEFabcdef"
#define DIGITS "0123456789"

	/* first: pure hex number (id, slot is undefined) */
	if (strspn(slot_id, HEXDIGITS) == strlen(slot_id)) {
		/* ah, easiest case: only hex. */
		if ((strlen(slot_id) + 1) / 2 > *id_len) {
			fprintf(stderr, "ID string too long!\n");
			return 0;
		}
		*slot = -1;
		return hex_to_bin(slot_id, id, id_len);
	}

	/* second: slot:id. slot is an digital int. */
	if (sscanf(slot_id, "%d", &n) == 1) {
		i = strspn(slot_id, DIGITS);

		if (slot_id[i] != ':') {
			fprintf(stderr, "Could not parse string!\n");
			return 0;
		}
		i++;
		if (slot_id[i] == 0) {
			*slot = n;
			*id_len = 0;
			return 1;
		}
		if (strspn(slot_id + i, HEXDIGITS) + i != strlen(slot_id)) {
			fprintf(stderr, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i + 1) / 2 > *id_len) {
			fprintf(stderr, "ID string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(slot_id + i, id, id_len);
	}

	/* third: id_<id>, slot is undefined */
	if (strncmp(slot_id, "id_", 3) == 0) {
		if (strspn(slot_id + 3, HEXDIGITS) + 3 != strlen(slot_id)) {
			fprintf(stderr, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - 3 + 1) / 2 > *id_len) {
			fprintf(stderr, "ID string too long!\n");
			return 0;
		}
		*slot = -1;
		return hex_to_bin(slot_id + 3, id, id_len);
	}

	/* label_<label>, slot is undefined */
	if (strncmp(slot_id, "label_", 6) == 0) {
		*slot = -1;
		*label = strdup(slot_id + 6);
		return *label != NULL;
	}

	/* last try: it has to be slot_<slot> and then "-id_<cert>" */

	if (strncmp(slot_id, "slot_", 5) != 0) {
		fprintf(stderr, "Format not recognized!\n");
		return 0;
	}

	/* slot is an digital int. */
	if (sscanf(slot_id + 5, "%d", &n) != 1) {
		fprintf(stderr, "Could not decode slot number!\n");
		return 0;
	}

	i = strspn(slot_id + 5, DIGITS);

	if (slot_id[i + 5] == 0) {
		*slot = n;
		*id_len = 0;
		return 1;
	}

	if (slot_id[i + 5] != '-') {
		fprintf(stderr, "Could not parse string!\n");
		return 0;
	}

	i = 5 + i + 1;

	/* now followed by "id_" */
	if (strncmp(slot_id + i, "id_", 3) == 0) {
		if (strspn(slot_id + i + 3, HEXDIGITS) + 3 + i != strlen(slot_id)) {
			fprintf(stderr, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i - 3 + 1) / 2 > *id_len) {
			fprintf(stderr, "ID string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(slot_id + i + 3, id, id_len);
	}

	/* ... or "label_" */
	if (strncmp(slot_id + i, "label_", 6) == 0) {
		*slot = n;
		return (*label = strdup(slot_id + i + 6)) != NULL;
	}

	fprintf(stderr, "Could not parse string!\n");
	return 0;
}

static int parse_uri_attr(const char *attr, int attrlen, unsigned char **field,
		size_t *field_len)
{
	size_t max, outlen = 0;
	unsigned char *out;
	int ret = 1;

	if (field_len) {
		out = *field;
		max = *field_len;
	} else {
		out = malloc(attrlen + 1);
		if (out == NULL)
			return 0;
		max = attrlen + 1;
	}

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
				ret = hex_to_bin(tmp, &out[outlen++], &l);
				attrlen -= 3;
				attr += 3;
			}

		} else {
			out[outlen++] = *(attr++);
			attrlen--;
		}
	}
	if (attrlen && outlen == max)
		ret = 0;

	if (ret) {
		if (field_len) {
			*field_len = outlen;
		} else {
			out[outlen] = 0;
			*field = out;
		}
	} else {
		if (field_len == NULL)
			free(out);
	}

	return ret;
}

static int parse_pkcs11_uri(const char *uri, PKCS11_TOKEN **p_tok,
		unsigned char *id, size_t *id_len, char *pin, size_t *pin_len,
		char **label)
{
	PKCS11_TOKEN *tok;
	char *newlabel = NULL;
	const char *end, *p;
	int rv = 1, pin_set = 0;

	tok = calloc(1, sizeof(*tok));
	if (tok == NULL) {
		fprintf(stderr, "Could not allocate memory for token info\n");
		return 0;
	}

	/* We are only ever invoked if the string starts with 'pkcs11:' */
	end = uri + 6;
	while (rv && end[0] && end[1]) {
		p = end + 1;
		end = strchr(p, ';');
		if (end == NULL)
			end = p + strlen(p);

		if (!strncmp(p, "model=", 6)) {
			p += 6;
			rv = parse_uri_attr(p, end - p, (void *)&tok->model, NULL);
		} else if (!strncmp(p, "manufacturer=", 13)) {
			p += 13;
			rv = parse_uri_attr(p, end - p, (void *)&tok->manufacturer, NULL);
		} else if (!strncmp(p, "token=", 6)) {
			p += 6;
			rv = parse_uri_attr(p, end - p, (void *)&tok->label, NULL);
		} else if (!strncmp(p, "serial=", 7)) {
			p += 7;
			rv = parse_uri_attr(p, end - p, (void *)&tok->serialnr, NULL);
		} else if (!strncmp(p, "object=", 7)) {
			p += 7;
			rv = parse_uri_attr(p, end - p, (void *)&newlabel, NULL);
		} else if (!strncmp(p, "id=", 3)) {
			p += 3;
			rv = parse_uri_attr(p, end - p, (void *)&id, id_len);
		} else if (!strncmp(p, "pin-value=", 10)) {
			p += 10;
			rv = parse_uri_attr(p, end - p, (void *)&pin, pin_len);
			pin_set = 1;
		} else if (!strncmp(p, "type=", 5) || !strncmp(p, "object-type=", 12)) {
			p = strchr(p, '=') + 1;

			if ((end - p == 4 && !strncmp(p, "cert", 4)) ||
					(end - p == 6 && !strncmp(p, "public", 6)) ||
					(end - p == 7 && !strncmp(p, "private", 7))) {
				/* Actually, just ignore it */
			} else {
				fprintf(stderr, "Unknown object type\n");
				rv = 0;
			}
		} else {
			rv = 0;
		}
	}

	if (!pin_set)
		*pin_len = 0;

	if (rv) {
		*label = newlabel;
		*p_tok = tok;
	} else {
		free(tok);
		tok = NULL;
		free(newlabel);
	}

	return rv;
}

#define MAX_VALUE_LEN	200

/* prototype for OpenSSL ENGINE_load_cert */
/* used by load_cert_ctrl via ENGINE_ctrl for now */

static X509 *pkcs11_load_cert(ENGINE * engine, const char *s_slot_cert_id)
{
	PKCS11_SLOT *slot_list, *slot;
	PKCS11_SLOT *found_slot = NULL;
	PKCS11_TOKEN *tok, *match_tok = NULL;
	PKCS11_CERT *certs, *selected_cert = NULL;
	X509 *x509;
	unsigned int slot_count, cert_count, n, m;
	unsigned char cert_id[MAX_VALUE_LEN / 2];
	size_t cert_id_len = sizeof(cert_id);
	char *cert_label = NULL;
	char tmp_pin[MAX_PIN_LENGTH];
	size_t tmp_pin_len = sizeof(tmp_pin);
	int slot_nr = -1;
	char flags[64];

	/*
	 * TODO: Retrieve the libp11 context with:
	 *   ctx = ENGINE_get_ex_data(e, pkcs11_idx);
	 * instead of using a global context
	 */
	(void)engine;

	if (s_slot_cert_id && *s_slot_cert_id) {
		if (!strncmp(s_slot_cert_id, "pkcs11:", 7)) {
			n = parse_pkcs11_uri(s_slot_cert_id, &match_tok,
				cert_id, &cert_id_len,
				tmp_pin, &tmp_pin_len, &cert_label);
			if (n && tmp_pin_len > 0 && tmp_pin[0] != 0) {
				zero_pin();
				pin = calloc(MAX_PIN_LENGTH, sizeof(char));
				if (pin != NULL) {
					memcpy(pin, tmp_pin, tmp_pin_len);
					pin_length = tmp_pin_len;
				}
			}

			if (!n) {
				fprintf(stderr,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n");
				return NULL;
			}
		} else {
			n = parse_slot_id_string(s_slot_cert_id, &slot_nr,
				cert_id, &cert_id_len, &cert_label);

			if (!n) {
				fprintf(stderr,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n"
					"The legacy ENGINE_pkcs11 ID format is also "
					"still accepted for now\n");
				return NULL;
			}
		}
		if (verbose) {
			fprintf(stderr, "Looking in slot %d for certificate: ",
				slot_nr);
			if (cert_label == NULL) {
				for (n = 0; n < cert_id_len; n++)
					fprintf(stderr, "%02x", cert_id[n]);
				fprintf(stderr, "\n");
			} else
				fprintf(stderr, "label: %s\n", cert_label);
		}
	}

	if (PKCS11_enumerate_slots(ctx, &slot_list, &slot_count) < 0) {
		fprintf(stderr, "Failed to enumerate slots\n");
		return NULL;
	}

	if (verbose) {
		fprintf(stderr, "Found %u slot%s\n", slot_count,
			(slot_count <= 1) ? "" : "s");
	}
	for (n = 0; n < slot_count; n++) {
		slot = slot_list + n;
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
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (slot_nr != -1 &&
			slot_nr == (int)PKCS11_get_slotid_from_slot(slot)) {
			found_slot = slot;
		}
		if (match_tok && slot->token &&
				(match_tok->label == NULL ||
					!strcmp(match_tok->label, slot->token->label)) &&
				(match_tok->manufacturer == NULL ||
					!strcmp(match_tok->manufacturer, slot->token->manufacturer)) &&
				(match_tok->serialnr == NULL ||
					!strcmp(match_tok->serialnr, slot->token->serialnr)) &&
				(match_tok->model == NULL ||
					!strcmp(match_tok->model, slot->token->model))) {
			found_slot = slot;
		}
		if (verbose) {
			fprintf(stderr, "[%lu] %-25.25s  %-16s",
				PKCS11_get_slotid_from_slot(slot),
				slot->description, flags);
			if (slot->token) {
				fprintf(stderr, "  (%s)",
					slot->token->label[0] ?
					slot->token->label : "no label");
			}
			fprintf(stderr, "\n");
		}
	}

	if (match_tok) {
		free(match_tok->model);
		free(match_tok->manufacturer);
		free(match_tok->serialnr);
		free(match_tok->label);
		free(match_tok);
	}
	if (found_slot) {
		slot = found_slot;
	} else if (match_tok) {
		fprintf(stderr, "Specified object not found\n");
		return NULL;
	} else if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx, slot_list, slot_count))) {
			fprintf(stderr, "No tokens found\n");
			return NULL;
		}
	} else {
		fprintf(stderr, "Invalid slot number: %d\n", slot_nr);
		PKCS11_release_all_slots(ctx, slot_list, slot_count);
		return NULL;
	}
	tok = slot->token;

	if (tok == NULL) {
		fprintf(stderr, "Empty token found\n");
		PKCS11_release_all_slots(ctx, slot_list, slot_count);
		return NULL;
	}

	if (verbose) {
		fprintf(stderr, "Found slot:  %s\n", slot->description);
		fprintf(stderr, "Found token: %s\n", slot->token->label);
	}

	/* In several tokens certificates are marked as private. We use the pin-value */
	if (tok->loginRequired && pin) {
		/* Now login in with the (possibly NULL) pin */
		if (PKCS11_login(slot, 0, pin)) {
			/* Login failed, so free the PIN if present */
			zero_pin();
			fprintf(stderr, "Login failed\n");
			return NULL;
		}
	}

	if (PKCS11_enumerate_certs(tok, &certs, &cert_count)) {
		fprintf(stderr, "Unable to enumerate certificates\n");
		PKCS11_release_all_slots(ctx, slot_list, slot_count);
		return NULL;
	}

	if (verbose) {
		fprintf(stderr, "Found %u cert%s:\n", cert_count,
			(cert_count <= 1) ? "" : "s");
	}
	if ((s_slot_cert_id && *s_slot_cert_id) &&
			(cert_id_len != 0 || cert_label != NULL)) {
		for (n = 0; n < cert_count; n++) {
			PKCS11_CERT *k = certs + n;

			if (cert_label == NULL) {
				if (cert_id_len != 0 && k->id_len == cert_id_len &&
						memcmp(k->id, cert_id, cert_id_len) == 0)
					selected_cert = k;
			} else {
				if (strcmp(k->label, cert_label) == 0)
					selected_cert = k;
			}
		}
	} else {
		selected_cert = certs; /* Use the first certificate */
	}

	if (selected_cert == NULL) {
		fprintf(stderr, "Certificate not found.\n");
		PKCS11_release_all_slots(ctx, slot_list, slot_count);
		return NULL;
	}

	x509 = X509_dup(selected_cert->x509);
	if (cert_label != NULL)
		free(cert_label);
	return x509;
}

int load_cert_ctrl(ENGINE * e, void *p)
{
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} *parms = p;

	if (parms->cert != NULL)
		return 0;

	parms->cert = pkcs11_load_cert(e, parms->s_slot_cert_id);
	if (parms->cert == NULL)
		return 0;

	return 1;
}

/*
 * Log-into the token if necesary.
 *
 * @slot is PKCS11 slot to log in
 * @tok is PKCS11 token to log in (??? could be derived as @slot->token)
 * @ui_method is OpenSSL user inteface which is used to ask for a password
 * @callback_data are application data to the user interface
 * @return 1 on success, 0 on error.
 */
static int pkcs11_login(PKCS11_SLOT *slot, PKCS11_TOKEN *tok,
		UI_METHOD *ui_method, void *callback_data)
{
	if (tok->loginRequired) {
		/* If the token has a secure login (i.e., an external keypad),
		 * then use a NULL pin. Otherwise, check if a PIN exists. If
		 * not, allocate and obtain a new PIN. */
		if (tok->secureLogin) {
			/* Free the PIN if it has already been
			 * assigned (i.e, cached by get_pin) */
			zero_pin();
		} else if (pin == NULL) {
			pin = (char *)calloc(MAX_PIN_LENGTH, sizeof(char));
			pin_length = MAX_PIN_LENGTH;
			if (pin == NULL) {
				fprintf(stderr, "Could not allocate memory for PIN");
				return 0;
			}
			if (!get_pin(ui_method, callback_data)) {
				zero_pin();
				fprintf(stderr, "No pin code was entered");
				return 0;
			}
		}

		/* Now login in with the (possibly NULL) pin */
		if (PKCS11_login(slot, 0, pin)) {
			/* Login failed, so free the PIN if present */
			zero_pin();
			fprintf(stderr, "Login failed\n");
			return 0;
		}
		/* Login successful, PIN retained in case further logins are
		 * required. This will occur on subsequent calls to the
		 * pkcs11_load_key function. Subsequent login calls should be
		 * relatively fast (the token should maintain its own login
		 * state), although there may still be a slight performance
		 * penalty. We could maintain state noting that successful
		 * login has been performed, but this state may not be updated
		 * if the token is removed and reinserted between calls. It
		 * seems safer to retain the PIN and peform a login on each
		 * call to pkcs11_load_key, even if this may not be strictly
		 * necessary. */
		/* TODO when does PIN get freed after successful login? */
		/* TODO confirm that multiple login attempts do not introduce
		 * significant performance penalties */
	}
	return 1;
}

static EVP_PKEY *pkcs11_load_key(ENGINE * engine, const char *s_slot_key_id,
		UI_METHOD * ui_method, void *callback_data, int isPrivate)
{
	PKCS11_SLOT *slot_list, *slot;
	PKCS11_SLOT *found_slot = NULL;
	PKCS11_TOKEN *tok, *match_tok = NULL;
	PKCS11_KEY *keys, *selected_key = NULL;
	PKCS11_CERT *certs;
	EVP_PKEY *pk;
	unsigned int slot_count, cert_count, key_count, n, m;
	unsigned char key_id[MAX_VALUE_LEN / 2];
	size_t key_id_len = sizeof(key_id);
	char *key_label = NULL;
	int slot_nr = -1;
	char tmp_pin[MAX_PIN_LENGTH];
	size_t tmp_pin_len = sizeof(tmp_pin);
	char flags[64];

	/*
	 * TODO: Retrieve the libp11 context with:
	 *   ctx = ENGINE_get_ex_data(e, pkcs11_idx);
	 * instead of using a global context
	 */
	(void)engine;

	if (verbose)
		fprintf(stderr, "Loading %s key \"%s\"\n",
			(char *)(isPrivate ? "private" : "public"),
			s_slot_key_id);
	if (s_slot_key_id && *s_slot_key_id) {
		if (!strncmp(s_slot_key_id, "pkcs11:", 7)) {
			n = parse_pkcs11_uri(s_slot_key_id, &match_tok,
				key_id, &key_id_len,
				tmp_pin, &tmp_pin_len, &key_label);

			if (n && tmp_pin_len > 0 && tmp_pin[0] != 0) {
				zero_pin();
				pin = calloc(MAX_PIN_LENGTH, sizeof(char));
				if (pin != NULL) {
					memcpy(pin, tmp_pin, tmp_pin_len);
					pin_length = tmp_pin_len;
				}
			}

			if (!n) {
				fprintf(stderr,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n");
				return NULL;
			}
		} else {
			n = parse_slot_id_string(s_slot_key_id, &slot_nr,
				key_id, &key_id_len, &key_label);

			if (!n) {
				fprintf(stderr,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n"
					"The legacy ENGINE_pkcs11 ID format is also "
					"still accepted for now\n");
				return NULL;
			}
		}
		if (verbose) {
			fprintf(stderr, "Looking in slot %d for key: ",
				slot_nr);
			if (key_label == NULL) {
				for (n = 0; n < key_id_len; n++)
					fprintf(stderr, "%02x", key_id[n]);
				fprintf(stderr, "\n");
			} else
				fprintf(stderr, "label: %s\n", key_label);
		}
	}

	if (PKCS11_enumerate_slots(ctx, &slot_list, &slot_count) < 0) {
		fprintf(stderr, "Failed to enumerate slots\n");
		return NULL;
	}

	if (verbose) {
		fprintf(stderr, "Found %u slot%s\n", slot_count,
			(slot_count <= 1) ? "" : "s");
	}
	for (n = 0; n < slot_count; n++) {
		slot = slot_list + n;
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
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (slot_nr != -1 &&
			slot_nr == (int)PKCS11_get_slotid_from_slot(slot)) {
			found_slot = slot;
		}
		if (match_tok && slot->token &&
				(match_tok->label == NULL ||
					!strcmp(match_tok->label, slot->token->label)) &&
				(match_tok->manufacturer == NULL ||
					!strcmp(match_tok->manufacturer, slot->token->manufacturer)) &&
				(match_tok->serialnr == NULL ||
					!strcmp(match_tok->serialnr, slot->token->serialnr)) &&
				(match_tok->model == NULL ||
					!strcmp(match_tok->model, slot->token->model))) {
			found_slot = slot;
		}
		if (verbose) {
			fprintf(stderr, "[%lu] %-25.25s  %-16s",
				PKCS11_get_slotid_from_slot(slot),
				slot->description, flags);
			if (slot->token) {
				fprintf(stderr, "  (%s)",
					slot->token->label[0] ?
					slot->token->label : "no label");
			}
			fprintf(stderr, "\n");
		}
	}

	if (match_tok) {
		free(match_tok->model);
		free(match_tok->manufacturer);
		free(match_tok->serialnr);
		free(match_tok->label);
		free(match_tok);
	}
	if (found_slot) {
		slot = found_slot;
	} else if (match_tok) {
		fprintf(stderr, "Specified object not found\n");
		return NULL;
	} else if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx, slot_list, slot_count))) {
			fprintf(stderr, "No tokens found\n");
			return NULL;
		}
	} else {
		fprintf(stderr, "Invalid slot number: %d\n", slot_nr);
		PKCS11_release_all_slots(ctx, slot_list, slot_count);
		return NULL;
	}
	tok = slot->token;

	if (tok == NULL) {
		fprintf(stderr, "Found empty token\n");
		PKCS11_release_all_slots(ctx, slot_list, slot_count);
		return NULL;
	}
	/* The following check is non-critical to ensure interoperability
	 * with some other (which ones?) PKCS#11 libraries */
	if (!tok->initialized)
		fprintf(stderr, "Found uninitialized token\n");
	if (isPrivate && !tok->userPinSet && !tok->readOnly) {
		fprintf(stderr, "Found slot without user PIN\n");
		PKCS11_release_all_slots(ctx, slot_list, slot_count);
		return NULL;
	}

	if (verbose) {
		fprintf(stderr, "Found slot:  %s\n", slot->description);
		fprintf(stderr, "Found token: %s\n", slot->token->label);
	}

	if (PKCS11_enumerate_certs(tok, &certs, &cert_count)) {
		fprintf(stderr, "Unable to enumerate certificates\n");
		return NULL;
	}

	if (verbose) {
		fprintf(stderr, "Found %u certificate%s:\n", cert_count,
			(cert_count <= 1) ? "" : "s");
		for (n = 0; n < cert_count; n++) {
			PKCS11_CERT *c = certs + n;
			char *dn = NULL;

			fprintf(stderr, "  %2u    %s", n + 1, c->label);
			if (c->x509)
				dn = X509_NAME_oneline(X509_get_subject_name(c->x509), NULL, 0);
			if (dn) {
				fprintf(stderr, " (%s)", dn);
				OPENSSL_free(dn);
			}
			fprintf(stderr, "\n");
		}
	}

	if (isPrivate) {
		/* Perform login to the token if required */
		if (!pkcs11_login(slot, tok, ui_method, callback_data)) {
			fprintf(stderr, "login to token failed, returning NULL...\n");
			return NULL;
		}

		/* Make sure there is at least one private key on the token */
		if (PKCS11_enumerate_keys(tok, &keys, &key_count)) {
			fprintf(stderr, "Unable to enumerate private keys\n");
			return NULL;
		}
	} else {
		/* Make sure there is at least one public key on the token */
		if (PKCS11_enumerate_public_keys(tok, &keys, &key_count)) {
			fprintf(stderr, "Unable to enumerate public keys\n");
			return NULL;
		}
	}
	if (key_count == 0) {
		fprintf(stderr, "No %s keys found.\n",
			(char *)(isPrivate ? "private" : "public"));
		return NULL;
	}
	if (verbose)
		fprintf(stderr, "Found %u %s key%s:\n", key_count,
			(char *)(isPrivate ? "private" : "public"),
			(key_count == 1) ? "" : "s");

	if (s_slot_key_id && *s_slot_key_id &&
			(key_id_len != 0 || key_label != NULL)) {
		for (n = 0; n < key_count; n++) {
			PKCS11_KEY *k = keys + n;

			if (verbose) {
				fprintf(stderr, "  %2u %c%c %s\n", n + 1,
					k->isPrivate ? 'P' : ' ',
					k->needLogin ? 'L' : ' ', k->label);
			}
			if (key_label == NULL) {
				if (key_id_len != 0 && k->id_len == key_id_len
						&& memcmp(k->id, key_id, key_id_len) == 0) {
					selected_key = k;
				}
			} else {
				if (strcmp(k->label, key_label) == 0) {
					selected_key = k;
				}
			}
		}
	} else {
		selected_key = keys; /* Use the first key */
	}

	if (selected_key == NULL) {
		fprintf(stderr, "Key not found.\n");
		return NULL;
	}

	pk = isPrivate ?
		PKCS11_get_private_key(selected_key) :
		PKCS11_get_public_key(selected_key);
	if (key_label != NULL)
		free(key_label);
	return pk;
}

EVP_PKEY *pkcs11_load_public_key(ENGINE * e, const char *s_key_id,
		UI_METHOD * ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(e, s_key_id, ui_method, callback_data, 0);
	if (pk == NULL) {
		fprintf(stderr, "PKCS11_load_public_key returned NULL\n");
		return NULL;
	}
	return pk;
}

EVP_PKEY *pkcs11_load_private_key(ENGINE * e, const char *s_key_id,
		UI_METHOD * ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(e, s_key_id, ui_method, callback_data, 1);
	if (pk == NULL) {
		fprintf(stderr, "PKCS11_get_private_key returned NULL\n");
		return NULL;
	}
	return pk;
}

/* vim: set noexpandtab: */
