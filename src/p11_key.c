/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2016-2024 Michał Trojnara <Michal.Trojnara@stunnel.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include "libp11-int.h"
#include <string.h>
#include <openssl/ui.h>
#include <openssl/bn.h>

#if defined(_WIN32) && !defined(strncasecmp)
#define strncasecmp strnicmp
#endif

/* The maximum length of PIN */
#define MAX_PIN_LENGTH   256

static int pkcs11_find_keys(PKCS11_SLOT_private *, CK_SESSION_HANDLE, unsigned int, PKCS11_TEMPLATE *);
static int pkcs11_next_key(PKCS11_CTX_private *ctx, PKCS11_SLOT_private *,
	CK_SESSION_HANDLE session, CK_OBJECT_CLASS type);
static int pkcs11_init_key(PKCS11_SLOT_private *, CK_SESSION_HANDLE session,
	CK_OBJECT_HANDLE o, CK_OBJECT_CLASS type, PKCS11_KEY **);
static int pkcs11_store_key(PKCS11_SLOT_private *, EVP_PKEY *, CK_OBJECT_CLASS,
	char *, unsigned char *, size_t, PKCS11_KEY **);

/* Helper to acquire object handle from given template */
static CK_OBJECT_HANDLE pkcs11_handle_from_template(PKCS11_SLOT_private *slot,
	CK_SESSION_HANDLE session, PKCS11_TEMPLATE *tmpl)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_OBJECT_HANDLE object;
	CK_ULONG count;
	CK_RV rv;

	rv = CRYPTOKI_call(ctx,
		C_FindObjectsInit(session, tmpl->attrs, tmpl->nattr));
	if (rv == CKR_OK) {
		rv = CRYPTOKI_call(ctx,
			C_FindObjects(session, &object, 1, &count));
		CRYPTOKI_call(ctx, C_FindObjectsFinal(session));
	}
	pkcs11_zap_attrs(tmpl);

	if (rv == CKR_OK && count == 1)
		return object;

	return CK_INVALID_HANDLE;
}

/* Get object from a handle */
PKCS11_OBJECT_private *pkcs11_object_from_handle(PKCS11_SLOT_private *slot,
		CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	PKCS11_OBJECT_private *obj;
	PKCS11_OBJECT_ops *ops = NULL;
	CK_OBJECT_CLASS object_class = -1;
	CK_KEY_TYPE key_type = -1;
	CK_CERTIFICATE_TYPE cert_type = -1;
	size_t size;
	unsigned char *data;

	if (pkcs11_getattr_val(ctx, session, object, CKA_CLASS,
			(CK_BYTE *) &object_class, sizeof(object_class)))
		return NULL;

	switch (object_class) {
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
		if (pkcs11_getattr_val(ctx, session, object, CKA_KEY_TYPE,
				(CK_BYTE *)&key_type, sizeof(key_type)))
			return NULL;
		switch (key_type) {
		case CKK_RSA:
			ops = &pkcs11_rsa_ops;
			break;
#ifndef OPENSSL_NO_EC
		case CKK_EC:
			ops = &pkcs11_ec_ops;
			break;
#endif
		default:
			/* Ignore any keys we don't understand */
			return 0;
		}
		break;
	case CKO_CERTIFICATE:
		if (pkcs11_getattr_val(ctx, session, object, CKA_CERTIFICATE_TYPE,
				(CK_BYTE *)&cert_type, sizeof(cert_type)))
			return NULL;
		/* Ignore unknown certificate types */
		if (cert_type != CKC_X_509)
			return 0;
		break;
	default:
		return NULL;
	}

	obj = OPENSSL_malloc(sizeof(*obj));
	if (!obj)
		return NULL;

	memset(obj, 0, sizeof(*obj));
	obj->refcnt = 1;
	pthread_mutex_init(&obj->lock, 0);
	obj->object_class = object_class;
	obj->object = object;
	obj->slot = pkcs11_slot_ref(slot);
	obj->id_len = sizeof(obj->id);
	if (pkcs11_getattr_var(ctx, session, object, CKA_ID, obj->id, &obj->id_len))
		obj->id_len = 0;
	pkcs11_getattr_alloc(ctx, session, object, CKA_LABEL, (CK_BYTE **)&obj->label, NULL);
	obj->ops = ops;
	obj->forkid = get_forkid();
	switch (object_class) {
	case CKO_PRIVATE_KEY:
		if (pkcs11_getattr_val(ctx, session, object, CKA_ALWAYS_AUTHENTICATE,
				&obj->always_authenticate, sizeof(CK_BBOOL))) {
#ifdef DEBUG
			fprintf(stderr, "Missing CKA_ALWAYS_AUTHENTICATE attribute\n");
#endif
		}
		break;
	case CKO_CERTIFICATE:
		if (!pkcs11_getattr_alloc(ctx, session, object, CKA_VALUE,
				&data, &size)) {
			const unsigned char *p = data;
			obj->x509 = d2i_X509(NULL, &p, (long)size);
			OPENSSL_free(data);
		}
		break;
	}
	return obj;
}

/* Get object based on template */
PKCS11_OBJECT_private *pkcs11_object_from_template(PKCS11_SLOT_private *slot,
	CK_SESSION_HANDLE session, PKCS11_TEMPLATE *tmpl)
{
	PKCS11_OBJECT_private *obj = NULL;
	CK_OBJECT_HANDLE object_handle;
	int release = 0;

	if (session == CK_INVALID_HANDLE) {
		if (pkcs11_get_session(slot, 0, &session))
			return NULL;
		release = 1;
	}

	object_handle = pkcs11_handle_from_template(slot, session, tmpl);
	if (object_handle)
		obj = pkcs11_object_from_handle(slot, session, object_handle);

	if (release)
		pkcs11_put_session(slot, session);

	return obj;
}

PKCS11_OBJECT_private *pkcs11_object_from_object(PKCS11_OBJECT_private *obj,
	CK_SESSION_HANDLE session, CK_OBJECT_CLASS object_class)
{
	PKCS11_TEMPLATE tmpl = {0};
	pkcs11_addattr_var(&tmpl, CKA_CLASS, object_class);
	pkcs11_addattr(&tmpl, CKA_ID, obj->id, obj->id_len);
	return pkcs11_object_from_template(obj->slot, session, &tmpl);
}

void pkcs11_object_free(PKCS11_OBJECT_private *obj)
{
	if (!obj)
		return;

	if (pkcs11_atomic_add(&obj->refcnt, -1, &obj->lock) != 0)
		return;
	pkcs11_slot_unref(obj->slot);
	X509_free(obj->x509);
	OPENSSL_free(obj->label);
	pthread_mutex_destroy(&obj->lock);
	OPENSSL_free(obj);
}

/* Set UI method to allow retrieving CKU_CONTEXT_SPECIFIC PINs interactively */
int pkcs11_set_ui_method(PKCS11_CTX_private *ctx,
		UI_METHOD *ui_method, void *ui_user_data)
{
	if (!ctx)
		return -1;
	ctx->ui_method = ui_method;
	ctx->ui_user_data = ui_user_data;
	return 0;
}

/*
 * Find private key matching a certificate
 */
PKCS11_KEY *pkcs11_find_key(PKCS11_OBJECT_private *cert)
{
	PKCS11_KEY *keys, key_template = {0};
	unsigned int n, count;
	key_template.isPrivate = 1;

	key_template.id = cert->id;
	key_template.id_len = cert->id_len;

	if (pkcs11_enumerate_keys(cert->slot, CKO_PRIVATE_KEY, &key_template, &keys, &count))
		return NULL;
	for (n = 0; n < count; n++) {
		PKCS11_OBJECT_private *kpriv = PRIVKEY(&keys[n]);
		if (kpriv && cert->id_len == kpriv->id_len
				&& !memcmp(cert->id, kpriv->id, cert->id_len))
			return &keys[n];
	}
	return NULL;
}

/*
 * Reopens the object by refresing the object handle
 */
int pkcs11_reload_object(PKCS11_OBJECT_private *obj)
{
	PKCS11_SLOT_private *slot = obj->slot;
	CK_SESSION_HANDLE session;
	PKCS11_TEMPLATE tmpl = {0};

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	pkcs11_addattr_var(&tmpl, CKA_CLASS, obj->object_class);
	if (obj->id_len)
		pkcs11_addattr(&tmpl, CKA_ID, obj->id, obj->id_len);
	if (obj->label)
		pkcs11_addattr_s(&tmpl, CKA_LABEL, obj->label);

	obj->object = pkcs11_handle_from_template(slot, session, &tmpl);
	pkcs11_put_session(slot, session);

	if (obj->object == CK_INVALID_HANDLE)
		CRYPTOKI_checkerr(CKR_F_PKCS11_RELOAD_KEY, CKR_OBJECT_HANDLE_INVALID);

	return 0;
}

/**
 * Generate a key pair directly on token
 */
int pkcs11_generate_key(PKCS11_SLOT_private *slot, int algorithm, unsigned int bits,
		char *label, unsigned char *id, size_t id_len) {

	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	PKCS11_TEMPLATE pubtmpl = {0}, privtmpl = {0};
	CK_MECHANISM mechanism = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
	};
	CK_ULONG num_bits = bits;
	CK_BYTE public_exponent[] = { 1, 0, 1 };
	CK_OBJECT_HANDLE pub_key_obj, priv_key_obj;
	int rv;

	(void)algorithm; /* squash the unused parameter warning */

	if (pkcs11_get_session(slot, 1, &session))
		return -1;

	/* pubkey attributes */
	pkcs11_addattr(&pubtmpl, CKA_ID, id, id_len);
	if (label)
		pkcs11_addattr_s(&pubtmpl, CKA_LABEL, label);
	pkcs11_addattr_bool(&pubtmpl, CKA_TOKEN, TRUE);
	pkcs11_addattr_bool(&pubtmpl, CKA_ENCRYPT, TRUE);
	pkcs11_addattr_bool(&pubtmpl, CKA_VERIFY, TRUE);
	pkcs11_addattr_bool(&pubtmpl, CKA_WRAP, TRUE);
	pkcs11_addattr_var(&pubtmpl, CKA_MODULUS_BITS, num_bits);
	pkcs11_addattr(&pubtmpl, CKA_PUBLIC_EXPONENT, public_exponent, 3);

	/* privkey attributes */
	pkcs11_addattr(&privtmpl, CKA_ID, id, id_len);
	if (label)
		pkcs11_addattr_s(&privtmpl, CKA_LABEL, label);
	pkcs11_addattr_bool(&privtmpl, CKA_TOKEN, TRUE);
	pkcs11_addattr_bool(&privtmpl, CKA_PRIVATE, TRUE);
	pkcs11_addattr_bool(&privtmpl, CKA_SENSITIVE, TRUE);
	pkcs11_addattr_bool(&privtmpl, CKA_DECRYPT, TRUE);
	pkcs11_addattr_bool(&privtmpl, CKA_SIGN, TRUE);
	pkcs11_addattr_bool(&privtmpl, CKA_UNWRAP, TRUE);

	/* call the pkcs11 module to create the key pair */
	rv = CRYPTOKI_call(ctx, C_GenerateKeyPair(
		session, &mechanism,
		pubtmpl.attrs, pubtmpl.nattr,
		privtmpl.attrs, privtmpl.nattr,
		&pub_key_obj, &priv_key_obj));
	pkcs11_put_session(slot, session);

	/* zap all memory allocated when building the template */
	pkcs11_zap_attrs(&privtmpl);
	pkcs11_zap_attrs(&pubtmpl);

	CRYPTOKI_checkerr(CKR_F_PKCS11_GENERATE_KEY, rv);

	return 0;
}

/*
 * Store a private key on the token
 */
int pkcs11_store_private_key(PKCS11_SLOT_private *slot, EVP_PKEY *pk,
		char *label, unsigned char *id, size_t id_len)
{
	if (pkcs11_store_key(slot, pk, CKO_PRIVATE_KEY, label, id, id_len, NULL))
		return -1;
	return 0;
}

int pkcs11_store_public_key(PKCS11_SLOT_private *slot, EVP_PKEY *pk,
		char *label, unsigned char *id, size_t id_len)
{
	if (pkcs11_store_key(slot, pk, CKO_PUBLIC_KEY, label, id, id_len, NULL))
		return -1;
	return 0;
}

/*
 * Store private key
 */
static int pkcs11_store_key(PKCS11_SLOT_private *slot, EVP_PKEY *pk,
		CK_OBJECT_CLASS type, char *label, unsigned char *id, size_t id_len,
		PKCS11_KEY **ret_key)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	PKCS11_TEMPLATE tmpl = {0};
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_KEY_TYPE key_type_rsa = CKK_RSA;
	int rv, r = -1;
	const BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_p, *rsa_q, *rsa_dmp1, *rsa_dmq1, *rsa_iqmp;

	/* Now build the key attrs */
	pkcs11_addattr_var(&tmpl, CKA_CLASS, type);
	if (label)
		pkcs11_addattr_s(&tmpl, CKA_LABEL, label);
	if (id && id_len)
		pkcs11_addattr(&tmpl, CKA_ID, id, id_len);
	pkcs11_addattr_bool(&tmpl, CKA_TOKEN, TRUE);
	if (type == CKO_PRIVATE_KEY) {
		pkcs11_addattr_bool(&tmpl, CKA_PRIVATE, TRUE);
		pkcs11_addattr_bool(&tmpl, CKA_SENSITIVE, TRUE);
		pkcs11_addattr_bool(&tmpl, CKA_DECRYPT, TRUE);
		pkcs11_addattr_bool(&tmpl, CKA_SIGN, TRUE);
		pkcs11_addattr_bool(&tmpl, CKA_UNWRAP, TRUE);
	} else { /* CKO_PUBLIC_KEY */
		pkcs11_addattr_bool(&tmpl, CKA_ENCRYPT, TRUE);
		pkcs11_addattr_bool(&tmpl, CKA_VERIFY, TRUE);
		pkcs11_addattr_bool(&tmpl, CKA_WRAP, TRUE);
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100003L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL )
	if (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA) {
		RSA *rsa = EVP_PKEY_get1_RSA(pk);
		RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
		RSA_get0_factors(rsa, &rsa_p, &rsa_q);
		RSA_get0_crt_params(rsa, &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);
		RSA_free(rsa);
#else
	if (pk->type == EVP_PKEY_RSA) {
		RSA *rsa = pk->pkey.rsa;
		rsa_n = rsa->n;
		rsa_e = rsa->e;
		rsa_d = rsa->d;
		rsa_p = rsa->p;
		rsa_q = rsa->q;
		rsa_dmp1 = rsa->dmp1;
		rsa_dmq1 = rsa->dmq1;
		rsa_iqmp = rsa->iqmp;
#endif
		pkcs11_addattr_var(&tmpl, CKA_KEY_TYPE, key_type_rsa);
		pkcs11_addattr_bn(&tmpl, CKA_MODULUS, rsa_n);
		pkcs11_addattr_bn(&tmpl, CKA_PUBLIC_EXPONENT, rsa_e);
		if (type == CKO_PRIVATE_KEY) {
			pkcs11_addattr_bn(&tmpl, CKA_PRIVATE_EXPONENT, rsa_d);
			pkcs11_addattr_bn(&tmpl, CKA_PRIME_1, rsa_p);
			pkcs11_addattr_bn(&tmpl, CKA_PRIME_2, rsa_q);
			if (rsa_dmp1)
				pkcs11_addattr_bn(&tmpl, CKA_EXPONENT_1, rsa_dmp1);
			if (rsa_dmq1)
				pkcs11_addattr_bn(&tmpl, CKA_EXPONENT_2, rsa_dmq1);
			if (rsa_iqmp)
				pkcs11_addattr_bn(&tmpl, CKA_COEFFICIENT, rsa_iqmp);
		}
	} else {
		pkcs11_zap_attrs(&tmpl);
		P11err(P11_F_PKCS11_STORE_KEY, P11_R_NOT_SUPPORTED);
		return -1;
	}

	if (pkcs11_get_session(slot, 1, &session)) {
		pkcs11_zap_attrs(&tmpl);
		return -1;
	}

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(session, tmpl.attrs, tmpl.nattr, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(&tmpl);

	if (rv == CKR_OK) {
		/* Gobble the key object */
		r = pkcs11_init_key(slot, session, object, type, ret_key);
	}
	pkcs11_put_session(slot, session);

	CRYPTOKI_checkerr(CKR_F_PKCS11_STORE_KEY, rv);
	return r;

}

/*
 * Get the key type
 */
int pkcs11_get_key_type(PKCS11_OBJECT_private *key)
{
	if (key->ops)
		return key->ops->pkey_type;
	return EVP_PKEY_NONE;
}

/*
 * Create an EVP_PKEY OpenSSL object for a given key
 * Returns the key type specified in object_class.
 */
EVP_PKEY *pkcs11_get_key(PKCS11_OBJECT_private *key0, CK_OBJECT_CLASS object_class)
{
	PKCS11_OBJECT_private *key = key0;
	EVP_PKEY *ret = NULL;
	RSA *rsa;
#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
	EC_KEY *ec_key;
#endif

	if (key->object_class != object_class)
		key = pkcs11_object_from_object(key, CK_INVALID_HANDLE, object_class);
	if (!key || !key->ops)
		goto err;
	if (!key->evp_key) {
		key->evp_key = key->ops->get_evp_key(key);
		if (!key->evp_key)
			goto err;
	}
	/* We need a full copy of the EVP_PKEY as it will be modified later.
	 * Using a reference would mean changes to the duplicated EVP_PKEY could
	 * affect the original one.
	 */
	switch (EVP_PKEY_base_id(key->evp_key)) {
	case EVP_PKEY_RSA:
		/* Do not try to duplicate foreign RSA keys */
		rsa = EVP_PKEY_get1_RSA(key->evp_key);
		if (!rsa)
			goto err;
		ret = EVP_PKEY_new();
		if (!ret) {
			RSA_free(rsa);
			goto err;
		}
		if (!EVP_PKEY_assign_RSA(ret, rsa)) {
			RSA_free(rsa);
			EVP_PKEY_free(ret);
			goto err;
		}
		if (key->object_class == CKO_PRIVATE_KEY)
			pkcs11_object_ref(key);
		else /* Public key -> detach PKCS11_OBJECT */
			pkcs11_set_ex_data_rsa(rsa, NULL);
		break;
	case EVP_PKEY_EC:
#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
		ec_key = EVP_PKEY_get1_EC_KEY(key->evp_key);
		if (!ec_key)
			goto err;
		ret = EVP_PKEY_new();
		if (!ret) {
			EC_KEY_free(ec_key);
			goto err;
		}
		if (!EVP_PKEY_assign_EC_KEY(ret, ec_key)) {
			EC_KEY_free(ec_key);
			EVP_PKEY_free(ret);
			goto err;
		}
		if (key->object_class == CKO_PRIVATE_KEY)
			pkcs11_object_ref(key);
		else /* Public key -> detach PKCS11_OBJECT */
			pkcs11_set_ex_data_ec(ec_key, NULL);
#else
		/* pkcs11_ec_copy() method is only set for private keys,
		 * so public keys do not have a PKCS11_OBJECT reference */
		ret = EVP_PKEY_dup(key->evp_key);
#endif
		break;
	default:
		printf("Unsupported key type\n");
	}
err:
	if (key != key0)
		pkcs11_object_free(key);
	return ret;
}

/*
 * Authenticate a private the key operation if needed
 * This function *only* handles CKU_CONTEXT_SPECIFIC logins.
 */
int pkcs11_authenticate(PKCS11_OBJECT_private *key, CK_SESSION_HANDLE session)
{
	PKCS11_SLOT_private *slot = key->slot;
	PKCS11_CTX_private *ctx = slot->ctx;
	char pin[MAX_PIN_LENGTH+1];
	char *prompt;
	UI *ui;
	int rv;

	/* Handle CKF_PROTECTED_AUTHENTICATION_PATH */
	if (slot->secure_login) {
		rv = CRYPTOKI_call(ctx,
			C_Login(session, CKU_CONTEXT_SPECIFIC, NULL, 0));
		return rv == CKR_USER_ALREADY_LOGGED_IN ? 0 : rv;
	}

	/* Call UI to ask for a PIN */
	ui = UI_new_method(ctx->ui_method);
	if (!ui)
		return P11_R_UI_FAILED;
	if (ctx->ui_user_data)
		UI_add_user_data(ui, ctx->ui_user_data);
	memset(pin, 0, MAX_PIN_LENGTH+1);
	prompt = UI_construct_prompt(ui, "PKCS#11 key PIN", key->label);
	if (!prompt) {
		return P11_R_UI_FAILED;
	}
	if (UI_dup_input_string(ui, prompt,
			UI_INPUT_FLAG_DEFAULT_PWD, pin, 4, MAX_PIN_LENGTH) <= 0) {
		UI_free(ui);
		OPENSSL_free(prompt);
		return P11_R_UI_FAILED;
	}
	OPENSSL_free(prompt);

	if (UI_process(ui)) {
		UI_free(ui);
		return P11_R_UI_FAILED;
	}
	UI_free(ui);

	/* Login with the PIN */
	rv = CRYPTOKI_call(ctx,
		C_Login(session, CKU_CONTEXT_SPECIFIC,
			(CK_UTF8CHAR *)pin, strlen(pin)));
	OPENSSL_cleanse(pin, MAX_PIN_LENGTH+1);
	return rv == CKR_USER_ALREADY_LOGGED_IN ? 0 : rv;
}

/*
 * Return keys of a given type (public or private) matching the key_template
 * Use the cached values if available
 */
int pkcs11_enumerate_keys(PKCS11_SLOT_private *slot, unsigned int type, const PKCS11_KEY *key_template,
		PKCS11_KEY **keyp, unsigned int *countp)
{
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &slot->prv : &slot->pub;
	PKCS11_TEMPLATE tmpl = {0};
	CK_SESSION_HANDLE session;
	CK_OBJECT_CLASS object_class = type;
	int rv;

	pkcs11_addattr_var(&tmpl, CKA_CLASS, object_class);
	if (key_template) {
		if (key_template->id_len)
			pkcs11_addattr(&tmpl, CKA_ID, key_template->id, key_template->id_len);

		if (key_template->label)
			pkcs11_addattr_s(&tmpl, CKA_LABEL, key_template->label);
	}

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	rv = pkcs11_find_keys(slot, session, type, &tmpl);
	pkcs11_put_session(slot, session);
	if (rv < 0) {
		pkcs11_destroy_keys(slot, type);
		return -1;
	}

	if (keyp)
		*keyp = keys->keys;
	if (countp)
		*countp = keys->num;
	return 0;
}

/**
 * Remove an object from the associated token
 */
int pkcs11_remove_object(PKCS11_OBJECT_private *obj)
{
	PKCS11_SLOT_private *slot = obj->slot;
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	int rv;

	if (pkcs11_get_session(slot, 1, &session))
		return -1;

	rv = CRYPTOKI_call(ctx, C_DestroyObject(session, obj->object));
	pkcs11_put_session(slot, session);
	CRYPTOKI_checkerr(CKR_F_PKCS11_REMOVE_KEY, rv);

	return 0;
}

/*
 * Find all keys of a given type (public or private) matching template
 */
static int pkcs11_find_keys(PKCS11_SLOT_private *slot, CK_SESSION_HANDLE session, unsigned int type, PKCS11_TEMPLATE *tmpl)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	int rv, res = -1;

	/* Tell the PKCS11 lib to enumerate all matching objects */
	rv = CRYPTOKI_call(ctx,
		C_FindObjectsInit(session, tmpl->attrs, tmpl->nattr));
	CRYPTOKI_checkerr(CKR_F_PKCS11_FIND_KEYS, rv);

	do {
		res = pkcs11_next_key(ctx, slot, session, type);
	} while (res == 0);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(session));

	return (res < 0) ? -1 : 0;
}

static int pkcs11_next_key(PKCS11_CTX_private *ctx, PKCS11_SLOT_private *slot,
		CK_SESSION_HANDLE session, CK_OBJECT_CLASS type)
{
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	int rv;

	/* Get the next matching object */
	rv = CRYPTOKI_call(ctx, C_FindObjects(session, &obj, 1, &count));
	CRYPTOKI_checkerr(CKR_F_PKCS11_NEXT_KEY, rv);

	if (count == 0)
		return 1;

	if (pkcs11_init_key(slot, session, obj, type, NULL))
		return -1;

	return 0;
}

PKCS11_OBJECT_private *pkcs11_object_ref(PKCS11_OBJECT_private *obj)
{
	pkcs11_atomic_add(&obj->refcnt, 1, &obj->lock);
	return obj;
}

static int pkcs11_init_key(PKCS11_SLOT_private *slot, CK_SESSION_HANDLE session,
	CK_OBJECT_HANDLE object, CK_OBJECT_CLASS type, PKCS11_KEY **ret)
{
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &slot->prv : &slot->pub;
	PKCS11_OBJECT_private *kpriv;
	PKCS11_KEY *key, *tmp;
	int i;

	/* Prevent re-adding existing PKCS#11 object handles */
	/* TODO: Rewrite the O(n) algorithm as O(log n),
	 * or it may be too slow with a large number of keys */
	for (i = 0; i < keys->num; ++i) {
		if (PRIVKEY(&keys->keys[i])->object == object) {
			if (ret)
				*ret = &keys->keys[i];
			return 0;
		}
	}

	kpriv = pkcs11_object_from_handle(slot, session, object);
	if (!kpriv)
		return -1;

	/* Allocate memory */
	tmp = OPENSSL_realloc(keys->keys, (keys->num + 1) * sizeof(PKCS11_KEY));
	if (!tmp) {
		pkcs11_object_free(kpriv);
		return -1;
	}
	keys->keys = tmp;
	key = keys->keys + keys->num++;
	memset(key, 0, sizeof(PKCS11_KEY));

	/* Fill public properties */
	key->_private = kpriv;
	key->id = kpriv->id;
	key->id_len = kpriv->id_len;
	key->label = kpriv->label;
	key->isPrivate = (type == CKO_PRIVATE_KEY);

	if (ret)
		*ret = key;
	return 0;
}

/*
 * Destroy all keys of a given type (public or private)
 */
void pkcs11_destroy_keys(PKCS11_SLOT_private *slot, unsigned int type)
{
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &slot->prv : &slot->pub;

	while (keys->num > 0) {
		PKCS11_KEY *key = &keys->keys[--keys->num];
		PKCS11_OBJECT_private *obj = PRIVKEY(key);

		if (obj) {
			EVP_PKEY_free(obj->evp_key);
			pkcs11_object_free(obj);
		}
	}
	if (keys->keys)
		OPENSSL_free(keys->keys);
	keys->keys = NULL;
	keys->num = 0;
}

/* vim: set noexpandtab: */
