/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2016 Michał Trojnara <Michal.Trojnara@stunnel.org>
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
#include <openssl/bn.h>

#ifdef _WIN32
#define strncasecmp strnicmp
#endif

static int pkcs11_find_keys(PKCS11_TOKEN *, unsigned int);
static int pkcs11_next_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
	CK_SESSION_HANDLE session, CK_OBJECT_CLASS type);
static int pkcs11_init_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
	CK_SESSION_HANDLE session, CK_OBJECT_HANDLE o,
	CK_OBJECT_CLASS type, PKCS11_KEY **);
static int pkcs11_store_key(PKCS11_TOKEN *, EVP_PKEY *, unsigned int,
	char *, unsigned char *, size_t, PKCS11_KEY **);

/*
 * Find key matching a certificate
 */
PKCS11_KEY *pkcs11_find_key(PKCS11_CERT *cert)
{
	PKCS11_CERT_private *cpriv;
	PKCS11_KEY_private *kpriv;
	PKCS11_KEY *keys;
	unsigned int n, count;

	cpriv = PRIVCERT(cert);
	if (PKCS11_enumerate_keys(CERT2TOKEN(cert), &keys, &count))
		return NULL;
	for (n = 0; n < count; n++) {
		kpriv = PRIVKEY(&keys[n]);
		if (cpriv->id_len == kpriv->id_len
				&& !memcmp(cpriv->id, kpriv->id, cpriv->id_len))
			return &keys[n];
	}
	return NULL;
}

/*
 * Find key matching a key of the other type (public vs private)
 */
PKCS11_KEY *pkcs11_find_key_from_key(PKCS11_KEY * keyin)
{
	PKCS11_KEY_private *kinpriv = PRIVKEY(keyin);
	PKCS11_KEY *keys;
	unsigned int n, count;

	pkcs11_enumerate_keys(KEY2TOKEN(keyin),
		keyin->isPrivate ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY, /* other type */
		&keys, &count);
	for (n = 0; n < count; n++) {
		PKCS11_KEY_private *kpriv = PRIVKEY(&keys[n]);
		if (kinpriv->id_len == kpriv->id_len
				&& !memcmp(kinpriv->id, kpriv->id, kinpriv->id_len))
			return &keys[n];
	}
	return NULL;
}

/*
 * Reopens the object associated with the key
 */
int pkcs11_reload_key(PKCS11_KEY * key)
{
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	CK_OBJECT_CLASS key_search_class =
		key->isPrivate ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
	CK_ATTRIBUTE key_search_attrs[2] = {
		{CKA_CLASS, &key_search_class, sizeof(key_search_class)},
		{CKA_ID, kpriv->id, kpriv->id_len},
	};
	CK_ULONG count;
	int rv;

	/* this is already covered with a per-ctx lock */

	rv = CRYPTOKI_call(ctx,
		C_FindObjectsInit(spriv->session, key_search_attrs, 2));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_KEYS, rv);

	rv = CRYPTOKI_call(ctx,
		C_FindObjects(spriv->session, &kpriv->object, 1, &count));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_KEYS, rv);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(spriv->session));

	return 0;
}

/*
 * Generate and store a private key on the token
 * FIXME: We should check first whether the token supports
 * on-board key generation, and if it does, use its own algorithm
 */
int pkcs11_generate_key(PKCS11_TOKEN * token, int algorithm, unsigned int bits,
		char *label, unsigned char* id, size_t id_len)
{
	PKCS11_KEY *key_obj;
	EVP_PKEY *pk;
	RSA *rsa;
	BIO *err;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	BIGNUM *exp = NULL;
	BN_GENCB *gencb = NULL;
#endif
	int rc;

	if (algorithm != EVP_PKEY_RSA) {
		PKCS11err(PKCS11_F_PKCS11_GENERATE_KEY, PKCS11_NOT_SUPPORTED);
		return -1;
	}

	err = BIO_new_fp(stderr, BIO_NOCLOSE);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	exp = BN_new();
	rsa = RSA_new();
	gencb = BN_GENCB_new();
	if (gencb)
	    BN_GENCB_set(gencb, NULL, err);

	if ( rsa == NULL  || exp == NULL || gencb == NULL
	    || !BN_set_word(exp, RSA_F4) || !RSA_generate_key_ex(rsa, bits, exp, gencb)) {
		RSA_free(rsa);
	}
	BN_GENCB_free(gencb);
	BN_free(exp);

#else
	rsa = RSA_generate_key(bits, RSA_F4, NULL, err);
#endif
	BIO_free(err);
	if (rsa == NULL) {
		PKCS11err(PKCS11_F_PKCS11_GENERATE_KEY, PKCS11_KEYGEN_FAILED);
		return -1;
	}

	pk = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pk, rsa);
	rc = pkcs11_store_key(token, pk, CKO_PRIVATE_KEY,
		label, id, id_len, &key_obj);

	if (rc == 0) {
		PKCS11_KEY_private *kpriv;

		kpriv = PRIVKEY(key_obj);
		rc = pkcs11_store_key(token, pk, CKO_PUBLIC_KEY,
			label, kpriv->id, kpriv->id_len, NULL);
	}
	EVP_PKEY_free(pk);
	return rc;
}

/*
 * Store a private key on the token
 */
int pkcs11_store_private_key(PKCS11_TOKEN * token, EVP_PKEY * pk,
		char *label, unsigned char *id, size_t id_len)
{
	if (pkcs11_store_key(token, pk, CKO_PRIVATE_KEY, label, id, id_len, NULL))
		return -1;
	return 0;
}

int pkcs11_store_public_key(PKCS11_TOKEN * token, EVP_PKEY * pk,
		char *label, unsigned char *id, size_t id_len)
{
	if (pkcs11_store_key(token, pk, CKO_PUBLIC_KEY, label, id, id_len, NULL))
		return -1;
	return 0;
}

/*
 * Store private key
 */
static int pkcs11_store_key(PKCS11_TOKEN * token, EVP_PKEY * pk,
		unsigned int type, char *label, unsigned char *id, size_t id_len,
		PKCS11_KEY ** ret_key)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;
	BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_p, *rsa_q;

	/* First, make sure we have a session */
	if (!spriv->haveSession && PKCS11_open_session(slot, 1))
		return -1;

	/* Now build the key attrs */
	pkcs11_addattr_int(attrs + n++, CKA_CLASS, type);
	if (label)
		pkcs11_addattr_s(attrs + n++, CKA_LABEL, label);
	if (id && id_len)
		pkcs11_addattr(attrs + n++, CKA_ID, id, id_len);
	pkcs11_addattr_bool(attrs + n++, CKA_TOKEN, TRUE);
	if (type == CKO_PRIVATE_KEY) {
		pkcs11_addattr_bool(attrs + n++, CKA_PRIVATE, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_SENSITIVE, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_DECRYPT, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_SIGN, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_UNWRAP, TRUE);
	} else { /* CKO_PUBLIC_KEY */
		pkcs11_addattr_bool(attrs + n++, CKA_ENCRYPT, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_VERIFY, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_WRAP, TRUE);
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
	if (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA) {
		RSA *rsa = EVP_PKEY_get1_RSA(pk);
#else
	if (pk->type == EVP_PKEY_RSA) {
		RSA *rsa = pk->pkey.rsa;
#endif
		pkcs11_addattr_int(attrs + n++, CKA_KEY_TYPE, CKK_RSA);
#if OPENSSL_VERSION_NUMBER >= 0x10100005L
		RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
		RSA_get0_factors(rsa, &rsa_p, &rsa_q);
#else
		rsa_n=rsa->n;
		rsa_e=rsa->e;
		rsa_d=rsa->d;
		rsa_p=rsa->p;
		rsa_q=rsa->q;
#endif
		pkcs11_addattr_bn(attrs + n++, CKA_MODULUS, rsa_n);
		pkcs11_addattr_bn(attrs + n++, CKA_PUBLIC_EXPONENT, rsa_e);
		if (type == CKO_PRIVATE_KEY) {
			pkcs11_addattr_bn(attrs + n++, CKA_PRIVATE_EXPONENT, rsa_d);
			pkcs11_addattr_bn(attrs + n++, CKA_PRIME_1, rsa_p);
			pkcs11_addattr_bn(attrs + n++, CKA_PRIME_2, rsa_q);
		}
	} else {
		pkcs11_zap_attrs(attrs, n);
		PKCS11err(type == CKO_PRIVATE_KEY ?
				PKCS11_F_PKCS11_STORE_PRIVATE_KEY :
				PKCS11_F_PKCS11_STORE_PUBLIC_KEY,
			PKCS11_NOT_SUPPORTED);
		return -1;
	}

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(spriv->session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(PKCS11_F_PKCS11_STORE_PRIVATE_KEY, rv);

	/* Gobble the key object */
	return pkcs11_init_key(ctx, token, spriv->session, object, type, ret_key);
}

/*
 * Get the key type
 */
int pkcs11_get_key_type(PKCS11_KEY * key)
{
	PKCS11_KEY_private *kpriv = PRIVKEY(key);

	return kpriv->ops->type;
}

/*
 * Create an EVP_PKEY OpenSSL object for a given key
 * Returns private or public key depending on isPrivate
 */
EVP_PKEY *pkcs11_get_key(PKCS11_KEY *key, int isPrivate)
{
	if (key->isPrivate != isPrivate)
		key = pkcs11_find_key_from_key(key);
	if (key == NULL)
		return NULL;
	if (key->evp_key == NULL) {
		PKCS11_KEY_private *kpriv = PRIVKEY(key);
		key->evp_key = kpriv->ops->get_evp_key(key);
		if (key->evp_key == NULL)
			return NULL;
		kpriv->always_authenticate = CK_FALSE;
		if(isPrivate) {
			if(key_getattr_val(key, CKA_ALWAYS_AUTHENTICATE,
					&kpriv->always_authenticate, sizeof(CK_BBOOL)))
				fprintf(stderr, "Missing CKA_ALWAYS_AUTHENTICATE attribute\n");
		}
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_PKEY_up_ref(key->evp_key);
#else
	CRYPTO_add(&key->evp_key->references, 1, CRYPTO_LOCK_EVP_PKEY);
#endif
	return key->evp_key;
}

/*
 * Authenticate a private the key operation if needed
 */
int pkcs11_authenticate(PKCS11_KEY *key)
{
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	int rv;
	const char* pin = NULL;

	if (!kpriv->always_authenticate)
		return 0;

	if (spriv->prev_callbacks) {
		pin = spriv->prev_callbacks->pin_get(spriv->prev_callbacks->pin_get_data, spriv->id,
			(slot->token ? slot->token->label : NULL), spriv->prev_so);
	} else {
		pin = spriv->prev_pin;
	}

	rv = CRYPTOKI_call(ctx,
		C_Login(spriv->session, CKU_CONTEXT_SPECIFIC,
			(CK_UTF8CHAR *) pin,
			pin ? strlen(pin) : 0));
	if (rv == CKR_USER_ALREADY_LOGGED_IN) /* ignore */
		rv = 0;

	if (spriv->prev_callbacks && spriv->prev_callbacks->pin_done) {
		spriv->prev_callbacks->pin_done(spriv->prev_callbacks->pin_done_data, spriv->id,
			(slot->token ? slot->token->label : NULL), spriv->prev_so);
	}

	return rv;
}

/*
 * Return keys of a given type (public or private)
 * Use the cached values if available
 */
int pkcs11_enumerate_keys(PKCS11_TOKEN * token, unsigned int type,
		PKCS11_KEY ** keyp, unsigned int * countp)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &tpriv->prv : &tpriv->pub;
	int rv;

	if (keys->num < 0) { /* No cache was built for the specified type */
		/* Make sure we have a session */
		if (!spriv->haveSession && PKCS11_open_session(slot, 0))
			return -1;
		CRYPTO_THREAD_write_lock(cpriv->rwlock);
		rv = pkcs11_find_keys(token, type);
		CRYPTO_THREAD_unlock(cpriv->rwlock);
		if (rv < 0) {
			pkcs11_destroy_keys(token, type);
			return -1;
		}
	}
	if (keyp)
		*keyp = keys->keys;
	if (countp)
		*countp = keys->num;
	return 0;
}

/*
 * Find all keys of a given type (public or private)
 */
static int pkcs11_find_keys(PKCS11_TOKEN * token, unsigned int type)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &tpriv->prv : &tpriv->pub;
	CK_OBJECT_CLASS key_search_class;
	CK_ATTRIBUTE key_search_attrs[1] = {
		{CKA_CLASS, &key_search_class, sizeof(key_search_class)},
	};
	int rv, res = -1;

	/* Tell the PKCS11 lib to enumerate all matching objects */
	key_search_class = type;
	rv = CRYPTOKI_call(ctx,
		C_FindObjectsInit(spriv->session, key_search_attrs, 1));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_KEYS, rv);

	keys->num = 0;
	do {
		res = pkcs11_next_key(ctx, token, spriv->session, type);
	} while (res == 0);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(spriv->session));

	return (res < 0) ? -1 : 0;
}

static int pkcs11_next_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
		CK_SESSION_HANDLE session, CK_OBJECT_CLASS type)
{
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	int rv;

	/* Get the next matching object */
	rv = CRYPTOKI_call(ctx, C_FindObjects(session, &obj, 1, &count));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_KEYS, rv);

	if (count == 0)
		return 1;

	if (pkcs11_init_key(ctx, token, session, obj, type, NULL))
		return -1;

	return 0;
}

static int pkcs11_init_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
		CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
		CK_OBJECT_CLASS type, PKCS11_KEY ** ret)
{
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &tpriv->prv : &tpriv->pub;
	PKCS11_KEY_private *kpriv;
	PKCS11_KEY *key, *tmp;
	CK_KEY_TYPE key_type;
	PKCS11_KEY_ops *ops;
	size_t size;

	(void)ctx;
	(void)session;

	size = sizeof(key_type);
	if (pkcs11_getattr_var(token, obj, CKA_KEY_TYPE, (CK_BYTE *)&key_type, &size))
		return -1;

	switch (key_type) {
	case CKK_RSA:
		ops = &pkcs11_rsa_ops;
		break;
	case CKK_EC:
		ops = pkcs11_ec_ops;
		if (ops == NULL)
			return 0; /* not supported */
		break;
	default:
		/* Ignore any keys we don't understand */
		return 0;
	}

	tmp = OPENSSL_realloc(keys->keys, (keys->num + 1) * sizeof(PKCS11_KEY));
	if (tmp == NULL) {
		OPENSSL_free(keys->keys);
		keys->keys = NULL;
		return -1;
	}
	keys->keys = tmp;

	key = keys->keys + keys->num++;
	memset(key, 0, sizeof(PKCS11_KEY));
	kpriv = OPENSSL_malloc(sizeof(PKCS11_KEY_private));
	if (kpriv)
		memset(kpriv, 0, sizeof(PKCS11_KEY_private));
	key->_private = kpriv;
	kpriv->object = obj;
	kpriv->parent = token;

	pkcs11_getattr_alloc(token, obj, CKA_LABEL, (CK_BYTE **)&key->label, NULL);
	key->id_len = 0;
	pkcs11_getattr_alloc(token, obj, CKA_ID, &key->id, &key->id_len);
	key->isPrivate = (type == CKO_PRIVATE_KEY);

	/* Initialize internal information */
	kpriv->id_len = sizeof(kpriv->id);
	if (pkcs11_getattr_var(token, obj, CKA_ID, kpriv->id, &kpriv->id_len))
		kpriv->id_len = 0;
	kpriv->ops = ops;
	kpriv->forkid = _P11_get_forkid();

	if (ret)
		*ret = key;
	return 0;
}

/*
 * Destroy all keys of a given type (public or private)
 */
void pkcs11_destroy_keys(PKCS11_TOKEN * token, unsigned int type)
{
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &tpriv->prv : &tpriv->pub;

	while (keys->num > 0) {
		PKCS11_KEY *key = &keys->keys[--(keys->num)];

		if (key->evp_key)
			EVP_PKEY_free(key->evp_key);
		OPENSSL_free(key->label);
		if (key->id)
			OPENSSL_free(key->id);
		if (key->_private != NULL)
			OPENSSL_free(key->_private);
	}
	if (keys->keys)
		OPENSSL_free(keys->keys);
	keys->keys = NULL;
	keys->num = -1;
}

/* vim: set noexpandtab: */
