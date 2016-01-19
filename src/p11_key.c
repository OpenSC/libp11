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

#ifdef _WIN32
#define strncasecmp strnicmp
#endif

static int pkcs11_enumerate_keys(PKCS11_TOKEN *, unsigned int,
	PKCS11_KEY **, unsigned int *);
static int pkcs11_find_keys(PKCS11_TOKEN *, unsigned int);
static int pkcs11_next_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
	CK_SESSION_HANDLE session, CK_OBJECT_CLASS type);
static int pkcs11_init_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
	CK_SESSION_HANDLE session, CK_OBJECT_HANDLE o,
	CK_OBJECT_CLASS type, PKCS11_KEY **);
static int pkcs11_store_key(PKCS11_TOKEN *, EVP_PKEY *, unsigned int,
	char *, unsigned char *, size_t, PKCS11_KEY **);

/*
 * Enumerate private keys on the card
 */
int
PKCS11_enumerate_keys(PKCS11_TOKEN * token,
		PKCS11_KEY ** keyp, unsigned int *countp)
{
	return pkcs11_enumerate_keys(token, CKO_PRIVATE_KEY, keyp, countp);
}

/*
 * Enumerate public keys on the card
 */
int
PKCS11_enumerate_public_keys(PKCS11_TOKEN * token,
		PKCS11_KEY ** keyp, unsigned int *countp)
{
	return pkcs11_enumerate_keys(token, CKO_PUBLIC_KEY, keyp, countp);
}

/*
 * Find key matching a certificate
 */
PKCS11_KEY *PKCS11_find_key(PKCS11_CERT *cert)
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
 * Find key matching a key of the other type pub vs priv
 */
PKCS11_KEY *PKCS11_find_key_from_key(PKCS11_KEY * keyin)
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
int
PKCS11_generate_key(PKCS11_TOKEN * token, int algorithm, unsigned int bits,
		char *label, unsigned char* id, size_t id_len)
{
	PKCS11_KEY *key_obj;
	EVP_PKEY *pk;
	RSA *rsa;
	BIO *err;
	int rc;

	if (algorithm != EVP_PKEY_RSA) {
		PKCS11err(PKCS11_F_PKCS11_GENERATE_KEY, PKCS11_NOT_SUPPORTED);
		return -1;
	}

	err = BIO_new_fp(stderr, BIO_NOCLOSE);
	rsa = RSA_generate_key(bits, RSA_F4, NULL, err);
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
int PKCS11_store_private_key(PKCS11_TOKEN * token, EVP_PKEY * pk,
		char *label, unsigned char *id, size_t id_len)
{
	if (pkcs11_store_key(token, pk, CKO_PRIVATE_KEY, label, id, id_len, NULL))
		return -1;
	return 0;
}

int PKCS11_store_public_key(PKCS11_TOKEN * token, EVP_PKEY * pk,
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
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;

	CHECK_SLOT_FORK(slot);

	/* First, make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 1))
		return -1;
	session = PRIVSLOT(slot)->session;

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
	if (pk->type == EVP_PKEY_RSA) {
		RSA *rsa = EVP_PKEY_get1_RSA(pk);
		pkcs11_addattr_int(attrs + n++, CKA_KEY_TYPE, CKK_RSA);
		pkcs11_addattr_bn(attrs + n++, CKA_MODULUS, rsa->n);
		pkcs11_addattr_bn(attrs + n++, CKA_PUBLIC_EXPONENT, rsa->e);
		if (type == CKO_PRIVATE_KEY) {
			pkcs11_addattr_bn(attrs + n++, CKA_PRIVATE_EXPONENT, rsa->d);
			pkcs11_addattr_bn(attrs + n++, CKA_PRIME_1, rsa->p);
			pkcs11_addattr_bn(attrs + n++, CKA_PRIME_2, rsa->q);
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
	rv = CRYPTOKI_call(ctx, C_CreateObject(session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(PKCS11_F_PKCS11_STORE_PRIVATE_KEY, rv);

	/* Gobble the key object */
	return pkcs11_init_key(ctx, token, session, object, type, ret_key);
}

/*
 * Get the key type
 */
int PKCS11_get_key_type(PKCS11_KEY * key)
{
	PKCS11_KEY_private *kpriv = PRIVKEY(key);

	return kpriv->ops->type;
}

/*
 * Create an EVP_PKEY OpenSSL object for a given key
 * Returns either private or public key object depending on the isPrivate
 * value for compatibility with a bug in engine_pkcs11 <= 0.2.0
 * TODO: Fix this when the affected engine_pkcs11 is phased out
 */
EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY * key)
{
	PKCS11_KEY_private *kpriv;

	if (key == NULL)
		return NULL;
	if (key->evp_key == NULL) {
		kpriv = PRIVKEY(key);
		key->evp_key = kpriv->ops->get_evp_key(key);
	}
	return key->evp_key;
}

/*
 * Create an EVP_PKEY OpenSSL object for a given key
 * Always returns the public key object
 */
EVP_PKEY *PKCS11_get_public_key(PKCS11_KEY * key)
{
	PKCS11_KEY_private *kpriv;

	if (key == NULL)
		return NULL;
	if (key->isPrivate) {
		key = PKCS11_find_key_from_key(key);
		if (key == NULL)
			return NULL;
	}
	if (key->evp_key == NULL) {
		kpriv = PRIVKEY(key);
		key->evp_key = kpriv->ops->get_evp_key(key);
	}
	return key->evp_key;
}

/*
 * Return keys of a given type (public or private)
 * Use the cached values if available
 */
static int pkcs11_enumerate_keys(PKCS11_TOKEN * token, unsigned int type,
		PKCS11_KEY ** keyp, unsigned int * countp)
{
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &tpriv->prv : &tpriv->pub;
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	int rv;

	if (keys->num < 0) { /* No cache was built for the specified type */
		pkcs11_w_lock(cpriv->lockid);
		rv = pkcs11_find_keys(token, type);
		pkcs11_w_unlock(cpriv->lockid);
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
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &tpriv->prv : &tpriv->pub;
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_OBJECT_CLASS key_search_class;
	CK_ATTRIBUTE key_search_attrs[1] = {
		{CKA_CLASS, &key_search_class, sizeof(key_search_class)},
	};
	int rv, res = -1;

	/* Make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 0))
		return -1;

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
	char label[256];
	unsigned char id[256];
	CK_KEY_TYPE key_type;
	PKCS11_KEY_ops *ops;
	size_t size;

	(void)ctx;
	(void)session;

	size = sizeof(key_type);
	if (pkcs11_getattr_var(token, obj, CKA_KEY_TYPE, &key_type, &size))
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

	if (!pkcs11_getattr_s(token, obj, CKA_LABEL, label, sizeof(label)))
		key->label = BUF_strdup(label);
	key->id_len = sizeof(id);
	if (!pkcs11_getattr_var(token, obj, CKA_ID, id, &key->id_len)) {
		key->id = OPENSSL_malloc(key->id_len);
		memcpy(key->id, id, key->id_len);
	}
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
