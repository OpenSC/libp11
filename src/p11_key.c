/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
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

#include <config.h>
#include <string.h>
#include "libp11-int.h"

#ifdef _WIN32
#define strncasecmp strnicmp
#endif

static int pkcs11_find_keys(PKCS11_TOKEN *, unsigned int);
static int pkcs11_next_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
			   CK_SESSION_HANDLE session, CK_OBJECT_CLASS type);
static int pkcs11_init_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
			   CK_SESSION_HANDLE session, CK_OBJECT_HANDLE o,
			   CK_OBJECT_CLASS type, PKCS11_KEY **);
static int pkcs11_store_private_key(PKCS11_TOKEN *, EVP_PKEY *, char *,
				    unsigned char *, unsigned int, PKCS11_KEY **);
static int pkcs11_store_public_key(PKCS11_TOKEN *, EVP_PKEY *, char *,
				   unsigned char *, unsigned int, PKCS11_KEY **);

static CK_OBJECT_CLASS key_search_class;
static CK_ATTRIBUTE key_search_attrs[] = {
	{CKA_CLASS, &key_search_class, sizeof(key_search_class)},
};
#define numof(arr)	(sizeof(arr)/sizeof((arr)[0]))
#define MAX_VALUE_LEN     200

/*
 * Enumerate all keys on the card
 * For now, we enumerate just the private keys.
 */
int
PKCS11_enumerate_keys(PKCS11_TOKEN * token, PKCS11_KEY ** keyp, unsigned int *countp)
{
	PKCS11_TOKEN_private *priv = PRIVTOKEN(token);

	if (priv->nkeys < 0) {
		priv->nkeys = 0;
		if (pkcs11_find_keys(token, CKO_PRIVATE_KEY)) {
			pkcs11_destroy_keys(token);
			return -1;
		}
		priv->nprkeys = priv->nkeys;
		if (pkcs11_find_keys(token, CKO_PUBLIC_KEY)) {
			pkcs11_destroy_keys(token);
			return -1;
		}
	}
	*keyp = priv->keys;
	*countp = priv->nprkeys;
	return 0;
}

/*
 * Find key matching a certificate
 */
PKCS11_KEY *PKCS11_find_key(PKCS11_CERT *cert)
{
        PKCS11_CERT_private *cpriv;
        PKCS11_KEY_private *kpriv;
        PKCS11_KEY *key;
        unsigned int n, count;

	cpriv = PRIVCERT(cert);
        if (PKCS11_enumerate_keys(CERT2TOKEN(cert), &key, &count))
                return NULL;
        for (n = 0; n < count; n++, key++) {
                kpriv = PRIVKEY(key);
                if (cpriv->id_len == kpriv->id_len
                    && !memcmp(cpriv->id, kpriv->id, cpriv->id_len))
                        return key;
        }
        return NULL;
}

/*
 * Store a private key on the token
 */
int PKCS11_store_private_key(PKCS11_TOKEN * token, EVP_PKEY * pk, char *label, unsigned char *id, unsigned int id_len)
{
	if (pkcs11_store_private_key(token, pk, label, id, id_len, NULL))
		return -1;
	return 0;
}

int PKCS11_store_public_key(PKCS11_TOKEN * token, EVP_PKEY * pk, char *label, unsigned char *id, unsigned int id_len)
{
	if (pkcs11_store_public_key(token, pk, label, id, id_len, NULL))
		return -1;
	return 0;
}

/*
 * Generate and store a private key on the token
 * FIXME: We should check first whether the token supports
 * on-board key generation, and if it does, use its own algorithm
 */
int
PKCS11_generate_key(PKCS11_TOKEN * token,
		    int algorithm, unsigned int bits, char *label, unsigned char* id, unsigned int id_len)
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
	rsa = RSA_generate_key(bits, 0x10001, NULL, err);
	BIO_free(err);
	if (rsa == NULL) {
		PKCS11err(PKCS11_F_PKCS11_GENERATE_KEY, PKCS11_KEYGEN_FAILED);
		return -1;
	}

	pk = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pk, rsa);
	rc = pkcs11_store_private_key(token, pk, label, id, id_len, &key_obj);

	if (rc == 0) {
		PKCS11_KEY_private *kpriv;

		kpriv = PRIVKEY(key_obj);
		rc = pkcs11_store_public_key(token, pk, label,
					     kpriv->id, kpriv->id_len, NULL);
	}
	EVP_PKEY_free(pk);
	return rc;
}

/*
 * Get the key type
 */
int PKCS11_get_key_type(PKCS11_KEY * key)
{
	PKCS11_KEY_private *priv = PRIVKEY(key);

	return priv->ops->type;
}

/*
 * Create a key object that will allow an OpenSSL application
 * to use the token via an EVP_PKEY
 */
EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY * key)
{
	PKCS11_KEY_private *priv = PRIVKEY(key);

	if (key->evp_key == NULL) {
		EVP_PKEY *pk = EVP_PKEY_new();
		if (pk == NULL)
			return NULL;
		if (priv->ops->get_private(key, pk)
		    || priv->ops->get_public(key, pk)) {
			EVP_PKEY_free(pk);
			return NULL;
		}
		key->evp_key = pk;
	}

	return key->evp_key;
}

EVP_PKEY *PKCS11_get_public_key(PKCS11_KEY * key)
{
	return PKCS11_get_private_key(key);
}


/*
 * Find all keys of a given type (public or private)
 */
static int pkcs11_find_keys(PKCS11_TOKEN * token, unsigned int type)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_SESSION_HANDLE session;
	int rv, res = -1;

	/* Make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 0))
		return -1;
	session = PRIVSLOT(slot)->session;

	/* Tell the PKCS11 lib to enumerate all matching objects */
	key_search_class = type;
	rv = CRYPTOKI_call(ctx, C_FindObjectsInit(session, key_search_attrs,
						  numof(key_search_attrs)));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_KEYS, rv);

	do {
		res = pkcs11_next_key(ctx, token, session, type);
	} while (res == 0);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(session));
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
	PKCS11_TOKEN_private *tpriv;
	PKCS11_KEY_private *kpriv;
	PKCS11_KEY *key, *tmp;
	char label[256];
	unsigned char id[256];
	CK_KEY_TYPE key_type;
	PKCS11_KEY_ops *ops;
	size_t size;

	size = sizeof(key_type);
	if (pkcs11_getattr_var(token, obj, CKA_KEY_TYPE, &key_type, &size))
		return -1;

	switch (key_type) {
	case CKK_RSA:
		ops = &pkcs11_rsa_ops;
		break;
	default:
		/* Ignore any keys we don't understand */
		return 0;
	}

	tpriv = PRIVTOKEN(token);
	tmp = (PKCS11_KEY *) OPENSSL_realloc(tpriv->keys,
				(tpriv->nkeys + 1) * sizeof(PKCS11_KEY));
	if (!tmp) {
		free(tpriv->keys);
		tpriv->keys = NULL;
		return -1;
	}
	tpriv->keys = tmp;

	key = tpriv->keys + tpriv->nkeys++;
	memset(key, 0, sizeof(*key));
	key->_private = kpriv = PKCS11_NEW(PKCS11_KEY_private);
	kpriv->object = obj;
	kpriv->parent = token;

	if (!pkcs11_getattr_s(token, obj, CKA_LABEL, label, sizeof(label)))
		key->label = BUF_strdup(label);
	key->id_len = sizeof(id);
	if (!pkcs11_getattr_var(token, obj, CKA_ID, id, (size_t *) & key->id_len)) {
		key->id = (unsigned char *) malloc(key->id_len);
		memcpy(key->id, id, key->id_len);
	}
	key->isPrivate = (type == CKO_PRIVATE_KEY);

	/* Initialize internal information */
	kpriv->id_len = sizeof(kpriv->id);
	if (pkcs11_getattr_var(token, obj, CKA_ID, kpriv->id, &kpriv->id_len))
		kpriv->id_len = 0;
	kpriv->ops = ops;

	if (ret)
		*ret = key;
	return 0;
}

/*
 * Destroy all keys
 */
void pkcs11_destroy_keys(PKCS11_TOKEN * token)
{
	PKCS11_TOKEN_private *priv = PRIVTOKEN(token);

	while (priv->nkeys > 0) {
		PKCS11_KEY *key = &priv->keys[--(priv->nkeys)];

		if (key->evp_key)
			EVP_PKEY_free(key->evp_key);
		OPENSSL_free(key->label);
		if (key->id)
			free(key->id);
		if (key->_private != NULL)
			OPENSSL_free(key->_private);
	}
	if (priv->keys)
		OPENSSL_free(priv->keys);
	priv->nprkeys = -1;
	priv->nkeys = -1;
	priv->keys = NULL;
}

/*
 * Store private key
 */
static int pkcs11_store_private_key(PKCS11_TOKEN * token, EVP_PKEY * pk,
		char *label, unsigned char *id, unsigned int id_len,
		PKCS11_KEY ** ret_key)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;

	/* First, make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 1))
		return -1;
	session = PRIVSLOT(slot)->session;

	/* Now build the key attrs */
	if (pk->type == EVP_PKEY_RSA) {
		RSA *rsa = EVP_PKEY_get1_RSA(pk);

		pkcs11_addattr_int(attrs + n++, CKA_CLASS, CKO_PRIVATE_KEY);
		pkcs11_addattr_int(attrs + n++, CKA_KEY_TYPE, CKK_RSA);

		pkcs11_addattr_bool(attrs + n++, CKA_TOKEN, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_PRIVATE, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_SENSITIVE, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_DECRYPT, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_SIGN, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_UNWRAP, TRUE);

		pkcs11_addattr_bn(attrs + n++, CKA_MODULUS, rsa->n);
		pkcs11_addattr_bn(attrs + n++, CKA_PUBLIC_EXPONENT, rsa->e);
		pkcs11_addattr_bn(attrs + n++, CKA_PRIVATE_EXPONENT, rsa->d);
		pkcs11_addattr_bn(attrs + n++, CKA_PRIME_1, rsa->p);
		pkcs11_addattr_bn(attrs + n++, CKA_PRIME_2, rsa->q);

		if (label)
			pkcs11_addattr_s(attrs + n++, CKA_LABEL, label);
		if (id && id_len)
			pkcs11_addattr(attrs + n++, CKA_ID, id, id_len);

	} else {
		PKCS11err(PKCS11_F_PKCS11_STORE_PRIVATE_KEY, PKCS11_NOT_SUPPORTED);
		return -1;
	}

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(PKCS11_F_PKCS11_STORE_PRIVATE_KEY, rv);

	/* Gobble the key object */
	return pkcs11_init_key(ctx, token, session, object,
			       CKO_PRIVATE_KEY, ret_key);
}

/*
 * Store public key
 */
static int pkcs11_store_public_key(PKCS11_TOKEN * token, EVP_PKEY * pk,
		char *label, unsigned char *id, unsigned int id_len,
		PKCS11_KEY ** ret_key)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;

	/* First, make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 1))
		return -1;
	session = PRIVSLOT(slot)->session;

	/* Now build the key attrs */
	if (pk->type == EVP_PKEY_RSA) {
		RSA *rsa = EVP_PKEY_get1_RSA(pk);

		pkcs11_addattr_int(attrs + n++, CKA_CLASS, CKO_PUBLIC_KEY);
		pkcs11_addattr_int(attrs + n++, CKA_KEY_TYPE, CKK_RSA);

		pkcs11_addattr_bool(attrs + n++, CKA_TOKEN, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_ENCRYPT, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_VERIFY, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_WRAP, TRUE);

		pkcs11_addattr_bn(attrs + n++, CKA_MODULUS, rsa->n);
		pkcs11_addattr_bn(attrs + n++, CKA_PUBLIC_EXPONENT, rsa->e);
		if (label)
			pkcs11_addattr_s(attrs + n++, CKA_LABEL, label);
		if (id && id_len)
			pkcs11_addattr(attrs + n++, CKA_ID, id, id_len);
	} else {
		PKCS11err(PKCS11_F_PKCS11_STORE_PUBLIC_KEY, PKCS11_NOT_SUPPORTED);
		return -1;
	}

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(PKCS11_F_PKCS11_STORE_PUBLIC_KEY, rv);

	/* Gobble the key object */
	return pkcs11_init_key(ctx, token, session, object, CKO_PUBLIC_KEY, ret_key);
}
int PKCS11_get_key_modulus(PKCS11_KEY * key, BIGNUM **bn) 
{
	
	if (pkcs11_getattr_bn(KEY2TOKEN(key), PRIVKEY(key)->object, CKA_MODULUS, bn))
		return 0;
	return 1;
}
int PKCS11_get_key_exponent(PKCS11_KEY * key, BIGNUM **bn) 
{
	
	if (pkcs11_getattr_bn(KEY2TOKEN(key), PRIVKEY(key)->object, CKA_PUBLIC_EXPONENT, bn))
		return 0;
	return 1;
}


int PKCS11_get_key_size(const PKCS11_KEY * key) 
{
	BIGNUM* n = NULL;
	int     numbytes = 0;
	if(key_getattr_bn(key, CKA_MODULUS, &n))
		return 0;
	numbytes = BN_num_bytes(n);
	BN_free(n);
	return numbytes;
}
