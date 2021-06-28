/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2015-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

#ifndef _LIBP11_INT_H
#define _LIBP11_INT_H

#ifndef _WIN32
#include "config.h"
#endif

#include "libp11.h"

#define CRYPTOKI_EXPORTS
#include "pkcs11.h"

#include "p11_pthread.h"

/* forward and type declarations */
typedef struct pkcs11_ctx_private PKCS11_CTX_private;
typedef struct pkcs11_slot_private PKCS11_SLOT_private;
typedef struct pkcs11_token_private PKCS11_TOKEN_private;
typedef struct pkcs11_key_private PKCS11_KEY_private;
typedef struct pkcs11_cert_private PKCS11_CERT_private;
typedef struct pkcs11_key_ops PKCS11_KEY_ops;

/* get private implementations of PKCS11 structures */

/*
 * PKCS11_CTX: context for a PKCS11 implementation
 */
struct pkcs11_ctx_private {
	CK_FUNCTION_LIST_PTR method;
	void *handle;
	char *init_args;
	UI_METHOD *ui_method; /* UI_METHOD for CKU_CONTEXT_SPECIFIC PINs */
	void *ui_user_data;
	unsigned int forkid;
	pthread_mutex_t fork_lock;
};
#define PRIVCTX(_ctx)		((PKCS11_CTX_private *) ((_ctx)->_private))

struct pkcs11_slot_private {
	PKCS11_CTX_private *ctx;
	PKCS11_TOKEN_private *token;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int8_t rw_mode, logged_in;
	CK_SLOT_ID id;
	CK_SESSION_HANDLE *session_pool;
	unsigned int session_head, session_tail, session_poolsize;
	unsigned int num_sessions, max_sessions;
	unsigned int forkid;

	/* options used in last PKCS11_login */
	char *prev_pin;
};
#define PRIVSLOT(_slot)		((PKCS11_SLOT_private *) ((_slot)->_private))

typedef struct pkcs11_keys {
	int num;
	PKCS11_KEY *keys;
} PKCS11_keys;

struct pkcs11_token_private {
	PKCS11_SLOT_private *slot;
	CK_BBOOL secure_login;
	PKCS11_keys prv, pub;
	int ncerts;
	PKCS11_CERT *certs;
};
#define PRIVTOKEN(_token)	((PKCS11_TOKEN_private *) (PRIVSLOT((_token)->slot)->token))

struct pkcs11_key_private {
	PKCS11_TOKEN_private *token;
	CK_OBJECT_HANDLE object;
	CK_BBOOL always_authenticate;
	CK_BBOOL is_private;
	unsigned char id[255];
	size_t id_len;
	char *label;
	PKCS11_KEY_ops *ops;
	EVP_PKEY *evp_key;
	unsigned int forkid;
};
#define PRIVKEY(_key)		((PKCS11_KEY_private *) (_key)->_private)

struct pkcs11_cert_private {
	PKCS11_TOKEN_private *token;
	CK_OBJECT_HANDLE object;
	unsigned char id[255];
	size_t id_len;
	char *label;
	unsigned int forkid;
};
#define PRIVCERT(_cert)		((PKCS11_CERT_private *) (_cert)->_private)

struct pkcs11_key_ops {
	int type; /* EVP_PKEY_xxx */
	EVP_PKEY *(*get_evp_key) (PKCS11_KEY_private *);
};

extern PKCS11_KEY_ops pkcs11_rsa_ops;
extern PKCS11_KEY_ops *pkcs11_ec_ops;

/*
 * Internal functions
 */
#define CRYPTOKI_checkerr(f, rv) \
	do { \
		if (rv) { \
			CKRerr(f, rv); \
			return -1; \
		} \
		ERR_clear_error(); \
	} while (0)
#define CRYPTOKI_call(ctx, func_and_args) \
	ctx->method->func_and_args
extern int ERR_load_CKR_strings(void);

/* Memory allocation */
#define PKCS11_DUP(s) \
	pkcs11_strdup((char *) s, sizeof(s))
extern char *pkcs11_strdup(char *, size_t);

/* Emulate the OpenSSL 1.1 getters */
#if OPENSSL_VERSION_NUMBER < 0x10100003L || defined(LIBRESSL_VERSION_NUMBER)
#define EVP_PKEY_get0_RSA(key) ((key)->pkey.rsa)
#define EVP_PKEY_get0_EC_KEY(key) ((key)->pkey.ec)
#endif

/* Reinitializing the module after fork (if detected) */
extern unsigned int get_forkid();
extern int check_fork(PKCS11_CTX_private *ctx);
extern int check_slot_fork(PKCS11_SLOT_private *slot);
extern int check_token_fork(PKCS11_TOKEN_private *token);
extern int check_key_fork(PKCS11_KEY_private *key);
extern int check_cert_fork(PKCS11_CERT_private *cert);

/* Other internal functions */
extern void *C_LoadModule(const char *name, CK_FUNCTION_LIST_PTR_PTR);
extern CK_RV C_UnloadModule(void *module);
extern void pkcs11_destroy_keys(PKCS11_TOKEN_private *, unsigned int);
extern void pkcs11_destroy_certs(PKCS11_TOKEN_private *);
extern int pkcs11_reload_key(PKCS11_KEY_private *);
extern int pkcs11_reload_certificate(PKCS11_CERT_private *cert);
extern int pkcs11_reload_slot(PKCS11_SLOT_private *spriv);

/* Managing object attributes */
extern int pkcs11_getattr_var(PKCS11_CTX_private *, CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
	CK_ATTRIBUTE_TYPE, CK_BYTE *, size_t *);
extern int pkcs11_getattr_val(PKCS11_CTX_private *, CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
	CK_ATTRIBUTE_TYPE, void *, size_t);
extern int pkcs11_getattr_alloc(PKCS11_CTX_private *, CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
	CK_ATTRIBUTE_TYPE, CK_BYTE **, size_t *);
/*
 * Caution: the BIGNUM ** shall reference either a NULL pointer or a
 * pointer to a valid BIGNUM.
 */
extern int pkcs11_getattr_bn(PKCS11_CTX_private *, CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
	CK_ATTRIBUTE_TYPE, BIGNUM **);

typedef int (*pkcs11_i2d_fn) (void *, unsigned char **);
extern void pkcs11_addattr(CK_ATTRIBUTE_PTR, int, const void *, size_t);
extern void pkcs11_addattr_int(CK_ATTRIBUTE_PTR, int, unsigned long);
extern void pkcs11_addattr_bool(CK_ATTRIBUTE_PTR, int, int);
extern void pkcs11_addattr_s(CK_ATTRIBUTE_PTR, int, const char *);
extern void pkcs11_addattr_bn(CK_ATTRIBUTE_PTR, int, const BIGNUM *);
extern void pkcs11_addattr_obj(CK_ATTRIBUTE_PTR, int, pkcs11_i2d_fn, void *);
extern void pkcs11_zap_attrs(CK_ATTRIBUTE_PTR, unsigned int);

/* Internal implementation of current features */

/* Allocate the context */
extern PKCS11_CTX *pkcs11_CTX_new(void);

/* Specify any private PKCS#11 module initialization args, if necessary */
extern void pkcs11_CTX_init_args(PKCS11_CTX *ctx, const char *init_args);

/* Load a PKCS#11 module */
extern int pkcs11_CTX_load(PKCS11_CTX *ctx, const char *ident);

/* Reinitialize a PKCS#11 module (after a fork) */
extern int pkcs11_CTX_reload(PKCS11_CTX_private *ctx);

/* Unload a PKCS#11 module */
extern void pkcs11_CTX_unload(PKCS11_CTX *ctx);

/* Free a libp11 context */
extern void pkcs11_CTX_free(PKCS11_CTX *ctx);

/* Open a session in RO or RW mode */
extern int pkcs11_open_session(PKCS11_SLOT_private *spriv, int rw);

/* Acquire a session from the slot specific session pool */
extern int pkcs11_get_session(PKCS11_SLOT_private *spriv, int rw, CK_SESSION_HANDLE *sessionp);

/* Return a session the the slot specific session pool */
extern void pkcs11_put_session(PKCS11_SLOT_private *spriv, CK_SESSION_HANDLE session);

/* Get a list of all slots */
extern int pkcs11_enumerate_slots(PKCS11_CTX_private * ctx,
			PKCS11_SLOT **slotsp, unsigned int *nslotsp);

/* Get the slot_id from a slot as it is stored in private */
extern unsigned long pkcs11_get_slotid_from_slot(PKCS11_SLOT_private *spriv);

/* Free the list of slots allocated by PKCS11_enumerate_slots() */
extern void pkcs11_release_all_slots(PKCS11_CTX_private *ctx,
			PKCS11_SLOT *slots, unsigned int nslots);

/* Refresh the slot's token status */
extern int pkcs11_refresh_token(PKCS11_SLOT *slot);

/* Check if user is already authenticated to a card */
extern int pkcs11_is_logged_in(PKCS11_SLOT_private *spriv, int so, int *res);

/* Authenticate to the card */
extern int pkcs11_login(PKCS11_SLOT_private *spriv, int so, const char *pin);

/* De-authenticate from the card */
extern int pkcs11_logout(PKCS11_SLOT_private *spriv);

/* Authenticate a private the key operation if needed */
int pkcs11_authenticate(PKCS11_KEY_private *key, CK_SESSION_HANDLE session);

/* Get a list of keys associated with this token */
extern int pkcs11_enumerate_keys(PKCS11_TOKEN_private *tpriv, unsigned int type,
	PKCS11_KEY **keys, unsigned int *nkeys);

/* Remove a key from the token */
extern int pkcs11_remove_key(PKCS11_KEY_private *key);

/* Get the key type (as EVP_PKEY_XXX) */
extern int pkcs11_get_key_type(PKCS11_KEY_private *key);

/* Returns a EVP_PKEY object with the private or public key */
extern EVP_PKEY *pkcs11_get_key(PKCS11_KEY_private *key, int isPrivate);

/* Find the corresponding certificate (if any) */
extern PKCS11_CERT *pkcs11_find_certificate(PKCS11_KEY_private *key);

/* Find the corresponding key (if any) */
extern PKCS11_KEY *pkcs11_find_key(PKCS11_CERT_private *cert);

/* Find the corresponding key (if any)  pub <-> priv base on ID */
extern PKCS11_KEY_private *pkcs11_find_key_from_key(PKCS11_KEY_private *key);

/* Get a list of all certificates associated with this token */
extern int pkcs11_enumerate_certs(PKCS11_TOKEN_private *tpriv,
	PKCS11_CERT **certs, unsigned int *ncerts);

/* Remove a certificate from the token */
extern int pkcs11_remove_certificate(PKCS11_CERT_private *key);

/* Set UI method to allow retrieving CKU_CONTEXT_SPECIFIC PINs interactively */
extern int pkcs11_set_ui_method(PKCS11_CTX_private *ctx,
	UI_METHOD *ui_method, void *ui_user_data);

/* Initialize a token */
extern int pkcs11_init_token(PKCS11_TOKEN_private *token, const char *pin,
	const char *label);

/* Initialize the user PIN on a token */
extern int pkcs11_init_pin(PKCS11_TOKEN_private *token, const char *pin);

/* Change the user PIN on a token */
extern int pkcs11_change_pin(PKCS11_SLOT_private *spriv,
	const char *old_pin, const char *new_pin);

/* Store private key on a token */
extern int pkcs11_store_private_key(PKCS11_TOKEN_private *token,
	EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len);

/* Store public key on a token */
extern int pkcs11_store_public_key(PKCS11_TOKEN_private *token,
	EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len);

/* Store certificate on a token */
extern int pkcs11_store_certificate(PKCS11_TOKEN_private *token, X509 * x509,
		char *label, unsigned char *id, size_t id_len,
		PKCS11_CERT **ret_cert);

/* Access the random number generator */
extern int pkcs11_seed_random(PKCS11_SLOT_private *, const unsigned char *s, unsigned int s_len);
extern int pkcs11_generate_random(PKCS11_SLOT_private *, unsigned char *r, unsigned int r_len);

/* Internal implementation of deprecated features */

/* Generate and store a private key on the token */
extern int pkcs11_generate_key(PKCS11_TOKEN_private *tpriv,
	int algorithm, unsigned int bits,
	char *label, unsigned char* id, size_t id_len);

/* Get the RSA key modulus size (in bytes) */
extern int pkcs11_get_key_size(PKCS11_KEY_private *);

/* Get the RSA key modules as BIGNUM */
extern int pkcs11_get_key_modulus(PKCS11_KEY_private *, BIGNUM **);

/* Get the RSA key public exponent as BIGNUM */
extern int pkcs11_get_key_exponent(PKCS11_KEY_private *, BIGNUM **);

/* Sign with the RSA private key */
extern int pkcs11_sign(int type,
	const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, PKCS11_KEY_private *key);

/* This function has never been implemented */
extern int pkcs11_verify(int type,
	const unsigned char *m, unsigned int m_len,
	unsigned char *signature, unsigned int siglen, PKCS11_KEY_private *key);

/* Encrypts data using the private key */
extern int pkcs11_private_encrypt(
	int flen, const unsigned char *from,
	unsigned char *to, PKCS11_KEY_private *rsa, int padding);

/* Decrypts data using the private key */
extern int pkcs11_private_decrypt(
	int flen, const unsigned char *from,
	unsigned char *to, PKCS11_KEY_private *key, int padding);

/* Retrieve PKCS11_KEY from an RSA key */
extern PKCS11_KEY_private *pkcs11_get_ex_data_rsa(const RSA *rsa);

/* Retrieve PKCS11_KEY from an EC_KEY */
extern PKCS11_KEY_private *pkcs11_get_ex_data_ec(const EC_KEY *ec);

#endif

/* vim: set noexpandtab: */
