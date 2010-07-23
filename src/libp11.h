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

/**
 * @file libp11.h
 * @brief libp11 header file
 */

#ifndef _LIB11_H
#define _LIB11_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

/* get some structures for local code to handle pkcs11 data readily */
#define ERR_LIB_PKCS11	ERR_LIB_USER

#define PKCS11err(f,r) \
ERR_PUT_error(ERR_LIB_PKCS11,(f),(r),__FILE__,__LINE__)

/*
 * The purpose of this library is to provide a simple PKCS11
 * interface to OpenSSL application that wish to use a previously
 * initialized card (as opposed to initializing it, etc).
 *
 * I am therefore making some simplifying assumptions:
 *
 *  -	no support for any operations that alter the card,
 *  	i.e. readonly-login
 */

/** PKCS11 key object (public or private) */
typedef struct PKCS11_key_st {
	char *label;
	unsigned char *id;
	size_t id_len;
	unsigned char isPrivate;	/**< private key present? */
	unsigned char needLogin;	/**< login to read private key? */
	EVP_PKEY *evp_key;		/**< initially NULL, need to call PKCS11_load_key */
	void *_private;
} PKCS11_KEY;

/** PKCS11 certificate object */
typedef struct PKCS11_cert_st {
	char *label;
	unsigned char *id;
	size_t id_len;
	X509 *x509;
	void *_private;
} PKCS11_CERT;

/** PKCS11 token: smart card or USB key */
typedef struct PKCS11_token_st {
	char *label;
	char *manufacturer;
	char *model;
	char *serialnr;
	unsigned char initialized;
	unsigned char loginRequired;
	unsigned char secureLogin;
	unsigned char userPinSet;
	unsigned char readOnly;
	unsigned char hasRng;
	unsigned char userPinCountLow;
	unsigned char userPinFinalTry;
	unsigned char userPinLocked;
	unsigned char userPinToBeChanged;
	unsigned char soPinCountLow;
	unsigned char soPinFinalTry;
	unsigned char soPinLocked;
	unsigned char soPinToBeChanged;
	void *_private;
} PKCS11_TOKEN;

/** PKCS11 slot: card reader */
typedef struct PKCS11_slot_st {
	char *manufacturer;
	char *description;
	unsigned char removable;
	PKCS11_TOKEN *token;	/**< NULL if no token present */
	void *_private;
} PKCS11_SLOT;

/** PKCS11 context */
typedef struct PKCS11_ctx_st {
	char *manufacturer;
	char *description;
	void *_private;
} PKCS11_CTX;

/**
 * Create a new libp11 context
 *
 * This should be the first function called in the use of libp11
 * @return an allocated context
 */
extern PKCS11_CTX *PKCS11_CTX_new(void);

/**
 * Specify any private PKCS#11 module initializtion args, if necessary
 *
 * @return none
 */
extern void PKCS11_CTX_init_args(PKCS11_CTX * ctx, const char * init_args);

/**
 * Load a PKCS#11 module
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 * @param ident PKCS#11 library filename
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_CTX_load(PKCS11_CTX * ctx, const char * ident);

/**
 * Unload a PKCS#11 module
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 */
extern void PKCS11_CTX_unload(PKCS11_CTX * ctx);

/**
 * Free a libp11 context
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 */
extern void PKCS11_CTX_free(PKCS11_CTX * ctx);

/** Open a session in RO or RW mode
 *
 * @param slot slot descriptor returned by PKCS11_find_token() or PKCS11_enumerate_slots()
 * @param rw open in read/write mode is mode != 0, otherwise in read only mode
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_open_session(PKCS11_SLOT * slot, int rw);

/**
 * Get a list of all slots
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 * @param slotsp pointer on a list of slots
 * @param nslotsp size of the allocated list
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_enumerate_slots(PKCS11_CTX * ctx,
			PKCS11_SLOT **slotsp, unsigned int *nslotsp);

/**
 * Get the slot_id from a slot as it is stored in private
 *
 * @param slotp pointer on a slot
 * @retval the slotid 
 */
extern unsigned long PKCS11_get_slotid_from_slot(PKCS11_SLOT *slotp);

/**
 * Free the list of slots allocated by PKCS11_enumerate_slots()
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 * @param slots list of slots allocated by PKCS11_enumerate_slots()
 * @param nslots size of the list
 */
extern void PKCS11_release_all_slots(PKCS11_CTX * ctx,
			PKCS11_SLOT *slots, unsigned int nslots);

/**
 * Find the first slot with a token
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 * @param slots list of slots allocated by PKCS11_enumerate_slots()
 * @param nslots size of the list
 * @retval !=NULL pointer on a slot structure
 * @retval NULL error
 */
PKCS11_SLOT *PKCS11_find_token(PKCS11_CTX * ctx, 
			PKCS11_SLOT *slots, unsigned int nslots);

/**
 * Authenticate to the card
 *
 * @param slot slot returned by PKCS11_find_token()
 * @param so login as CKU_SO if != 0, otherwise login as CKU_USER
 * @param pin PIN value
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_login(PKCS11_SLOT * slot, int so, const char *pin);

/**
 * De-authenticate from the card
 *
 * @param slot slot returned by PKCS11_find_token()
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_logout(PKCS11_SLOT * slot);

/* Get a list of all keys associated with this token */
extern int PKCS11_enumerate_keys(PKCS11_TOKEN *, PKCS11_KEY **, unsigned int *);

/* Get the key type (as EVP_PKEY_XXX) */
extern int PKCS11_get_key_type(PKCS11_KEY *);

/* Get size of key modulus in number of bytes */
extern int PKCS11_get_key_size(const PKCS11_KEY *);
/* Get actual modules and public exponent as BIGNUM */
extern int PKCS11_get_key_modulus(PKCS11_KEY *, BIGNUM **);
extern int PKCS11_get_key_exponent(PKCS11_KEY *, BIGNUM **);

/* Get the enveloped private key */
/**
 * Returns a EVP_PKEY object for the private key
 *
 * @param   key  PKCS11_KEY object
 * @retval !=NULL reference to EVP_PKEY object.
 *         The returned EVP_PKEY object should be treated as const 
 *         and must not be freed.
 * @retval NULL error
 */
extern EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY *key);
/**
 * Returns a EVP_PKEY object with the public key
 *
 * @param  key  PKCS11_KEY object
 * @retval !=NULL reference to EVP_PKEY object.
 *         The returned EVP_PKEY object should be treated as const
 *         and must not be freed.
 * @retval NULL error
 */
extern EVP_PKEY *PKCS11_get_public_key(PKCS11_KEY *key);

/* Find the corresponding certificate (if any) */
extern PKCS11_CERT *PKCS11_find_certificate(PKCS11_KEY *);

/* Find the corresponding key (if any) */
extern PKCS11_KEY *PKCS11_find_key(PKCS11_CERT *);

/* Get a list of all certificates associated with this token */
extern int PKCS11_enumerate_certs(PKCS11_TOKEN *, PKCS11_CERT **, unsigned int *);

/**
 * Initialize a token
 *
 * @param token token descriptor (in general slot->token)
 * @param pin Security Officer PIN value
 * @param label new name of the token
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_init_token(PKCS11_TOKEN * token, const char *pin,
	const char *label);

/**
 * Initialize the user PIN on a token
 *
 * @param token token descriptor (in general slot->token)
 * @param pin new user PIN value
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_init_pin(PKCS11_TOKEN * token, const char *pin);

/**
 * Change the user PIN on a token
 *
 * @param slot slot returned by PKCS11_find_token()
 * @param old_pin old PIN value
 * @param new_pin new PIN value
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_change_pin(PKCS11_SLOT * slot, const char *old_pin,
	const char *new_pin);

/** 
 * Generate and store a private key on the token
 *
 * @param token token returned by PKCS11_find_token()
 * @param algorithm EVP_PKEY_RSA
 * @param bits size of the modulus in bits
 * @param label label for this key
 * @param id bytes to use as id value
 * @param id_len length of id value.
 * @retval 0 success
 * @retval -1 error
 */

extern int PKCS11_generate_key(PKCS11_TOKEN * token, int algorithm, unsigned int bits, char *label, unsigned char* id, size_t id_len);

/**
 * Store private key on a token
 *
 * @param token token returned by PKCS11_find_token()
 * @param pk private key
 * @param label label for this key
 * @param id bytes to use as id value
 * @param id_len length of id value.
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_store_private_key(PKCS11_TOKEN * token, EVP_PKEY * pk, char *label, unsigned char *id, size_t id_len);

/**
 * Store public key on a token
 *
 * @param token token returned by PKCS11_find_token()
 * @param pk private key
 * @param label label for this key
 * @param id bytes to use as id value
 * @param id_len length of id value.
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_store_public_key(PKCS11_TOKEN * token, EVP_PKEY * pk, char *label, unsigned char *id, size_t id_len);

/**
 * Store certificate on a token
 *
 * @param token token returned by PKCS11_find_token()
 * @param x509 x509 certificate object
 * @param label label for this certificate
 * @param id bytes to use as id value
 * @param id_len length of id value.
 * @param ret_cert put new PKCS11_CERT object here
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_store_certificate(PKCS11_TOKEN * token, X509 * x509,
		char *label, unsigned char *id, size_t id_len,
		PKCS11_CERT **ret_cert);

/* rsa private key operations */
extern int PKCS11_sign(int type, const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const PKCS11_KEY * key);
extern int PKCS11_private_encrypt(int flen, const unsigned char *from,
	unsigned char *to, const PKCS11_KEY * rsa, int padding);
/**
 * Decrypts data using the private key
 * 
 * @param  flen     length of the encrypted data
 * @param  from     encrypted data
 * @param  to       output buffer (MUST be a least flen bytes long)
 * @param  key      private key object 
 * @param  padding  padding algorithm to be used
 * @return the length of the decrypted data or 0 if an error occurred
 */
extern int PKCS11_private_decrypt(int flen, const unsigned char *from,
	unsigned char *to, PKCS11_KEY * key, int padding);
extern int PKCS11_verify(int type, const unsigned char *m, unsigned int m_len,
	unsigned char *signature, unsigned int siglen, PKCS11_KEY * key);

/* access random number generator */
extern int PKCS11_seed_random(PKCS11_SLOT *, const unsigned char *s, unsigned int s_len);
extern int PKCS11_generate_random(PKCS11_SLOT *, unsigned char *r, unsigned int r_len);

/* using with openssl method mechanism */
RSA_METHOD *PKCS11_get_rsa_method(void);

/**
 * Load PKCS11 error strings
 *
 * Call this function to be able to use ERR_reason_error_string(ERR_get_error())
 * to get an textual version of the latest error code
 */
extern void ERR_load_PKCS11_strings(void);

/*
 * Function and reason codes
 */
#define PKCS11_F_PKCS11_CTX_LOAD		1
#define PKCS11_F_PKCS11_ENUM_SLOTS		2
#define PKCS11_F_PKCS11_CHECK_TOKEN		3
#define PKCS11_F_PKCS11_OPEN_SESSION		4
#define PKCS11_F_PKCS11_LOGIN			5
#define PKCS11_F_PKCS11_ENUM_KEYS		6
#define PKCS11_F_PKCS11_GET_KEY			7
#define PKCS11_F_PKCS11_RSA_DECRYPT		8
#define PKCS11_F_PKCS11_RSA_ENCRYPT		9
#define PKCS11_F_PKCS11_RSA_SIGN		10
#define PKCS11_F_PKCS11_RSA_VERIFY		11
#define PKCS11_F_PKCS11_ENUM_CERTS		12
#define PKCS11_F_PKCS11_INIT_TOKEN		13
#define PKCS11_F_PKCS11_INIT_PIN		14
#define PKCS11_F_PKCS11_LOGOUT			15
#define PKCS11_F_PKCS11_STORE_PRIVATE_KEY	16
#define PKCS11_F_PKCS11_GENERATE_KEY		17
#define PKCS11_F_PKCS11_STORE_PUBLIC_KEY	18
#define PKCS11_F_PKCS11_STORE_CERTIFICATE	19
#define PKCS11_F_PKCS11_SEED_RANDOM		20
#define PKCS11_F_PKCS11_GENERATE_RANDOM		21
#define PKCS11_F_PKCS11_CHANGE_PIN		22
#define PKCS11_F_PKCS11_GETATTR			40

#define PKCS11_ERR_BASE				1024
#define PKCS11_LOAD_MODULE_ERROR		(PKCS11_ERR_BASE+1)
#define PKCS11_MODULE_LOADED_ERROR		(PKCS11_ERR_BASE+2)
#define PKCS11_SYMBOL_NOT_FOUND_ERROR		(PKCS11_ERR_BASE+3)
#define PKCS11_NOT_SUPPORTED			(PKCS11_ERR_BASE+4)
#define PKCS11_NO_SESSION			(PKCS11_ERR_BASE+5)
#define PKCS11_KEYGEN_FAILED			(PKCS11_ERR_BASE+6)

#ifdef __cplusplus
}
#endif
#endif
