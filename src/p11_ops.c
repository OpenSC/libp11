/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2005 Kevin Stefanik <kstef@mtppi.org>
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


/* this file does certain cryptographic operations via the pkcs11 library */

#include "libp11-int.h"
#include <string.h>
#include <openssl/ossl_typ.h>
#include <openssl/asn1.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100002L
/* initial code will only support what is needed for pkcs11_ec_ckey
 * i.e. CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE
 * and CK_EC_KDF_TYPE  supported by token
 * The secret key object is deleted
 *
 * In future CKM_ECMQV_DERIVE with CK_ECMQV_DERIVE_PARAMS
 * could also be supported, and the secret key object could be returned.
 */
int pkcs11_ecdh_derive_internal(unsigned char **out, size_t *outlen,
		const unsigned long ecdh_mechanism,
		const void * ec_params,
		void *outnewkey,
		PKCS11_KEY * key)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_TOKEN *token = KEY2TOKEN(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	int rv;
	int ret = -1;
	unsigned char * buf = NULL;
	size_t buflen;

	CK_BBOOL true = TRUE;
	CK_BBOOL false = FALSE;
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS newkey_class= CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_OBJECT_HANDLE * tmpnewkey = (CK_OBJECT_HANDLE *)outnewkey;
	CK_ATTRIBUTE newkey_template[] = {
		{CKA_TOKEN, &false, sizeof(false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_ENCRYPT, &true, sizeof(true)},
		{CKA_DECRYPT, &true, sizeof(true)}
	};

	CHECK_KEY_FORK(key);

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism  = ecdh_mechanism;
	mechanism.pParameter =  (void*)ec_params;
	switch (ecdh_mechanism) {
		case CKM_ECDH1_DERIVE:
		case CKM_ECDH1_COFACTOR_DERIVE:
			mechanism.ulParameterLen  = sizeof(CK_ECDH1_DERIVE_PARAMS);
			break;
//		case CK_ECMQV_DERIVE_PARAMS:
//			mechanism.ulParameterLen  = sizeof(CK_ECMQV_DERIVE_PARAMS);
//			break;
		default:
		    PKCS11err(PKCS11_F_PKCS11_EC_KEY_COMPUTE_KEY, PKCS11_NOT_SUPPORTED);
		    goto err;
	}

	rv = CRYPTOKI_call(ctx, C_DeriveKey(spriv->session, &mechanism, kpriv->object, newkey_template, 5, &newkey));
	if (rv) {
	    PKCS11err(PKCS11_F_PKCS11_EC_KEY_COMPUTE_KEY, pkcs11_map_err(rv));
	    goto err;
	}

	/* Return the value of the secret key and/or the object handle of the secret key */

	/* pkcs11_ec_ckey only asks for the value */

	if (out && outlen) {
		/* get size of secret key value */
		if (!pkcs11_getattr_var(token, newkey, CKA_VALUE, NULL, &buflen)
			&& buflen > 0) {
			buf = OPENSSL_malloc(buflen);
			if (buf == NULL) {
				PKCS11err(PKCS11_F_PKCS11_EC_KEY_COMPUTE_KEY,
					pkcs11_map_err(CKR_HOST_MEMORY));
				goto err;
			}
		} else {
			PKCS11err(PKCS11_F_PKCS11_EC_KEY_COMPUTE_KEY,
				pkcs11_map_err(CKR_ATTRIBUTE_VALUE_INVALID));
			goto err;
		}

		pkcs11_getattr_var(token, newkey, CKA_VALUE, buf, &buflen);
		*out = buf;
		*outlen = buflen;
		buf = NULL;
	}

	/* not used by pkcs11_ec_ckey for future use */
	if (tmpnewkey) {
	    *tmpnewkey = newkey;
	    newkey = CK_INVALID_HANDLE;
	}

	ret = 1;
err:
	if (buf)
	    OPENSSL_free(buf);
	if (newkey != CK_INVALID_HANDLE && spriv->session != CK_INVALID_HANDLE)
		CRYPTOKI_call(ctx, C_DestroyObject(spriv->session, newkey));

	return ret;
}
#endif

/* Signature size is the issue, will assume the caller has a big buffer! */
/* No padding or other stuff needed.  We can call PKCS11 from here */
int
PKCS11_ecdsa_sign(const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY * key)
{
	int rv;
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	CK_ULONG ck_sigsize;

	CHECK_KEY_FORK(key);

	ck_sigsize = *siglen;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_ECDSA;

	pkcs11_w_lock(PRIVSLOT(slot)->lockid);
	rv = CRYPTOKI_call(ctx, C_SignInit(spriv->session, &mechanism, kpriv->object)) ||
		CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE *) m, m_len, sigret, &ck_sigsize));
	pkcs11_w_unlock(PRIVSLOT(slot)->lockid);

	if (rv) {
		PKCS11err(PKCS11_F_PKCS11_EC_KEY_SIGN, pkcs11_map_err(rv));
		return -1;
	}
	*siglen = ck_sigsize;

	return ck_sigsize;
}

/* Following used for RSA */
int
PKCS11_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY * key)
{
	int rv, ssl = ((type == NID_md5_sha1) ? 1 : 0);
	unsigned char *encoded = NULL;
	int sigsize;

	CHECK_KEY_FORK(key);

	sigsize = PKCS11_get_key_size(key);

	if (ssl) {
		if ((m_len != 36) /* SHA1 + MD5 */ ||
				((m_len + RSA_PKCS1_PADDING_SIZE) > (unsigned)sigsize)) {
			return 0; /* the size is wrong */
		}
	} else {
		ASN1_TYPE parameter = { V_ASN1_NULL, { NULL } };
 		ASN1_STRING digest = { m_len, V_ASN1_OCTET_STRING, (unsigned char *)m, 0 };
		X509_ALGOR algor = { NULL, &parameter };
		X509_SIG digest_info = { &algor, &digest };
		int size;
		/* Fetch the OID of the algorithm used */
		if ((algor.algorithm = OBJ_nid2obj(type)) &&
				(algor.algorithm) &&
				/* Get the size of the encoded DigestInfo */
				(size = i2d_X509_SIG(&digest_info, NULL)) &&
				/* Check that size is compatible with PKCS#11 padding */
				(size + RSA_PKCS1_PADDING_SIZE <= sigsize) &&
				(encoded = OPENSSL_malloc(sigsize))) {
			unsigned char *tmp = encoded;
			/* Actually do the encoding */
			i2d_X509_SIG(&digest_info,&tmp);
			m = encoded;
			m_len = size;
		} else {
			return 0;
		}
	}

	rv = PKCS11_private_encrypt(m_len, m, sigret, key, RSA_PKCS1_PADDING);

	if (rv <= 0)
		rv = 0;
	else {
		*siglen = rv;
		rv = 1;
	}

	if (encoded != NULL)  /* NULL on SSL case */
		OPENSSL_free(encoded);

	return rv;
}

int
PKCS11_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY * key, int padding)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	int rv;
	int sigsize;
	CK_ULONG ck_sigsize;

	sigsize = PKCS11_get_key_size(key);
	ck_sigsize = sigsize;

	memset(&mechanism, 0, sizeof(mechanism));

	switch (padding) {
		case RSA_NO_PADDING:
			mechanism.mechanism = CKM_RSA_X_509;
			break;
		case RSA_PKCS1_PADDING:
			if ((flen + RSA_PKCS1_PADDING_SIZE) > sigsize) {
				return -1; /* the size is wrong */
			}
			mechanism.mechanism = CKM_RSA_PKCS;
			break;
		default:
			printf("pkcs11 engine: only RSA_NO_PADDING or RSA_PKCS1_PADDING allowed so far\n");
			return -1;
	}

	CHECK_KEY_FORK(key);

	pkcs11_w_lock(PRIVSLOT(slot)->lockid);
	/* API is somewhat fishy here. *siglen is 0 on entry (cleared
	 * by OpenSSL). The library assumes that the memory passed
	 * by the caller is always big enough */
	rv = CRYPTOKI_call(ctx, C_SignInit(spriv->session, &mechanism, kpriv->object)) ||
		CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE *) from, flen, to, &ck_sigsize));
	pkcs11_w_unlock(PRIVSLOT(slot)->lockid);

	if (rv) {
		PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, pkcs11_map_err(rv));
		return -1;
	}

	if ((unsigned)sigsize != ck_sigsize)
		return -1;

	return sigsize;
}

int
PKCS11_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY * key, int padding)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	CK_ULONG size = flen;
	CK_RV rv;

	if (padding != RSA_PKCS1_PADDING) {
			printf("pkcs11 engine: only RSA_PKCS1_PADDING allowed so far\n");
			return -1;
	}

	CHECK_KEY_FORK(key);

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_RSA_PKCS;

	pkcs11_w_lock(PRIVSLOT(slot)->lockid);
	rv = CRYPTOKI_call(ctx, C_DecryptInit(spriv->session, &mechanism, kpriv->object)) ||
		CRYPTOKI_call(ctx,
			C_Decrypt(spriv->session, (CK_BYTE *) from, (CK_ULONG)flen,
				(CK_BYTE_PTR)to, &size));
	pkcs11_w_unlock(PRIVSLOT(slot)->lockid);

	if (rv)
		PKCS11err(PKCS11_F_PKCS11_RSA_DECRYPT, pkcs11_map_err(rv));

	return rv ? 0 : size;
}

int
PKCS11_verify(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *signature, unsigned int siglen, PKCS11_KEY * key)
{
	(void)type;
	(void)m;
	(void)m_len;
	(void)signature;
	(void)siglen;
	(void)key;

	/* PKCS11 calls go here */
	PKCS11err(PKCS11_F_PKCS11_RSA_VERIFY, PKCS11_NOT_SUPPORTED);
	return -1;
}

/* vim: set noexpandtab: */
