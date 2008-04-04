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

#include <config.h>
#include <string.h>
#include "libp11-int.h"

int
PKCS11_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, const PKCS11_KEY * key)
{

	PKCS11_KEY_private *priv;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	int rv, ssl = ((type == NID_md5_sha1) ? 1 : 0);
	unsigned char *encoded = NULL;
	int sigsize;
	CK_ULONG ck_sigsize;

	if (key == NULL)
		return 0;
	ctx = KEY2CTX(key);
	priv = PRIVKEY(key);
	slot = TOKEN2SLOT(priv->parent);
	session = PRIVSLOT(slot)->session;
	
	sigsize=PKCS11_get_key_size(key);
	ck_sigsize=sigsize;

	if (ssl) {
		if((m_len != 36) /* SHA1 + MD5 */ ||
		   ((m_len + RSA_PKCS1_PADDING_SIZE) > sigsize)) {
			return(0); /* the size is wrong */
		}
	} else {
		ASN1_TYPE parameter = { V_ASN1_NULL, { NULL } };
 		ASN1_STRING digest = { m_len, V_ASN1_OCTET_STRING, (unsigned char *)m };
		X509_ALGOR algor = { NULL, &parameter };
		X509_SIG digest_info = { &algor, &digest };
		int size;
		/* Fetch the OID of the algorithm used */
		if((algor.algorithm = OBJ_nid2obj(type)) && 
		   (algor.algorithm->length) &&
		   /* Get the size of the encoded DigestInfo */
		   (size = i2d_X509_SIG(&digest_info, NULL)) &&
		   /* Check that size is compatible with PKCS#11 padding */
		   (size + RSA_PKCS1_PADDING_SIZE <= sigsize) &&
		   (encoded = (unsigned char *) malloc(sigsize))) {
			unsigned char *tmp = encoded;
			/* Actually do the encoding */
			i2d_X509_SIG(&digest_info,&tmp);
			m = encoded;
			m_len = size;
		} else {
			return(0);
		}
	}

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_RSA_PKCS;

	/* API is somewhat fishy here. *siglen is 0 on entry (cleared
	 * by OpenSSL). The library assumes that the memory passed
	 * by the caller is always big enough */
	if((rv = CRYPTOKI_call(ctx, C_SignInit
			       (session, &mechanism, priv->object))) == 0) {
		rv = CRYPTOKI_call(ctx, C_Sign
				   (session, (CK_BYTE *) m, m_len,
				    sigret, &ck_sigsize));
	}
	*siglen = ck_sigsize;
	if (encoded != NULL)  /* NULL on SSL case */
		free(encoded);

	if (rv) {
		PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, pkcs11_map_err(rv));
	}
	return (rv) ? 0 : 1;
}


int
PKCS11_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
		   const PKCS11_KEY * rsa, int padding)
{
	/* PKCS11 calls go here */
	PKCS11err(PKCS11_F_PKCS11_RSA_ENCRYPT, PKCS11_NOT_SUPPORTED);
	return -1;
}

int
PKCS11_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
		   PKCS11_KEY * key, int padding)
{
	CK_RV rv;
	PKCS11_KEY_private *priv;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_ULONG size = flen;
								
	if (padding != RSA_PKCS1_PADDING) {
			printf("pkcs11 engine: only RSA_PKCS1_PADDING allowed so far\n");
			return -1;
	}
	if (key == NULL)
			return -1;

	/* PKCS11 calls go here */
										
	ctx = KEY2CTX(key);
	priv = PRIVKEY(key);
	slot = TOKEN2SLOT(priv->parent);
	session = PRIVSLOT(slot)->session;
	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_RSA_PKCS;

	if( (rv = CRYPTOKI_call(ctx, C_DecryptInit(session, &mechanism, priv->object))) == 0) {
		rv = CRYPTOKI_call(ctx, C_Decrypt
			   (session, (CK_BYTE *) from, (CK_ULONG)flen,
	   		    (CK_BYTE_PTR)to, &size));
	}

	if (rv) {
		PKCS11err(PKCS11_F_PKCS11_RSA_DECRYPT, pkcs11_map_err(rv));
	}

	return (rv) ? 0 : size;
}

int
PKCS11_verify(int type, const unsigned char *m, unsigned int m_len,
		  unsigned char *signature, unsigned int siglen, PKCS11_KEY * key)
{

	/* PKCS11 calls go here */
	PKCS11err(PKCS11_F_PKCS11_RSA_VERIFY, PKCS11_NOT_SUPPORTED);
	return -1;
}

