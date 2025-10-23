/*
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * PKCS#11 provider tests support library
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Ed25519/ED448 common functions */

#include "eddsa_common.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

int EVP_Digest_sign_verify_test(EVP_PKEY *priv, EVP_PKEY *pub)
{
	EVP_MD_CTX *mdctx = NULL;
	int retval = 0;
	const unsigned char msg[] = "libp11";
	size_t siglen, msglen = sizeof(msg) - 1;
	unsigned char *sig = NULL;

	if (!priv || !pub) {
		printf("Where are the keys?\n");
		return -1;
	}

	/* --- Sign --- */
	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		retval = -2;
		goto err;
	}
	/* initialize the sign context using an Ed25519/Ed448 private key,
	 * notice that the digest name must NOT be used */
	if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, priv) != 1) {
		retval = -3;
		goto err;
	}
	/* calculate the required size for the signature by passing a NULL buffer */
	if (EVP_DigestSign(mdctx, NULL, &siglen, msg, msglen) != 1) {
		retval = -4;
		goto err;
	}
	sig = OPENSSL_malloc(siglen);
	if (!sig) {
		retval = -5;
		goto err;
	}
	/* generate the signature */
	if (EVP_DigestSign(mdctx, sig, &siglen, msg, msglen) != 1) {
		retval = -6;
		goto err;
	}
	EVP_MD_CTX_destroy(mdctx);

	/* --- Verify --- */
	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		retval = -7;
		goto err;
	}
	/* initialize the verify context with a Ed25519/Ed448 public key */
	if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pub) != 1) {
		retval = -8;
		goto err;
	}
	/* Ed25519/Ed448 only supports the one shot interface using EVP_DigestVerify(),
	 * the streaming EVP_DigestVerifyUpdate() API is not supported */
	if (EVP_DigestVerify(mdctx, sig, siglen, msg, msglen) == 1) {
		retval = 0;
		goto err;
	} else {
		retval = -9;
		goto err;
	}

err:
	if (sig)
		OPENSSL_free(sig);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	return retval;
}

int EVP_PKEY_sign_verify_test(EVP_PKEY *priv, EVP_PKEY *pub)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_MD_CTX *mdctx = NULL;
	int retval = 0;
	const unsigned char msg[] = "libp11";
	size_t siglen, msglen = sizeof(msg) - 1;
	unsigned char *sig = NULL;

	if (!priv || !pub) {
		printf("Where are the keys?\n");
		return -1;
	}

	/* --- Sign --- */
	siglen = (size_t)EVP_PKEY_get_size(priv);
	sig = OPENSSL_malloc(siglen);
	if (!sig) {
		return -2;
	}
	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
	if (!ctx) {
		retval = -3;
		goto err;
	}
	if (EVP_PKEY_sign_init(ctx) <= 0) {
		retval = -4;
		goto err;
	}
	if (EVP_PKEY_sign(ctx, sig, &siglen, msg, msglen) <= 0) {
		retval = -5;
		goto err;
	}

	/* --- Verify ---
	 * Ed25519 and Ed448 do not implement verify_init/verify in EVP_PKEY_METHOD.
	 * These algorithms support only one-shot signing and verification operations.
	 * See also: EVP_SIGNATURE-ED25519 and EVP_SIGNATURE-ED448.
	 */
	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		retval = -6;
		goto err;
	}
	/* initialize the verify context with a Ed25519/Ed448 public key */
	if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pub) != 1) {
		retval = -7;
		goto err;
	}
	/* Ed25519/Ed448 only supports the one shot interface using EVP_DigestVerify(),
	 * the streaming EVP_DigestVerifyUpdate() API is not supported */
	if (EVP_DigestVerify(mdctx, sig, siglen, msg, msglen) == 1) {
		retval = 0;
		goto err;
	} else {
		retval = -8;
		goto err;
	}

err:
	if (sig)
		OPENSSL_free(sig);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	return retval;
}

#else

/* Disable ISO C forbids an empty translation unit [-Wpedantic] warning */
extern int make_iso_compilers_happy;

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* vim: set noexpandtab: */
