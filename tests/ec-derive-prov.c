/*
 * Copyright © 2026 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * ECDH derive test for pkcs11 provider.
 *
 * The test loads an EC private key and public key from the PKCS#11 provider,
 * generates a temporary software EC key on the same group, and verifies that:
 * ECDH(token_private, software_public) == ECDH(software_private, token_public)
 */

#include "helpers_prov.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(OPENSSL_NO_EC)

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

static EVP_PKEY *public_key_copy(EVP_PKEY *key)
{
	EVP_PKEY *copy = NULL;
	unsigned char *der = NULL, *p = NULL;
	const unsigned char *q = NULL;
	int der_len;

	der_len = i2d_PUBKEY(key, NULL);
	if (der_len <= 0) {
		display_openssl_errors();
		goto end;
	}
	der = OPENSSL_malloc((size_t)der_len);
	if (der == NULL) {
		display_openssl_errors();
		goto end;
	}
	p = der;
	if (i2d_PUBKEY(key, &p) != der_len) {
		display_openssl_errors();
		goto end;
	}
	q = der;
	copy = d2i_PUBKEY(NULL, &q, der_len);
	if (copy == NULL)
		display_openssl_errors();

end:
	OPENSSL_free(der);
	return copy;
}

static EVP_PKEY *generate_software_ec_key(EVP_PKEY *template_key)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	char group_name[128];
	size_t group_name_len = 0;

	if (EVP_PKEY_get_utf8_string_param(template_key,
			OSSL_PKEY_PARAM_GROUP_NAME,
			group_name, sizeof(group_name),
			&group_name_len) != 1) {
		fprintf(stderr, "Cannot get EC group name from token public key\n");
		display_openssl_errors();
		goto end;
	}

	group_name[sizeof(group_name) - 1] = '\0';
	printf("Using EC group: %s\n", group_name);

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=default");
	if (ctx == NULL) {
		display_openssl_errors();
		goto end;
	}
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		display_openssl_errors();
		goto end;
	}
	if (EVP_PKEY_CTX_set_group_name(ctx, group_name) <= 0) {
		display_openssl_errors();
		goto end;
	}
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		display_openssl_errors();
		goto end;
	}

end:
	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

/* SoftHSM does not support ECDH cofactor derivation:
 * EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, 1) */
static int derive_secret(EVP_PKEY *priv, EVP_PKEY *peer,
	unsigned char **secret, size_t *secret_len)
{
	EVP_PKEY_CTX *ctx = NULL;
	int ret = 0;

	*secret = NULL;
	*secret_len = 0;

	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
	if (ctx == NULL) {
		display_openssl_errors();
		goto end;
	}
	if (EVP_PKEY_derive_init(ctx) <= 0) {
		display_openssl_errors();
		goto end;
	}
	/* Set up peer's public key */
	if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
		display_openssl_errors();
		goto end;
	}
	if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) {
		display_openssl_errors();
		goto end;
	}
	if (*secret_len == 0) {
		fprintf(stderr, "Derived secret has zero length\n");
		goto end;
	}
	*secret = OPENSSL_malloc(*secret_len);
	if (*secret == NULL){
		display_openssl_errors();
		goto end;
	}
	if (EVP_PKEY_derive(ctx, *secret, secret_len) <= 0) {
		display_openssl_errors();
		goto end;
	}
	ret = 1;

end:
	EVP_PKEY_CTX_free(ctx);
	if (!ret) {
		OPENSSL_free(*secret);
		*secret = NULL;
		*secret_len = 0;
	}
	return ret;
}

static void dump_digest(const char *label, const unsigned char *buf, size_t len)
{
	EVP_MD_CTX *ctx = NULL;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len = 0;
	unsigned int i;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return;

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
			EVP_DigestUpdate(ctx, buf, len) != 1 ||
			EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
		EVP_MD_CTX_free(ctx);
		return;
	}

	fprintf(stderr, "%s SHA256: ", label);
	for (i = 0; i < md_len; i++)
		fprintf(stderr, "%02x", md[i]);
	fprintf(stderr, "\n");

	EVP_MD_CTX_free(ctx);
}

int main(int argc, char **argv)
{
	EVP_PKEY *token_priv = NULL;
	EVP_PKEY *token_pub = NULL;
	EVP_PKEY *token_pub_sw = NULL;
	EVP_PKEY *peer_priv = NULL;
	EVP_PKEY *peer_pub = NULL;
	EVP_PKEY *token_peer_priv = NULL;
	EVP_PKEY *token_peer_pub = NULL;
	unsigned char *secret_token = NULL;
	unsigned char *secret_ref = NULL;
	unsigned char *secret_token_peer = NULL;
	unsigned char *secret_peer_token = NULL;
	size_t secret_token_len = 0;
	size_t secret_ref_len = 0;
	size_t secret_token_peer_len = 0;
	size_t secret_peer_token_len = 0;
	int ret = EXIT_FAILURE;

	if (argc != 5) {
		fprintf(stderr, "usage: %s [private key URL] [public key URL] "
			"[peer private key URL] [peer public key URL]\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (!providers_load()) {
		display_openssl_errors();
		goto cleanup;
	}

	token_priv = load_pkey(argv[1], "provider=pkcs11prov", NULL);
	if (token_priv == NULL) {
		fprintf(stderr, "cannot load private key: %s\n", argv[1]);
		display_openssl_errors();
		goto cleanup;
	}

	token_pub = load_pubkey(argv[2], "provider=pkcs11prov");
	if (token_pub == NULL) {
		fprintf(stderr, "cannot load public key: %s\n", argv[2]);
		display_openssl_errors();
		goto cleanup;
	}

	token_peer_priv = load_pkey(argv[3], "provider=pkcs11prov", NULL);
	if (token_peer_priv == NULL) {
		fprintf(stderr, "cannot load peer private key: %s\n", argv[3]);
		display_openssl_errors();
		goto cleanup;
	}

	token_peer_pub = load_pubkey(argv[4], "provider=pkcs11prov");
	if (token_peer_pub == NULL) {
		fprintf(stderr, "cannot load peer public key: %s\n", argv[4]);
		display_openssl_errors();
		goto cleanup;
	}

	token_pub_sw = public_key_copy(token_pub);
	if (token_pub_sw == NULL) {
		fprintf(stderr, "cannot create software copy of token public key\n");
		goto cleanup;
	}

	peer_priv = generate_software_ec_key(token_pub_sw);
	if (peer_priv == NULL) {
		fprintf(stderr, "cannot generate software EC peer key\n");
		goto cleanup;
	}

	peer_pub = public_key_copy(peer_priv);
	if (peer_pub == NULL) {
		fprintf(stderr, "cannot create software EC peer public key\n");
		goto cleanup;
	}

	printf("Deriving with token private key and software public key\n");
	if (!derive_secret(token_priv, peer_pub,
			&secret_token, &secret_token_len)) {
		fprintf(stderr, "token ECDH derive failed\n");
		goto cleanup;
	}

	printf("Deriving with software private key and token public key\n");
	if (!derive_secret(peer_priv, token_pub_sw,
			&secret_ref, &secret_ref_len)) {
		fprintf(stderr, "software reference ECDH derive failed\n");
		goto cleanup;
	}

	if (secret_token_len != secret_ref_len ||
			memcmp(secret_token, secret_ref, secret_token_len) != 0) {
		fprintf(stderr, "ECDH secrets differ\n");
		dump_digest("token", secret_token, secret_token_len);
		dump_digest("ref  ", secret_ref, secret_ref_len);
		goto cleanup;
	}

	printf("Deriving with token private key and token peer public key\n");
	if (!derive_secret(token_priv, token_peer_pub,
			&secret_token_peer, &secret_token_peer_len)) {
		fprintf(stderr, "token-to-token ECDH derive failed\n");
		goto cleanup;
	}

	printf("Deriving with token peer private key and software copy "
		"of token public key\n");
	if (!derive_secret(token_peer_priv, token_pub_sw,
			&secret_peer_token, &secret_peer_token_len)) {
		fprintf(stderr, "reverse token-to-token ECDH derive failed\n");
		goto cleanup;
	}

	if (secret_token_peer_len != secret_peer_token_len ||
			memcmp(secret_token_peer, secret_peer_token,
				secret_token_peer_len) != 0) {
		fprintf(stderr, "token-to-token ECDH secrets differ\n");
		dump_digest("token     ", secret_token_peer,
			secret_token_peer_len);
		dump_digest("token peer", secret_peer_token,
			secret_peer_token_len);
		goto cleanup;
	}

	printf("ECDH derive success\n");
	ret = EXIT_SUCCESS;

cleanup:
	OPENSSL_free(secret_token);
	OPENSSL_free(secret_ref);
	OPENSSL_free(secret_token_peer);
	OPENSSL_free(secret_peer_token);
	EVP_PKEY_free(token_priv);
	EVP_PKEY_free(token_pub);
	EVP_PKEY_free(token_pub_sw);
	EVP_PKEY_free(peer_priv);
	EVP_PKEY_free(peer_pub);
	EVP_PKEY_free(token_peer_priv);
	EVP_PKEY_free(token_peer_pub);
	providers_cleanup();

	return ret;
}

#else

int main(void)
{
	fprintf(stderr, "Skipped: requires OpenSSL >= 3.0 with EC support\n");
	return 77;
}

#endif

/* vim: set noexpandtab: */
