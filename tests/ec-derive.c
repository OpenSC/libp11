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
 * ECDH derive test for engine pkcs11.
 *
 * The test loads an EC private key and public key from the PKCS#11 engine,
 * generates a temporary software EC key on the same group, and verifies that:
 * ECDH(token_private, software_public) == ECDH(software_private, token_public)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* this code intentionally uses deprecated ENGINE/EC APIs */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/opensslv.h>

#if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_EC)

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static void display_openssl_errors(int l)
{
	const char *file;
	char buf[120];
	unsigned long e;
	int line;

	if (ERR_peek_error() == 0)
		return;

	fprintf(stderr, "At ec-derive.c:%d:\n", l);
	while ((e = ERR_get_error_line(&file, &line)) != 0) {
		ERR_error_string_n(e, buf, sizeof(buf));
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

static EVP_PKEY *public_key_copy(EVP_PKEY *key)
{
	EVP_PKEY *copy = NULL;
	unsigned char *der = NULL, *p = NULL;
	const unsigned char *q = NULL;
	int der_len;

	der_len = i2d_PUBKEY(key, NULL);
	if (der_len <= 0) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	der = OPENSSL_malloc((size_t)der_len);
	if (der == NULL) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	p = der;
	if (i2d_PUBKEY(key, &p) != der_len) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	q = der;
	copy = d2i_PUBKEY(NULL, &q, der_len);
	if (copy == NULL)
		display_openssl_errors(__LINE__);

end:
	OPENSSL_free(der);
	return copy;
}

static EVP_PKEY *generate_software_ec_key(EVP_PKEY *template_key)
{
	EVP_PKEY *pkey = NULL;
	EC_KEY *template_ec = NULL;
	EC_KEY *ec = NULL;
	const EC_GROUP *group;
	int nid;

	template_ec = EVP_PKEY_get1_EC_KEY(template_key);
	if (template_ec == NULL) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	group = EC_KEY_get0_group(template_ec);
	if (group == NULL) {
		fprintf(stderr, "Token public key has no EC group\n");
		goto end;
	}
	nid = EC_GROUP_get_curve_name(group);
	if (nid != NID_undef)
		printf("Using EC group: %s\n", OBJ_nid2sn(nid));
	else
		printf("Using EC group with explicit parameters\n");

	ec = EC_KEY_new();
	if (ec == NULL) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	if (EC_KEY_set_group(ec, group) != 1) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	if (EC_KEY_generate_key(ec) != 1) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
		display_openssl_errors(__LINE__);
		EVP_PKEY_free(pkey);
		pkey = NULL;
		goto end;
	}
	/* pkey owns ec now */
	ec = NULL;

end:
	EC_KEY_free(template_ec);
	EC_KEY_free(ec);
	return pkey;
}

static int derive_secret(EVP_PKEY *priv, EVP_PKEY *peer, ENGINE *engine,
		unsigned char **secret, size_t *secret_len)
{
	EVP_PKEY_CTX *ctx = NULL;
	int ret = 0;

	*secret = NULL;
	*secret_len = 0;

	ctx = EVP_PKEY_CTX_new(priv, engine);
	if (ctx == NULL) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	if (EVP_PKEY_derive_init(ctx) <= 0) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	/* Set up peer's public key */
	if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) {
		display_openssl_errors(__LINE__);
		goto end;
	}
	if (*secret_len == 0) {
		fprintf(stderr, "Derived secret has zero length\n");
		goto end;
	}
	*secret = OPENSSL_malloc(*secret_len);
	if (*secret == NULL){
		display_openssl_errors(__LINE__);
		goto end;
	}
	if (EVP_PKEY_derive(ctx, *secret, secret_len) <= 0) {
		display_openssl_errors(__LINE__);
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

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
		return;

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
		EVP_DigestUpdate(ctx, buf, len) != 1 ||
		EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
		EVP_MD_CTX_destroy(ctx);
		return;
	}

	fprintf(stderr, "%s SHA256: ", label);
	for (i = 0; i < md_len; i++)
		fprintf(stderr, "%02x", md[i]);
	fprintf(stderr, "\n");

	EVP_MD_CTX_destroy(ctx);
}

int main(int argc, char **argv)
{
	ENGINE *engine = NULL;
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
	const char *module_path;
	int ret = EXIT_FAILURE;
	int engine_initialized = 0;
	int engine_structural_freed = 0;
	int res;

	if (argc != 7) {
		fprintf(stderr,
			"usage: %s [CONF] [private key URL] [public key URL] "
			"[peer private key URL] [peer public key URL] [module]\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	module_path = argv[6];

	res = CONF_modules_load_file(argv[1], "engines", 0);
	if (res <= 0) {
		fprintf(stderr, "cannot load %s\n", argv[1]);
		display_openssl_errors(__LINE__);
		goto cleanup;
	}

	ENGINE_add_conf_module();

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
		OPENSSL_INIT_ADD_ALL_DIGESTS |
		OPENSSL_INIT_LOAD_CONFIG, NULL);
#else
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
#endif

	ERR_clear_error();
	ENGINE_load_builtin_engines();

	engine = ENGINE_by_id("pkcs11");
	if (engine == NULL) {
		fprintf(stderr, "Could not get pkcs11 engine\n");
		display_openssl_errors(__LINE__);
		goto cleanup;
	}
	if (!ENGINE_ctrl_cmd_string(engine, "DEBUG_LEVEL", "7", 0)) {
		display_openssl_errors(__LINE__);
		goto cleanup;
	}
	if (module_path != NULL && module_path[0] != '\0') {
		if (!ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", module_path, 0)) {
			display_openssl_errors(__LINE__);
			goto cleanup;
		}
	}
	if (!ENGINE_init(engine)) {
		fprintf(stderr, "Could not initialize pkcs11 engine\n");
		display_openssl_errors(__LINE__);
		goto cleanup;
	}
	/* ENGINE_init() returned a functional reference; drop structural ref. */
	engine_initialized = 1;
	ENGINE_free(engine);
	engine_structural_freed = 1;

	token_priv = ENGINE_load_private_key(engine, argv[2], NULL, NULL);
	if (token_priv == NULL) {
		fprintf(stderr, "cannot load private key: %s\n", argv[2]);
		display_openssl_errors(__LINE__);
		goto cleanup;
	}

	token_pub = ENGINE_load_public_key(engine, argv[3], NULL, NULL);
	if (token_pub == NULL) {
		fprintf(stderr, "cannot load public key: %s\n",  argv[3]);
		display_openssl_errors(__LINE__);
		goto cleanup;
	}

	token_peer_priv = ENGINE_load_private_key(engine, argv[4], NULL, NULL);
	if (token_peer_priv == NULL) {
		fprintf(stderr, "cannot load peer private key: %s\n", argv[4]);
		display_openssl_errors(__LINE__);
		goto cleanup;
	}

	token_peer_pub = ENGINE_load_public_key(engine, argv[5], NULL, NULL);
	if (token_peer_pub == NULL) {
		fprintf(stderr, "cannot load peer public key: %s\n", argv[5]);
		display_openssl_errors(__LINE__);
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
	if (!derive_secret(token_priv, peer_pub, engine,
			&secret_token, &secret_token_len)) {
		fprintf(stderr, "token ECDH derive failed\n");
		goto cleanup;
	}

	printf("Deriving with software private key and token public key\n");
	if (!derive_secret(peer_priv, token_pub_sw, NULL,
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
	if (!derive_secret(token_priv, token_peer_pub, engine,
			&secret_token_peer, &secret_token_peer_len)) {
		fprintf(stderr, "token-to-token ECDH derive failed\n");
		goto cleanup;
	}

	printf("Deriving with token peer private key and software copy "
		"of token public key\n");
	if (!derive_secret(token_peer_priv, token_pub_sw, engine,
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

	if (engine != NULL) {
		if (engine_initialized)
			ENGINE_finish(engine);
		if (!engine_structural_freed)
			ENGINE_free(engine);
	}
	CONF_modules_unload(1);
	return ret;
}

#else /* !OPENSSL_NO_ENGINE && !OPENSSL_NO_EC */

int main(void)
{
	fprintf(stderr, "Skipped: requires OpenSSL with ENGINE and EC support\n");
	return 77;
}

#endif /* !OPENSSL_NO_ENGINE && !OPENSSL_NO_EC */

/* vim: set noexpandtab: */
