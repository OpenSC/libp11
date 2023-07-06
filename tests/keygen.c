 /*
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
 */

#include <libp11.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <string.h>

static void
usage(char* argv[])
{
	fprintf(stderr,
		"%s token_label key_label [module]\n",
		argv[0]);
}

static void
display_openssl_errors(int l)
{
	const char* file;
	char buf[120];
	int e, line;

	if (ERR_peek_error() == 0)
		return;
	fprintf(stderr, "At main.c:%d:\n", l);

	while ((e = ERR_get_error_line(&file, &line))) {
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

static int sign_verify_test(EVP_PKEY *priv, EVP_PKEY *pub) {
	EVP_MD_CTX *mdctx = NULL;
	int retval = 0;
	char *msg = "libp11";
	size_t slen;
	unsigned char *sig = NULL;

	if (!priv || !pub) {
		fprintf(stderr, "Where are the keys?\n");
		return -1;
	}
	if(!(mdctx = EVP_MD_CTX_create())) {
		display_openssl_errors(__LINE__);
		retval = -2;
		goto err;
	}
	if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, priv)) {
		display_openssl_errors(__LINE__);
		retval = -3;
		goto err;
	}
	if(1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg))) {
		display_openssl_errors(__LINE__);
		retval = -4;
		goto err;
	}
	if(1 != EVP_DigestSignFinal(mdctx, NULL, &slen)) {
		display_openssl_errors(__LINE__);
		retval = -5;
		goto err;
	}
	if(!(sig = OPENSSL_malloc(sizeof(unsigned char) * (slen)))) {
		display_openssl_errors(__LINE__);
		retval = -6;
		goto err;
	}
	if(1 != EVP_DigestSignFinal(mdctx, sig, &slen)) {
		display_openssl_errors(__LINE__);
		retval = -7;
		fprintf(stderr, "Sign fail\n");
		goto err;
	}
	printf("Sign success\n");

	if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub)) {
		display_openssl_errors(__LINE__);
		retval = -8;
		goto err;
	}
	if(1 != EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg))) {
		display_openssl_errors(__LINE__);
		retval = -9;
		goto err;
	}
	if(1 == EVP_DigestVerifyFinal(mdctx, sig, slen))
	{
		printf("Verify success\n");
		retval = 0;
	}
	else
	{
		display_openssl_errors(__LINE__);
		fprintf(stderr, "Verify fail\n");
		retval = -10;
		goto err;
	}

err:
	if(sig) OPENSSL_free(sig);
	if(mdctx) EVP_MD_CTX_destroy(mdctx);
	return retval;
}

int
main(int argc, char* argv[])
{
	int ret = 0;
	ENGINE* engine = NULL;
	char *module = argv[3];

	if (argc < 3) {
		fprintf(stderr, "Too few arguments\n");
		usage(argv);
		return 1;
	}

	ENGINE_load_builtin_engines();
	engine = ENGINE_by_id("pkcs11");
	if (engine == NULL) {
		fprintf(stderr, "Could not get engine\n");
		display_openssl_errors(__LINE__);
		exit(1);
	}
	if (!ENGINE_ctrl_cmd_string(engine, "PIN", "1234", 0)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}
	if (!ENGINE_ctrl_cmd_string(engine, "VERBOSE", NULL, 0)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}
	if (module) {
		if (!ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", module, 0)) {
			display_openssl_errors(__LINE__);
			exit(1);
		}
	}
	if (!ENGINE_init(engine)) {
		fprintf(stderr, "Could not initialize engine\n");
		display_openssl_errors(__LINE__);
		exit(1);
	}

	PKCS11_EC_KGEN ec = {
		.curve = "P-256"
	};
	PKCS11_KGEN_ATTRS eckg =
	{
		.type = EVP_PKEY_EC,
		.kgen.ec = &ec,
		.token_label = argv[1],
		.key_label = argv[2],
		.key_id = "1234",
	};

	if (!ENGINE_ctrl_cmd(engine, "KEYGEN", 0, &eckg, NULL, 1)) {
		fprintf(stderr, "Could not generate ECC keys\n");
		exit(1);
	}

	EVP_PKEY *ecpb = ENGINE_load_public_key(engine, "1234", NULL, NULL);
	EVP_PKEY *ecpr = ENGINE_load_private_key(engine, "1234", NULL, NULL);
	if ((ret = sign_verify_test(ecpr, ecpb)) < 0) {
		fprintf(stderr, "ECC Sign-verify failed with err code: %d\n", ret);
		exit(1);
	}
	PKCS11_RSA_KGEN rsa = {
		.bits = 2048
	};
	PKCS11_KGEN_ATTRS rsakg = {
		.type = EVP_PKEY_RSA,
		.kgen.rsa = &rsa,
		.token_label = argv[1],
		.key_label = argv[2],
		.key_id = "4321",
	};
	if (!ENGINE_ctrl_cmd(engine, "KEYGEN", 0, &rsakg, NULL, 1)) {
		fprintf(stderr, "Could not generate RSA keys\n");
		exit(1);
	}
	EVP_PKEY *rsapb = ENGINE_load_public_key(engine, "4321", NULL, NULL);
	EVP_PKEY *rsapr = ENGINE_load_private_key(engine, "4321", NULL, NULL);
	if ((ret = sign_verify_test(rsapr, rsapb)) < 0) {
		fprintf(stderr, "RSA Sign-verify failed with err code: %d\n", ret);
		exit(1);
	}

	ENGINE_finish(engine);
	return ret;
}
