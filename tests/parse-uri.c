/*
 * Copyright (c) 2026 Jakub Jelen <jjelen@redhat.com>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

static void print_hex(const char *label, char *value, int length)
{
	char *hex = NULL;
	if (length == 0) {
		printf("%s=\n", label);
		return;
	}

	hex = dump_hex((unsigned char *)value, length);
	if (hex) {
		printf("%s=%s\n", label, hex);
		OPENSSL_free(hex);
	}
}

static void print_hex_str(const char *label, char *value)
{
	if (value != NULL) {
		print_hex(label, value, strlen(value));
	}
}

int main(int argc, char **argv)
{
	UTIL_CTX *ctx;
	PARSED parsed;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pkcs11-uri>\n", argv[0]);
		return 1;
	}

	ctx = UTIL_CTX_new(0);
	if (!ctx) {
		fprintf(stderr, "Failed to create UTIL_CTX\n");
		return 1;
	}

	memset(&parsed, 0, sizeof(parsed));
	if (!util_ctx_parse_uri(ctx, &parsed, "object", argv[1])) {
		fprintf(stderr, "Failed to parse URI: %s\n", argv[1]);
		util_parsed_free(&parsed);
		UTIL_CTX_free(ctx);
		return 1;
	}

	print_hex_str("library-description", parsed.library_description);
	print_hex_str("library-manufacturer", parsed.library_manufacturer);
	if (parsed.library_version)
		printf("library-version=%s\n", parsed.library_version);
	if (parsed.match_tok) {
		print_hex_str("token", parsed.match_tok->label);
		print_hex_str("manufacturer", parsed.match_tok->manufacturer);
		print_hex_str("serial", parsed.match_tok->serialnr);
		print_hex_str("model", parsed.match_tok->model);
	}
	print_hex_str("slot-description", parsed.slot_description);
	print_hex_str("slot-manufacturer", parsed.slot_manufacturer);
	if (parsed.slot_id != -1)
		printf("slot-id=%d\n", parsed.slot_id);
	print_hex_str("object", parsed.obj_label);
	if (parsed.type)
		printf("type=%s\n", parsed.type);
	if (parsed.obj_id)
		print_hex("id", parsed.obj_id, parsed.obj_id_len);
	if (parsed.pin_value)
		printf("pin-value=%s\n", parsed.pin_value);
	else if (parsed.pin)
		printf("pin-value=%s\n", parsed.pin);
	if (parsed.pin_source)
		printf("pin-source=%s\n", parsed.pin_source);
	if (parsed.module_name)
		printf("module-name=%s\n", parsed.module_name);
	if (parsed.module_path)
		printf("module-path=%s\n", parsed.module_path);

	util_parsed_free(&parsed);
	UTIL_CTX_free(ctx);
	return 0;
}
