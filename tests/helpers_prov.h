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

/* Common functions */

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/provider.h>
#include <openssl/ui.h>

void display_openssl_errors(void);
EVP_PKEY *load_pkey(const char *uri, const UI_METHOD *ui_method);
EVP_PKEY *load_pubkey(const char *uri);
X509 *load_cert(const char *uri);
void provider_free(OSSL_PROVIDER *prov);
void providers_cleanup(void);
int provider_load(const char *pname);
int providers_load(void);

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* vim: set noexpandtab: */
