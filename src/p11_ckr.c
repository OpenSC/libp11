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

#include "libp11.h"
#include "libp11-int.h"

#define CKR_LIB_NAME "PKCS#11 module"

/* BEGIN ERROR CODES */
#ifndef NO_ERR

# define ERR_FUNC(func) ERR_PACK(0,func,0)
# define ERR_REASON(reason) ERR_PACK(0,0,reason)

static ERR_STRING_DATA CKR_str_functs[] = {
	{ERR_FUNC(CKR_F_PKCS11_CHANGE_PIN), "pkcs11_change_pin"},
	{ERR_FUNC(CKR_F_PKCS11_CHECK_TOKEN), "pkcs11_check_token"},
	{ERR_FUNC(CKR_F_PKCS11_CTX_LOAD), "pkcs11_CTX_load"},
	{ERR_FUNC(CKR_F_PKCS11_ECDH_DERIVE), "pkcs11_ecdh_derive"},
	{ERR_FUNC(CKR_F_PKCS11_ECDSA_SIGN), "pkcs11_ecdsa_sign"},
	{ERR_FUNC(CKR_F_PKCS11_ENUMERATE_SLOTS), "pkcs11_enumerate_slots"},
	{ERR_FUNC(CKR_F_PKCS11_FIND_CERTS), "pkcs11_find_certs"},
	{ERR_FUNC(CKR_F_PKCS11_FIND_KEYS), "pkcs11_find_keys"},
	{ERR_FUNC(CKR_F_PKCS11_GENERATE_RANDOM), "pkcs11_generate_random"},
	{ERR_FUNC(CKR_F_PKCS11_GETATTR_ALLOC), "pkcs11_getattr_alloc"},
	{ERR_FUNC(CKR_F_PKCS11_GETATTR_BN), "pkcs11_getattr_bn"},
	{ERR_FUNC(CKR_F_PKCS11_GETATTR_INT), "pkcs11_getattr_int"},
	{ERR_FUNC(CKR_F_PKCS11_INIT_PIN), "pkcs11_init_pin"},
	{ERR_FUNC(CKR_F_PKCS11_INIT_SLOT), "pkcs11_init_slot"},
	{ERR_FUNC(CKR_F_PKCS11_INIT_TOKEN), "pkcs11_init_token"},
	{ERR_FUNC(CKR_F_PKCS11_IS_LOGGED_IN), "pkcs11_is_logged_in"},
	{ERR_FUNC(CKR_F_PKCS11_LOGIN), "pkcs11_login"},
	{ERR_FUNC(CKR_F_PKCS11_LOGOUT), "pkcs11_logout"},
	{ERR_FUNC(CKR_F_PKCS11_NEXT_CERT), "pkcs11_next_cert"},
	{ERR_FUNC(CKR_F_PKCS11_NEXT_KEY), "pkcs11_next_key"},
	{ERR_FUNC(CKR_F_PKCS11_OPEN_SESSION), "pkcs11_open_session"},
	{ERR_FUNC(CKR_F_PKCS11_PRIVATE_DECRYPT), "pkcs11_private_decrypt"},
	{ERR_FUNC(CKR_F_PKCS11_PRIVATE_ENCRYPT), "pkcs11_private_encrypt"},
	{ERR_FUNC(CKR_F_PKCS11_RELOAD_KEY), "pkcs11_reload_key"},
	{ERR_FUNC(CKR_F_PKCS11_SEED_RANDOM), "pkcs11_seed_random"},
	{ERR_FUNC(CKR_F_PKCS11_STORE_CERTIFICATE), "pkcs11_store_certificate"},
	{ERR_FUNC(CKR_F_PKCS11_STORE_KEY), "pkcs11_store_key"},
	{ERR_FUNC(CKR_F_PKCS11_RELOAD_CERTIFICATE), "pkcs11_reload_certificate"},
	{ERR_FUNC(CKR_F_PKCS11_GET_SESSION), "pkcs11_get_session"},
	{ERR_FUNC(CKR_F_PKCS11_ENUMERATE_MECHANISMS), "pkcs11_enumerate_mechanisms"},
	{ERR_FUNC(CKR_F_PKCS11_DIGEST), "pkcs11_digest"},
	{ERR_FUNC(CKR_F_PKCS11_DIGEST_INIT), "pkcs11_digest_init"},
	{ERR_FUNC(CKR_F_PKCS11_DIGEST_ABORT), "pkcs11_digest_abort"},
	{ERR_FUNC(CKR_F_PKCS11_DIGEST_UPDATE), "pkcs11_digest_update"},
	{ERR_FUNC(CKR_F_PKCS11_DIGEST_FINAL), "pkcs11_digest_final"},
	{ERR_FUNC(CKR_F_PKCS11_CREATE_CIPHER_KEY_OBJECT), "pkcs11_create_cipher_key_object"},
	{ERR_FUNC(CKR_F_PKCS11_DESTROY_CIPHER_KEY_OBJECT), "pkcs11_destroy_cipher_key_object"},
	{ERR_FUNC(CKR_F_PKCS11_DECRYPT_INIT), "pkcs11_decrypt_init"},
	{ERR_FUNC(CKR_F_PKCS11_DECRYPT_UPDATE), "pkcs11_decrypt_update"},
	{ERR_FUNC(CKR_F_PKCS11_DECRYPT_FINAL), "pkcs11_decrypt_final"},
	{ERR_FUNC(CKR_F_PKCS11_ENCRYPT_INIT), "pkcs11_encrypt_init"},
	{ERR_FUNC(CKR_F_PKCS11_ENCRYPT_UPDATE), "pkcs11_encrypt_update"},
	{ERR_FUNC(CKR_F_PKCS11_ENCRYPT_FINAL), "pkcs11_encrypt_final"},
	{ERR_FUNC(CKR_F_PKCS11_CTX_RELOAD), ""},
	{0, NULL}
};

static ERR_STRING_DATA CKR_str_reasons[] = {
	{ERR_REASON(CKR_CANCEL), "Cancel"},
	{ERR_REASON(CKR_HOST_MEMORY), "Host memory error"},
	{ERR_REASON(CKR_SLOT_ID_INVALID), "Invalid slot ID"},
	{ERR_REASON(CKR_GENERAL_ERROR), "General Error"},
	{ERR_REASON(CKR_FUNCTION_FAILED), "Function failed"},
	{ERR_REASON(CKR_ARGUMENTS_BAD), "Invalid arguments"},
	{ERR_REASON(CKR_NO_EVENT), "No event"},
	{ERR_REASON(CKR_NEED_TO_CREATE_THREADS), "Need to create threads"},
	{ERR_REASON(CKR_CANT_LOCK), "Cannot lock"},
	{ERR_REASON(CKR_ATTRIBUTE_READ_ONLY), "Attribute read only"},
	{ERR_REASON(CKR_ATTRIBUTE_SENSITIVE), "Attribute sensitive"},
	{ERR_REASON(CKR_ATTRIBUTE_TYPE_INVALID), "Attribute type invalid"},
	{ERR_REASON(CKR_ATTRIBUTE_VALUE_INVALID), "Attribute value invalid"},
	{ERR_REASON(CKR_DATA_INVALID), "Data invalid"},
	{ERR_REASON(CKR_DATA_LEN_RANGE), "Data len range"},
	{ERR_REASON(CKR_DEVICE_ERROR), "Device error"},
	{ERR_REASON(CKR_DEVICE_MEMORY), "Device memory"},
	{ERR_REASON(CKR_DEVICE_REMOVED), "Device removed"},
	{ERR_REASON(CKR_ENCRYPTED_DATA_INVALID), "Encrypted data invalid"},
	{ERR_REASON(CKR_ENCRYPTED_DATA_LEN_RANGE), "Encrypted data len range"},
	{ERR_REASON(CKR_FUNCTION_CANCELED), "Function canceled"},
	{ERR_REASON(CKR_FUNCTION_NOT_PARALLEL), "Function not parallel"},
	{ERR_REASON(CKR_FUNCTION_NOT_SUPPORTED), "Function not supported"},
	{ERR_REASON(CKR_KEY_HANDLE_INVALID), "Key handle invalid"},
	{ERR_REASON(CKR_KEY_SIZE_RANGE), "Key size range"},
	{ERR_REASON(CKR_KEY_TYPE_INCONSISTENT), "Key type inconsistent"},
	{ERR_REASON(CKR_KEY_NOT_NEEDED), "Key not needed"},
	{ERR_REASON(CKR_KEY_CHANGED), "Key changed"},
	{ERR_REASON(CKR_KEY_NEEDED), "Key needed"},
	{ERR_REASON(CKR_KEY_INDIGESTIBLE), "Key indigestible"},
	{ERR_REASON(CKR_KEY_FUNCTION_NOT_PERMITTED), "Key function not permitted"},
	{ERR_REASON(CKR_KEY_NOT_WRAPPABLE), "Key not wrappable"},
	{ERR_REASON(CKR_KEY_UNEXTRACTABLE), "Key unextractable"},
	{ERR_REASON(CKR_MECHANISM_INVALID), "Mechanism invalid"},
	{ERR_REASON(CKR_MECHANISM_PARAM_INVALID), "Mechanism param invalid"},
	{ERR_REASON(CKR_OBJECT_HANDLE_INVALID), "Object handle invalid"},
	{ERR_REASON(CKR_OPERATION_ACTIVE), "Operation active"},
	{ERR_REASON(CKR_OPERATION_NOT_INITIALIZED), "Operation not initialized"},
	{ERR_REASON(CKR_PIN_INCORRECT), "PIN incorrect"},
	{ERR_REASON(CKR_PIN_INVALID), "PIN invalid"},
	{ERR_REASON(CKR_PIN_LEN_RANGE), "Invalid PIN length"},
	{ERR_REASON(CKR_PIN_EXPIRED), "PIN expired"},
	{ERR_REASON(CKR_PIN_LOCKED), "PIN locked"},
	{ERR_REASON(CKR_SESSION_CLOSED), "Session closed"},
	{ERR_REASON(CKR_SESSION_COUNT), "Session count"},
	{ERR_REASON(CKR_SESSION_HANDLE_INVALID), "Session handle invalid"},
	{ERR_REASON(CKR_SESSION_PARALLEL_NOT_SUPPORTED), "Session parallel not supported"},
	{ERR_REASON(CKR_SESSION_READ_ONLY), "Session read only"},
	{ERR_REASON(CKR_SESSION_EXISTS), "Session exists"},
	{ERR_REASON(CKR_SESSION_READ_ONLY_EXISTS), "Read-only session exists"},
	{ERR_REASON(CKR_SESSION_READ_WRITE_SO_EXISTS), "Read/write SO session exists"},
	{ERR_REASON(CKR_SIGNATURE_INVALID), "Signature invalid"},
	{ERR_REASON(CKR_SIGNATURE_LEN_RANGE), "Signature len range"},
	{ERR_REASON(CKR_TEMPLATE_INCOMPLETE), "Incomplete template"},
	{ERR_REASON(CKR_TEMPLATE_INCONSISTENT), "Inconsistent template"},
	{ERR_REASON(CKR_TOKEN_NOT_PRESENT), "No PKCS#11 token present"},
	{ERR_REASON(CKR_TOKEN_NOT_RECOGNIZED), "PKCS#11 token not recognized"},
	{ERR_REASON(CKR_TOKEN_WRITE_PROTECTED), "Token write protected"},
	{ERR_REASON(CKR_UNWRAPPING_KEY_HANDLE_INVALID), "Unwrapping key handle invalid"},
	{ERR_REASON(CKR_UNWRAPPING_KEY_SIZE_RANGE), "Unwrapping key size range"},
	{ERR_REASON(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT), "Unwrapping key type inconsistent"},
	{ERR_REASON(CKR_USER_ALREADY_LOGGED_IN), "User already logged in"},
	{ERR_REASON(CKR_USER_NOT_LOGGED_IN), "User not logged in"},
	{ERR_REASON(CKR_USER_PIN_NOT_INITIALIZED), "User pin not initialized"},
	{ERR_REASON(CKR_USER_TYPE_INVALID), "User type invalid"},
	{ERR_REASON(CKR_USER_ANOTHER_ALREADY_LOGGED_IN), "User another is already logged in"},
	{ERR_REASON(CKR_USER_TOO_MANY_TYPES), "User too many types"},
	{ERR_REASON(CKR_WRAPPED_KEY_INVALID), "Wrapped key invalid"},
	{ERR_REASON(CKR_WRAPPED_KEY_LEN_RANGE), "Wrapped key len range"},
	{ERR_REASON(CKR_WRAPPING_KEY_HANDLE_INVALID), "Wrapping key handle invalid"},
	{ERR_REASON(CKR_WRAPPING_KEY_SIZE_RANGE), "Wrapping key size range"},
	{ERR_REASON(CKR_WRAPPING_KEY_TYPE_INCONSISTENT), "Wrapping key type inconsistent"},
	{ERR_REASON(CKR_RANDOM_SEED_NOT_SUPPORTED), "Random seed not supported"},
	{ERR_REASON(CKR_RANDOM_NO_RNG), "Random no rng"},
	{ERR_REASON(CKR_DOMAIN_PARAMS_INVALID), "Domain params invalid"},
	{ERR_REASON(CKR_BUFFER_TOO_SMALL), "Buffer too small"},
	{ERR_REASON(CKR_SAVED_STATE_INVALID), "Saved state invalid"},
	{ERR_REASON(CKR_INFORMATION_SENSITIVE), "Information sensitive"},
	{ERR_REASON(CKR_STATE_UNSAVEABLE), "State unsaveable"},
	{ERR_REASON(CKR_CRYPTOKI_NOT_INITIALIZED), "Cryptoki not initialized"},
	{ERR_REASON(CKR_CRYPTOKI_ALREADY_INITIALIZED), "Cryptoki already initialized"},
	{ERR_REASON(CKR_MUTEX_BAD), "Mutex bad"},
	{ERR_REASON(CKR_MUTEX_NOT_LOCKED), "Mutex not locked"},
	{ERR_REASON(CKR_NEW_PIN_MODE), "New pin mode"},
	{ERR_REASON(CKR_NEXT_OTP), "Next otp"},
	{ERR_REASON(CKR_EXCEEDED_MAX_ITERATIONS), "Exceeded max iterations"},
	{ERR_REASON(CKR_FIPS_SELF_TEST_FAILED), "FIPS seld test failed"},
	{ERR_REASON(CKR_LIBRARY_LOAD_FAILED), "Library load failed"},
	{ERR_REASON(CKR_PIN_TOO_WEAK), "Pin too weak"},
	{ERR_REASON(CKR_PUBLIC_KEY_INVALID), "Public key invalid"},
	{ERR_REASON(CKR_FUNCTION_REJECTED), "Function rejected"},
	{ERR_REASON(CKR_TOKEN_RESOURCE_EXCEEDED), "Token resource exceeded"},
	{ERR_REASON(CKR_VENDOR_DEFINED), "Vendor defined"},
	{0, NULL}
};
#endif

#ifdef CKR_LIB_NAME
static ERR_STRING_DATA CKR_lib_name[] = {
	{0, CKR_LIB_NAME},
	{0, NULL}
};
#endif

static int CKR_lib_error_code = 0;
static int CKR_error_init = 1;

int ERR_load_CKR_strings(void)
{
	if (CKR_lib_error_code == 0)
		CKR_lib_error_code = ERR_get_next_error_library();

	if (CKR_error_init) {
		CKR_error_init = 0;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(CKR_lib_error_code, CKR_str_functs);
		ERR_load_strings(CKR_lib_error_code, CKR_str_reasons);
#endif

#ifdef CKR_LIB_NAME
		CKR_lib_name->error = ERR_PACK(CKR_lib_error_code, 0, 0);
		ERR_load_strings(0, CKR_lib_name);
#endif
	}
	return 1;
}

void ERR_unload_CKR_strings(void)
{
	if (CKR_error_init == 0) {
#ifndef OPENSSL_NO_ERR
		ERR_unload_strings(CKR_lib_error_code, CKR_str_functs);
		ERR_unload_strings(CKR_lib_error_code, CKR_str_reasons);
#endif

#ifdef CKR_LIB_NAME
		ERR_unload_strings(0, CKR_lib_name);
#endif
		CKR_error_init = 1;
	}
}

void ERR_CKR_error(int function, int reason, char *file, int line)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    (void)function;
#endif

	if (CKR_lib_error_code == 0)
		CKR_lib_error_code = ERR_get_next_error_library();
	ERR_PUT_error(CKR_lib_error_code, function, reason, file, line);
}

/* During dynamic module initialization one shall not use error codes
 * of the library, since OpenSSL unloads the module before printing
 * the error message. Hence the strings won't be available.
 */
void ERR_CKR_init_error(int function, int reason, char *file, int line)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* Fallback to original version as I have no such OpenSSL version 
     * to implement properly.
     */
    ERR_CKR_error(function, reason, file, line);
#else
    (void)function;
    char buffer[4096];
    ERR_STRING_DATA *msg = CKR_str_reasons;

    while((msg->error&ERR_REASON_MASK) != (unsigned int)reason && msg->string != NULL)
    {
        ++msg;
    }

# ifdef OPENSSL_NO_FILENAMES
    file = "";
# endif

    if (msg->string != NULL)
    {
        snprintf(buffer, 4095, "%s:%s:%s:%s:%d", CKR_lib_name->string, OPENSSL_FUNC, msg->string, file, line);
    }
    else
    {
        snprintf(buffer, 4095, "%s:%s:reason(%d):%s:%d", CKR_lib_name->string, OPENSSL_FUNC, reason, file, line);
    }

    ERR_raise(ERR_LIB_PROV, ERR_R_INIT_FAIL);
    ERR_add_error_data(1, buffer);
#endif
}

int ERR_get_CKR_code(void)
{
	if (CKR_lib_error_code == 0)
		CKR_lib_error_code = ERR_get_next_error_library();
	return CKR_lib_error_code;
}

/* vim: set noexpandtab: */
