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

#include "libp11-int.h"

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA PKCS11_str_library[] = {
	{ERR_PACK(ERR_LIB_PKCS11, 0, 0), "PKCS11 library"},
	{0, NULL}
};

static ERR_STRING_DATA PKCS11_str_functs[] = {
	{ERR_PACK(0, PKCS11_F_PKCS11_CTX_LOAD, 0), "PKCS11_CTX_load"},
	{ERR_PACK(0, PKCS11_F_PKCS11_ENUM_SLOTS, 0), "PKCS11_enum_slots"},
	{ERR_PACK(0, PKCS11_F_PKCS11_CHECK_TOKEN, 0), "PKCS11_check_token"},
	{ERR_PACK(0, PKCS11_F_PKCS11_OPEN_SESSION, 0), "PKCS11_open_session"},
	{ERR_PACK(0, PKCS11_F_PKCS11_LOGIN, 0), "PKCS11_login"},
	{ERR_PACK(0, PKCS11_F_PKCS11_ENUM_KEYS, 0), "PKCS11_enum_keys"},
	{ERR_PACK(0, PKCS11_F_PKCS11_GET_KEY, 0), "PKCS11_get_key"},
	{ERR_PACK(0, PKCS11_F_PKCS11_RSA_DECRYPT, 0), "PKCS11_rsa_decrypt"},
	{ERR_PACK(0, PKCS11_F_PKCS11_RSA_ENCRYPT, 0), "PKCS11_rsa_encrypt"},
	{ERR_PACK(0, PKCS11_F_PKCS11_RSA_SIGN, 0), "PKCS11_rsa_sign"},
	{ERR_PACK(0, PKCS11_F_PKCS11_RSA_VERIFY, 0), "PKCS11_rsa_verify"},
	{ERR_PACK(0, PKCS11_F_PKCS11_ENUM_CERTS, 0), "PKCS11_enum_certs"},
	{ERR_PACK(0, PKCS11_F_PKCS11_INIT_TOKEN, 0), "PKCS11_init_token"},
	{ERR_PACK(0, PKCS11_F_PKCS11_INIT_PIN, 0), "PKCS11_init_pin"},
	{ERR_PACK(0, PKCS11_F_PKCS11_GETATTR, 0), "pkcs11_getattr"},
	{ERR_PACK(0, PKCS11_F_PKCS11_LOGOUT, 0), "PKCS11_logout"},
	{ERR_PACK(0, PKCS11_F_PKCS11_STORE_PRIVATE_KEY, 0), "PKCS11_store_private_key"},
	{ERR_PACK(0, PKCS11_F_PKCS11_GENERATE_KEY, 0), "PKCS11_generate_key"},
	{ERR_PACK(0, PKCS11_F_PKCS11_GENERATE_KEY_PAIR, 0), "PKCS11_generate_key_pair"},
	{ERR_PACK(0, PKCS11_F_PKCS11_STORE_PUBLIC_KEY, 0), "PKCS11_store_public_key"},
	{ERR_PACK(0, PKCS11_F_PKCS11_STORE_CERTIFICATE, 0), "PKCS11_store_certificate"},
	{ERR_PACK(0, PKCS11_F_PKCS11_CHANGE_PIN, 0), "PKCS11_change_pin"},
	{ERR_PACK(0, PKCS11_F_PKCS11_EC_KEY_COMPUTE_KEY, 0), "PKCS11_ecdh_derive"},
	{0, NULL}
};

static ERR_STRING_DATA PKCS11_str_reasons[] = {
	{PKCS11_LOAD_MODULE_ERROR, "Unable to load PKCS#11 module"},
	{PKCS11_MODULE_LOADED_ERROR, "Already loaded module for PKCS#11 context"},
	{PKCS11_SYMBOL_NOT_FOUND_ERROR, "Symbol not found in PKCS#11 module"},
	{PKCS11_NOT_SUPPORTED, "Not supported"},
	{PKCS11_NO_SESSION, "No session open"},
	{PKCS11_UI_FAILED, "UI request failed"},
	{CKR_CANCEL, "Cancel"},
	{CKR_HOST_MEMORY, "Host memory error"},
	{CKR_SLOT_ID_INVALID, "Invalid slot ID"},
	{CKR_GENERAL_ERROR, "General Error"},
	{CKR_FUNCTION_FAILED, "Function failed"},
	{CKR_ARGUMENTS_BAD, "Invalid arguments"},
	{CKR_NO_EVENT, "No event"},
	{CKR_NEED_TO_CREATE_THREADS, "Need to create threads"},
	{CKR_CANT_LOCK, "Cannott lock"},
	{CKR_ATTRIBUTE_READ_ONLY, "Attribute read only"},
	{CKR_ATTRIBUTE_SENSITIVE, "Attribute sensitive"},
	{CKR_ATTRIBUTE_TYPE_INVALID, "Attribute type invalid"},
	{CKR_ATTRIBUTE_VALUE_INVALID, "Attribute value invalid"},
	{CKR_DATA_INVALID, "Data invalid"},
	{CKR_DATA_LEN_RANGE, "Data len range"},
	{CKR_DEVICE_ERROR, "Device error"},
	{CKR_DEVICE_MEMORY, "Device memory"},
	{CKR_DEVICE_REMOVED, "Device removed"},
	{CKR_ENCRYPTED_DATA_INVALID, "Encrypted data invalid"},
	{CKR_ENCRYPTED_DATA_LEN_RANGE, "Encrypted data len range"},
	{CKR_FUNCTION_CANCELED, "Function canceled"},
	{CKR_FUNCTION_NOT_PARALLEL, "Function not parallel"},
	{CKR_FUNCTION_NOT_SUPPORTED, "Function not supported"},
	{CKR_KEY_HANDLE_INVALID, "Key handle invalid"},
	{CKR_KEY_SIZE_RANGE, "Key size range"},
	{CKR_KEY_TYPE_INCONSISTENT, "Key type inconsistent"},
	{CKR_KEY_NOT_NEEDED, "Key not needed"},
	{CKR_KEY_CHANGED, "Key changed"},
	{CKR_KEY_NEEDED, "Key needed"},
	{CKR_KEY_INDIGESTIBLE, "Key indigestible"},
	{CKR_KEY_FUNCTION_NOT_PERMITTED, "Key function not permitted"},
	{CKR_KEY_NOT_WRAPPABLE, "Key not wrappable"},
	{CKR_KEY_UNEXTRACTABLE, "Key unextractable"},
	{CKR_MECHANISM_INVALID, "Mechanism invalid"},
	{CKR_MECHANISM_PARAM_INVALID, "Mechanism param invalid"},
	{CKR_OBJECT_HANDLE_INVALID, "Object handle invalid"},
	{CKR_OPERATION_ACTIVE, "Operation active"},
	{CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized"},
	{CKR_PIN_INCORRECT, "PIN incorrect"},
	{CKR_PIN_INVALID, "PIN invalid"},
	{CKR_PIN_LEN_RANGE, "Invalid PIN length"},
	{CKR_PIN_EXPIRED, "PIN expired"},
	{CKR_PIN_LOCKED, "PIN locked"},
	{CKR_SESSION_CLOSED, "Session closed"},
	{CKR_SESSION_COUNT, "Session count"},
	{CKR_SESSION_HANDLE_INVALID, "Session handle invalid"},
	{CKR_SESSION_PARALLEL_NOT_SUPPORTED, "Session parallel not supported"},
	{CKR_SESSION_READ_ONLY, "Session read only"},
	{CKR_SESSION_EXISTS, "Session exists"},
	{CKR_SESSION_READ_ONLY_EXISTS, "Read-only session exists"},
	{CKR_SESSION_READ_WRITE_SO_EXISTS, "Read/write SO session exists"},
	{CKR_SIGNATURE_INVALID, "Signature invalid"},
	{CKR_SIGNATURE_LEN_RANGE, "Signature len range"},
	{CKR_TEMPLATE_INCOMPLETE, "Incomplete template"},
	{CKR_TEMPLATE_INCONSISTENT, "Inconsistent template"},
	{CKR_TOKEN_NOT_PRESENT, "No PKCS#11 token present"},
	{CKR_TOKEN_NOT_RECOGNIZED, "PKCS#11 token not recognized"},
	{CKR_TOKEN_WRITE_PROTECTED, "Token write protected"},
	{CKR_UNWRAPPING_KEY_HANDLE_INVALID, "Unwrapping key handle invalid"},
	{CKR_UNWRAPPING_KEY_SIZE_RANGE, "Unwrapping key size range"},
	{CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, "Unwrapping key type inconsistent"},
	{CKR_USER_ALREADY_LOGGED_IN, "User already logged in"},
	{CKR_USER_NOT_LOGGED_IN, "User not logged in"},
	{CKR_USER_PIN_NOT_INITIALIZED, "User pin not initialized"},
	{CKR_USER_TYPE_INVALID, "User type invalid"},
	{CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "User another is already logged in"},
	{CKR_USER_TOO_MANY_TYPES, "User too many types"},
	{CKR_WRAPPED_KEY_INVALID, "Wrapped key invalid"},
	{CKR_WRAPPED_KEY_LEN_RANGE, "Wrapped key len range"},
	{CKR_WRAPPING_KEY_HANDLE_INVALID, "Wrapping key handle invalid"},
	{CKR_WRAPPING_KEY_SIZE_RANGE, "Wrapping key size range"},
	{CKR_WRAPPING_KEY_TYPE_INCONSISTENT, "Wrapping key type inconsistent"},
	{CKR_RANDOM_SEED_NOT_SUPPORTED, "Random seed not supported"},
	{CKR_RANDOM_NO_RNG, "Random no rng"},
	{CKR_DOMAIN_PARAMS_INVALID, "Domain params invalid"},
	{CKR_BUFFER_TOO_SMALL, "Buffer too small"},
	{CKR_SAVED_STATE_INVALID, "Saved state invalid"},
	{CKR_INFORMATION_SENSITIVE, "Information sensitive"},
	{CKR_STATE_UNSAVEABLE, "State unsaveable"},
	{CKR_CRYPTOKI_NOT_INITIALIZED, "Cryptoki not initialized"},
	{CKR_CRYPTOKI_ALREADY_INITIALIZED, "Cryptoki already initialized"},
	{CKR_MUTEX_BAD, "Mutex bad"},
	{CKR_MUTEX_NOT_LOCKED, "Mutex not locked"},
	{CKR_VENDOR_DEFINED, "Vendor defined"},
	{0, NULL}
};
#endif

void ERR_load_PKCS11_strings(void)
{
	static int init = 1;

	if (init) {
		init = 0;
#ifndef NO_ERR
		ERR_load_strings(0, PKCS11_str_library);
		ERR_load_strings(ERR_LIB_PKCS11, PKCS11_str_functs);
		ERR_load_strings(ERR_LIB_PKCS11, PKCS11_str_reasons);
#endif
	}
}

/* vim: set noexpandtab: */
