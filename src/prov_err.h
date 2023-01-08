/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PROV_ERR_H
#define HEADER_PROV_ERR_H

#ifdef __cplusplus
extern "C"
{
#endif

    int ERR_load_PROV_strings(void);
    void ERR_unload_PROV_strings(void);
    void ERR_PROV_error(int function, int reason, char* file, int line);

#define P11_PROVerr(f, r) ERR_PROV_error((f), (r), __FILE__, __LINE__)

#define PROV_checkerr(f, rv) \
    {                        \
        if (rv)              \
        {                    \
            PROVerr(f, rv);  \
            return -1;       \
        }                    \
        ERR_clear_error();   \
    }

    /* BEGIN ERROR CODES */

/* Error codes for the ENG functions. */

/* Function codes. */
#define PROV_F_CTX_LOAD_PRIVKEY 100
#define PROV_F_CTX_LOAD_PUBKEY 101
#define PROV_F_CTX_CTRL_SET_PIN 102
#define PROV_F_CTX_LOAD_OBJECT 103
#define PROV_F_STOREMGMT 104
#define PROV_F_URI 105
#define PROV_F_CTX_GET_PIN 106
#define PROV_CTX_LOGIN 107

/* Reason codes. */
#define PROV_R_INVALID_ID 100
#define PROV_R_OBJECT_NOT_FOUND 101
#define PROV_R_UNKNOWN_COMMAND 102
#define PROV_R_INVALID_PARAMETER 103
#define PROV_R_LOAD_OBJECT_CB 104
#define PROV_R_UNHANDLED_KEY_TYPE 105
#define PROV_R_EVP_LOADER_ERR 106
#define PROV_R_CANNOT_LOAD_PRIVKEY 107
#define PROV_R_CANNOT_LOAD_PUBKEY 108
#define PROV_R_CANNOT_LOAD_UNHANDLED_DATA_TYPE 109
#define PROV_R_UNHANDLED_KEY_TYPE 110
#define PROV_R_CANNOT_PARSE_URI 111
#define PROV_R_MEMORY 112
#define PROV_R_URI_TYPE_UNKNOWN 113
#define PROV_R_INPUT_FAILED 114
#define PROV_R_LOGIN_FAILED 115
#define PROV_R_SLOT_AMBIGUOUS 116

#ifdef __cplusplus
}
#endif
#endif
