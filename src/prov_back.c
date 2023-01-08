/*
 * Copyright (c) 2001 Markus Friedl
 * Copyright (c) 2002 Juha Yrjölä
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
 * Copyright (c) 2016-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Copyright (c) 2022 Zoltan Patocs
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

#include "libp11-int.h"
#include "libp11.h"
#include "prov_ctx.h"
#include "prov_err.h"
#include "prov_parse.h"

#include <stdio.h>
#include <string.h>

#include <openssl/provider.h>
#include <openssl/ui.h> /* UI_INPUT_FLAG_DEFAULT_PWD */

#if defined(_WIN32) || defined(_WIN64)
#define strncasecmp _strnicmp
#endif

/* The maximum length of an internally-allocated PIN */
#define MAX_PIN_LENGTH 32
#define MAX_VALUE_LEN 200

static int ctx_ctrl_set_pin(PROVIDER_CTX* ctx, const char* pin);

/******************************************************************************/
/* Utility functions                                                          */
/******************************************************************************/

static void dump_hex(PROVIDER_CTX* ctx, int level,
                     const unsigned char* val, const size_t len)
{
    size_t n;

    for (n = 0; n < len; n++)
        ctx_log(ctx, level, "%02x", val[n]);
}

/******************************************************************************/
/* PIN handling                                                               */
/******************************************************************************/

/* Free PIN storage in secure way. */
static void ctx_destroy_pin(PROVIDER_CTX* ctx)
{
    if (ctx->pin)
    {
        OPENSSL_cleanse(ctx->pin, ctx->pin_length);
        OPENSSL_free(ctx->pin);
        ctx->pin = NULL;
        ctx->pin_length = 0;
        ctx->forced_pin = 0;
    }
}

/* Get the PIN via asking user interface. The supplied call-back data are
 * passed to the user interface implemented by an application. Only the
 * application knows how to interpret the call-back data.
 * A (strdup'ed) copy of the PIN code will be stored in the pin variable. */
static int ctx_get_pin(PROVIDER_CTX* ctx, const char* token_label, OSSL_PASSPHRASE_CALLBACK* pw_cb, void* pw_cbarg)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DESC, (char*)token_label, 0);
    params[1] = OSSL_PARAM_construct_end();

    ctx->pin = OPENSSL_zalloc(MAX_PIN_LENGTH + 1);
    if (!ctx->pin)
        return 0;

    /* request password; this is application specific*/
    if (!pw_cb(ctx->pin, MAX_PIN_LENGTH, &ctx->pin_length, params, pw_cbarg))
    {
        PROVerr(PROV_F_GET_PIN, PROV_R_INPUT_FAILED);
        // ctx_log(ctx, 0, "pin input failed");
        goto err;
    }

    return 1;

err:
    free(ctx->pin);
    ctx->pin = NULL;

    return 0;
}

/* Return 1 if the user has already logged in */
static int slot_logged_in(PROVIDER_CTX* ctx, PKCS11_SLOT* slot)
{
    int logged_in = 0;

    /* Check if already logged in to avoid resetting state */
    if (PKCS11_is_logged_in(slot, 0, &logged_in) != 0)
    {
        ctx_log(ctx, 0, "Unable to check if already logged in\n");
        return 0;
    }
    return logged_in;
}

/*
 * Log-into the token if necessary.
 *
 * @slot is PKCS11 slot to log in
 * @tok is PKCS11 token to log in (??? could be derived as @slot->token)
 * @ui_method is OpenSSL user interface which is used to ask for a password
 * @callback_data are application data to the user interface
 * @return 1 on success, 0 on error.
 */
static int ctx_login(PROVIDER_CTX* ctx, PKCS11_SLOT* slot, PKCS11_TOKEN* tok,
                     OSSL_PASSPHRASE_CALLBACK* pw_cb, void* pw_cbarg)
{
    if (!(ctx->force_login || tok->loginRequired) || slot_logged_in(ctx, slot))
        return 1;

    /* If the token has a secure login (i.e., an external keypad),
     * then use a NULL PIN. Otherwise, obtain a new PIN if needed. */
    if (tok->secureLogin && !ctx->forced_pin)
    {
        /* Free the PIN if it has already been
         * assigned (i.e, cached by ctx_get_pin) */
        ctx_destroy_pin(ctx);
    }
    else if (!ctx->pin)
    {
        ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH + 1);
        ctx->pin_length = MAX_PIN_LENGTH;
        if (ctx->pin == NULL)
        {
            ctx_log(ctx, 0, "Could not allocate memory for PIN\n");
            return 0;
        }
        memset(ctx->pin, 0, MAX_PIN_LENGTH + 1);
        if (!ctx_get_pin(ctx, tok->label, pw_cb, pw_cbarg))
        {
            ctx_destroy_pin(ctx);
            ctx_log(ctx, 0, "No PIN code was entered\n");
            return 0;
        }
    }

    /* Now login in with the (possibly NULL) PIN */
    if (PKCS11_login(slot, 0, ctx->pin))
    {
        /* Login failed, so free the PIN if present */
        ctx_destroy_pin(ctx);
        PROVerr(PROV_CTX_LOGIN, PROV_R_LOGIN_FAILED);
        // ctx_log(ctx, 0, "Login failed\n");
        return 0;
    }
    return 1;
}

/******************************************************************************/
/*                                                                            */
/******************************************************************************/

static int ctx_enumerate_slots_unlocked(PROVIDER_CTX* ctx, PKCS11_CTX* pkcs11_ctx)
{
    /* PKCS11_update_slots() uses C_GetSlotList() via libp11 */
    if (PKCS11_update_slots(pkcs11_ctx, &ctx->slot_list, &ctx->slot_count) < 0)
    {
        ctx_log(ctx, 0, "Failed to enumerate slots\n");
        return 0;
    }
    ctx_log(ctx, 1, "Found %u slot%s\n", ctx->slot_count,
            ctx->slot_count <= 1 ? "" : "s");
    return 1;
}

/* not used currently, but kept here for further reference*/
/*
static int ctx_enumerate_slots(PROVIDER_CTX* ctx, PKCS11_CTX* pkcs11_ctx)
{
    int rv;

    pthread_mutex_lock(&ctx->lock);
    rv = ctx_enumerate_slots_unlocked(ctx, pkcs11_ctx);
    pthread_mutex_unlock(&ctx->lock);
    return rv;
}
*/

/* Initialize libp11 data: ctx->pkcs11_ctx and ctx->slot_list */
static int ctx_init_libp11_unlocked(PROVIDER_CTX* ctx)
{
    PKCS11_CTX* pkcs11_ctx;

    if (ctx->pkcs11_ctx && ctx->slot_list)
        return 0;

    ctx_log(ctx, 1, "PKCS#11: Initializing the engine: %s\n", ctx->module);

    pkcs11_ctx = PKCS11_CTX_new();
    PKCS11_CTX_init_args(pkcs11_ctx, ctx->init_args);
    PKCS11_set_password_callback(pkcs11_ctx, ctx->pw_cb, ctx->pw_cbarg);
    if (PKCS11_CTX_load(pkcs11_ctx, ctx->module) < 0)
    {
        ctx_log(ctx, 0, "Unable to load module %s\n", ctx->module);
        PKCS11_CTX_free(pkcs11_ctx);
        return -1;
    }
    ctx->pkcs11_ctx = pkcs11_ctx;

    if (ctx_enumerate_slots_unlocked(ctx, pkcs11_ctx) != 1)
        return -1;

    return ctx->pkcs11_ctx && ctx->slot_list ? 0 : -1;
}

/******************************************************************************/
/* Utilities common to public, private key and certificate handling           */
/******************************************************************************/

static void* ctx_try_load_object(PROVIDER_CTX* ctx,
                                 const char* object_typestr,
                                 void* (*match_func)(PROVIDER_CTX*, PKCS11_TOKEN*,
                                                     const unsigned char*, size_t, const char*),
                                 const char* object_uri, const int login,
                                 OSSL_PASSPHRASE_CALLBACK* pw_cb, void* pw_cbarg)
{
    PKCS11_SLOT* slot;
    PKCS11_SLOT *found_slot = NULL, **matched_slots = NULL;
    PKCS11_TOKEN *tok, *match_tok = NULL;
    unsigned int n, m;
    unsigned char obj_id[MAX_VALUE_LEN / 2];
    size_t obj_id_len = sizeof(obj_id);
    char* obj_label = NULL;
    char tmp_pin[MAX_PIN_LENGTH + 1];
    size_t tmp_pin_len = MAX_PIN_LENGTH;
    int slot_nr = -1;
    char flags[64];
    size_t matched_count = 0;
    void* object = NULL;

    if (object_uri && *object_uri)
    {
        if (!strncasecmp(object_uri, "pkcs11:", 7))
        {
            n = parse_pkcs11_uri(ctx, object_uri, &match_tok,
                                 obj_id, &obj_id_len, tmp_pin, &tmp_pin_len, &obj_label);
            if (!n)
            {
                ctx_log(ctx, 0,
                        "The %s ID is not a valid PKCS#11 URI\n"
                        "The PKCS#11 URI format is defined by RFC7512\n",
                        object_typestr);
                PROVerr(PROV_F_CTX_LOAD_OBJECT, PROV_R_INVALID_ID);
                goto error;
            }
            if (tmp_pin_len > 0 && tmp_pin[0] != 0)
            {
                tmp_pin[tmp_pin_len] = 0;
                if (!ctx_ctrl_set_pin(ctx, tmp_pin))
                {
                    goto error;
                }
            }
            ctx_log(ctx, 1, "Looking in slots for %s %s login: ",
                    object_typestr, login ? "with" : "without");
        }
        else
        {
            n = parse_slot_id_string(ctx, object_uri, &slot_nr,
                                     obj_id, &obj_id_len, &obj_label);
            if (!n)
            {
                ctx_log(ctx, 0,
                        "The %s ID is not a valid PKCS#11 URI\n"
                        "The PKCS#11 URI format is defined by RFC7512\n"
                        "The legacy ENGINE_pkcs11 ID format is also "
                        "still accepted for now\n",
                        object_typestr);
                PROVerr(PROV_F_CTX_LOAD_OBJECT, PROV_R_INVALID_ID);
                goto error;
            }
            ctx_log(ctx, 1, "Looking in slot %d for %s %s login: ",
                    slot_nr, object_typestr, login ? "with" : "without");
        }
        if (obj_id_len != 0)
        {
            ctx_log(ctx, 1, "id=");
            dump_hex(ctx, 1, obj_id, obj_id_len);
        }
        if (obj_id_len != 0 && obj_label)
            ctx_log(ctx, 1, " ");
        if (obj_label)
            ctx_log(ctx, 1, "label=%s", obj_label);
        ctx_log(ctx, 1, "\n");
    }

    matched_slots = (PKCS11_SLOT**)calloc(ctx->slot_count,
                                          sizeof(PKCS11_SLOT*));
    if (!matched_slots)
    {
        PROVerr(PROV_F_CTX_LOAD_OBJECT, PROV_R_MEMORY);
        // ctx_log(ctx, 0, "Could not allocate memory for matched slots\n");
        goto error;
    }

    for (n = 0; n < ctx->slot_count; n++)
    {
        slot = ctx->slot_list + n;
        flags[0] = '\0';
        if (slot->token)
        {
            if (!slot->token->initialized)
                strcat(flags, "uninitialized, ");
            else if (!slot->token->userPinSet)
                strcat(flags, "no pin, ");
            if (slot->token->loginRequired)
                strcat(flags, "login, ");
            if (slot->token->readOnly)
                strcat(flags, "ro, ");
        }
        else
        {
            strcpy(flags, "no token");
        }
        if ((m = strlen(flags)) != 0)
        {
            flags[m - 2] = '\0';
        }

        if (slot_nr != -1 && slot_nr == (int)PKCS11_get_slotid_from_slot(slot))
        {
            found_slot = slot;
        }

        if (match_tok && slot->token && (!match_tok->label || !strcmp(match_tok->label, slot->token->label)) && (!match_tok->manufacturer || !strcmp(match_tok->manufacturer, slot->token->manufacturer)) && (!match_tok->serialnr || !strcmp(match_tok->serialnr, slot->token->serialnr)) && (!match_tok->model || !strcmp(match_tok->model, slot->token->model)))
        {
            found_slot = slot;
        }
        ctx_log(ctx, 1, "- [%lu] %-25.25s  %-36s",
                PKCS11_get_slotid_from_slot(slot),
                slot->description, flags);
        if (slot->token)
        {
            ctx_log(ctx, 1, "  (%s)",
                    slot->token->label[0] ? slot->token->label : "no label");
        }
        ctx_log(ctx, 1, "\n");

        /* Ignore slots without tokens or with uninitialized token */
        if (found_slot && found_slot->token && found_slot->token->initialized)
        {
            matched_slots[matched_count] = found_slot;
            matched_count++;
        }
        found_slot = NULL;
    }

    if (matched_count == 0)
    {
        if (match_tok)
        {
            if (found_slot)
            {
                PROVerr(PROV_F_CTX_LOAD_OBJECT, PROV_R_OBJECT_NOT_FOUND);
                ctx_log(ctx, 0, "The %s was not found on token %s\n",
                        object_typestr, found_slot->token->label[0] ? found_slot->token->label : "no label");
            }
            else
            {
                PROVerr(PROV_F_CTX_LOAD_OBJECT, PROV_R_OBJECT_NOT_FOUND);
                ctx_log(ctx, 0, "No matching initialized token was found for %s\n",
                        object_typestr);
            }
            goto error;
        }

        /* If the legacy slot ID format was used */
        if (slot_nr != -1)
        {
            PROVerr(PROV_F_CTX_LOAD_OBJECT, PROV_R_OBJECT_NOT_FOUND);
            ctx_log(ctx, 0, "The %s was not found on slot %d\n", object_typestr, slot_nr);
            goto error;
        }
        else
        {
            found_slot = PKCS11_find_token(ctx->pkcs11_ctx,
                                           ctx->slot_list, ctx->slot_count);
            /* Ignore if the the token is not initialized */
            if (found_slot && found_slot->token && found_slot->token->initialized)
            {
                matched_slots[matched_count] = found_slot;
                matched_count++;
            }
            else
            {
                PROVerr(PROV_F_CTX_LOAD_OBJECT, PROV_R_OBJECT_NOT_FOUND);
                ctx_log(ctx, 0, "No tokens found\n");
                goto error;
            }
        }
    }

    for (n = 0; n < matched_count; n++)
    {
        slot = matched_slots[n];
        tok = slot->token;
        if (!tok)
        {
            ctx_log(ctx, 0, "Empty slot found\n");
            break;
        }

        ctx_log(ctx, 1, "Found slot:  %s\n", slot->description);
        ctx_log(ctx, 1, "Found token: %s\n", slot->token->label);

        /* In several tokens certificates are marked as private */
        if (login)
        {
            /* Only try to login if login is required */
            if (tok->loginRequired)
            {
                /* Only try to login if a single slot matched to avoiding trying
                 * the PIN against all matching slots */
                if (matched_count == 1)
                {
                    if (!ctx_login(ctx, slot, tok,
                                   pw_cb, pw_cbarg))
                    {
                        ctx_log(ctx, 0, "Login to token failed, returning NULL...\n");
                        goto error;
                    }
                }
                else
                {
                    ctx_log(ctx, 0, "Multiple matching slots (%lu); will not try to"
                                    " login\n",
                            matched_count);
                    for (m = 0; m < matched_count; m++)
                    {
                        slot = matched_slots[m];
                        ctx_log(ctx, 0, "- [%u] %s: %s\n", m + 1,
                                slot->description ? slot->description : "(no description)",
                                (slot->token && slot->token->label) ? slot->token->label : "no label");
                    }
                    PROVerr(PROV_CTX_LOGIN, PROV_R_SLOT_AMBIGUOUS);
                    goto error;
                }
            }
        }

        object = match_func(ctx, tok, obj_id, obj_id_len, obj_label);
        if (object)
            break;
    }

error:
    /* Free the searched token data */
    if (match_tok)
    {
        OPENSSL_free(match_tok->model);
        OPENSSL_free(match_tok->manufacturer);
        OPENSSL_free(match_tok->serialnr);
        OPENSSL_free(match_tok->label);
        OPENSSL_free(match_tok);
    }

    if (obj_label)
        OPENSSL_free(obj_label);
    if (matched_slots)
        free(matched_slots);
    return object;
}

static void* ctx_load_object(PROVIDER_CTX* ctx,
                             const char* object_typestr,
                             void* (*match_func)(PROVIDER_CTX*, PKCS11_TOKEN*,
                                                 const unsigned char*, size_t, const char*),
                             const char* object_uri, OSSL_PASSPHRASE_CALLBACK* pw_cb, void* pw_cbarg)
{
    void* obj = NULL;

    pthread_mutex_lock(&ctx->lock);

    /* Delayed libp11 initialization */
    if (ctx_init_libp11_unlocked(ctx))
    {
        PROVerr(PROV_F_CTX_LOAD_OBJECT, PROV_R_INVALID_PARAMETER);
        pthread_mutex_unlock(&ctx->lock);
        return NULL;
    }

    if (!ctx->force_login)
    {
        ERR_clear_error();
        obj = ctx_try_load_object(ctx, object_typestr, match_func,
                                  object_uri, 0, pw_cb, pw_cbarg);
    }

    if (!obj)
    {
        /* Try again with login */
        ERR_clear_error();
        obj = ctx_try_load_object(ctx, object_typestr, match_func,
                                  object_uri, 1, pw_cb, pw_cbarg);
        if (!obj)
        {
            ctx_log(ctx, 0, "The %s was not found at: %s\n",
                    object_typestr, object_uri);
        }
    }

    pthread_mutex_unlock(&ctx->lock);
    return obj;
}

/******************************************************************************/
/* Private and public key handling                                            */
/******************************************************************************/

static void* match_key(PROVIDER_CTX* ctx, const char* key_type,
                       PKCS11_KEY* keys, unsigned int key_count,
                       const unsigned char* obj_id, size_t obj_id_len, const char* obj_label)
{
    PKCS11_KEY* selected_key = NULL;
    unsigned int m;
    const char* which;

    if (key_count == 0)
        return NULL;

    ctx_log(ctx, 1, "Found %u %s key%s:\n", key_count, key_type,
            key_count == 1 ? "" : "s");

    if (obj_id_len != 0 || obj_label)
    {
        which = "last matching";
        for (m = 0; m < key_count; m++)
        {
            PKCS11_KEY* k = keys + m;

            ctx_log(ctx, 1, "  %2u %c%c id=", m + 1,
                    k->isPrivate ? 'P' : ' ',
                    k->needLogin ? 'L' : ' ');
            dump_hex(ctx, 1, k->id, k->id_len);
            ctx_log(ctx, 1, " label=%s\n", k->label ? k->label : "(null)");

            if (obj_label && obj_id_len != 0)
            {
                if (k->label && strcmp(k->label, obj_label) == 0 && k->id_len == obj_id_len && memcmp(k->id, obj_id, obj_id_len) == 0)
                {
                    selected_key = k;
                }
            }
            else if (obj_label && !obj_id_len)
            {
                if (k->label && strcmp(k->label, obj_label) == 0)
                {
                    selected_key = k;
                }
            }
            else if (obj_id_len && !obj_label)
            {
                if (k->id_len == obj_id_len && memcmp(k->id, obj_id, obj_id_len) == 0)
                {
                    selected_key = k;
                }
            }
        }
    }
    else
    {
        which = "first";
        selected_key = keys; /* Use the first key */
    }

    if (selected_key)
    {
        ctx_log(ctx, 1, "Returning %s %s key: id=", which, key_type);
        dump_hex(ctx, 1, selected_key->id, selected_key->id_len);
        ctx_log(ctx, 1, " label=%s\n", selected_key->label ? selected_key->label : "(null)");
    }
    else
    {
        ctx_log(ctx, 1, "No matching %s key returned.\n", key_type);
    }

    return selected_key;
}

static void* match_public_key(PROVIDER_CTX* ctx, PKCS11_TOKEN* tok,
                              const unsigned char* obj_id, size_t obj_id_len, const char* obj_label)
{
    PKCS11_KEY* keys;
    unsigned int key_count;

    /* Make sure there is at least one public key on the token */
    if (PKCS11_enumerate_public_keys(tok, &keys, &key_count))
    {
        ctx_log(ctx, 0, "Unable to enumerate public keys\n");
        return 0;
    }
    return match_key(ctx, "public", keys, key_count, obj_id, obj_id_len, obj_label);
}

static void* match_private_key(PROVIDER_CTX* ctx, PKCS11_TOKEN* tok,
                               const unsigned char* obj_id, size_t obj_id_len, const char* obj_label)
{
    PKCS11_KEY* keys;
    unsigned int key_count;

    /* Make sure there is at least one private key on the token */
    if (PKCS11_enumerate_keys(tok, &keys, &key_count))
    {
        ctx_log(ctx, 0, "Unable to enumerate private keys\n");
        return 0;
    }
    return match_key(ctx, "private", keys, key_count, obj_id, obj_id_len, obj_label);
}

EVP_PKEY* ctx_load_pubkey(PROVIDER_CTX* ctx, const char* s_key_id,
                          OSSL_PASSPHRASE_CALLBACK* pw_cb, void* pw_cbarg)
{
    PKCS11_KEY* key;

    key = ctx_load_object(ctx, "public key", match_public_key, s_key_id,
                          pw_cb, pw_cbarg);
    if (!key)
    {
        ctx_log(ctx, 0, "PKCS11_load_public_key returned NULL\n");
        if (!ERR_peek_last_error())
            PROVerr(PROV_F_CTX_LOAD_PUBKEY, PROV_R_OBJECT_NOT_FOUND);
        return NULL;
    }
    return PKCS11_get_public_key(key);
}

EVP_PKEY* ctx_load_privkey(PROVIDER_CTX* ctx, const char* s_key_id,
                           OSSL_PASSPHRASE_CALLBACK* pw_cb, void* pw_cbarg)
{
    PKCS11_KEY* key;

    key = ctx_load_object(ctx, "private key", match_private_key, s_key_id,
                          pw_cb, pw_cbarg);
    if (!key)
    {
        ctx_log(ctx, 0, "PKCS11_get_private_key returned NULL\n");
        if (!ERR_peek_last_error())
            PROVerr(PROV_F_CTX_LOAD_PRIVKEY, PROV_R_OBJECT_NOT_FOUND);
        return NULL;
    }
    return PKCS11_get_private_key(key);
}

/******************************************************************************/
/*                                                                            */
/******************************************************************************/

/**
 * Set the PIN used for login. A copy of the PIN shall be made.
 *
 * If the PIN cannot be assigned, the value 0 shall be returned
 * and errno shall be set as follows:
 *
 *   EINVAL - a NULL PIN was supplied
 *   ENOMEM - insufficient memory to copy the PIN
 *
 * @param pin the pin to use for login. Must not be NULL.
 *
 * @return 1 on success, 0 on failure.
 */
static int ctx_ctrl_set_pin(PROVIDER_CTX* ctx, const char* pin)
{
    /* Pre-condition check */
    if (!pin)
    {
        PROVerr(PROV_F_CTX_CTRL_SET_PIN, ERR_R_PASSED_NULL_PARAMETER);
        errno = EINVAL;
        return 0;
    }

    /* Copy the PIN. If the string cannot be copied, NULL
     * shall be returned and errno shall be set. */
    ctx_destroy_pin(ctx);
    ctx->pin = OPENSSL_strdup(pin);
    if (!ctx->pin)
    {
        PROVerr(PROV_F_CTX_CTRL_SET_PIN, ERR_R_MALLOC_FAILURE);
        errno = ENOMEM;
        return 0;
    }
    ctx->pin_length = strlen(ctx->pin);
    ctx->forced_pin = 1;
    return 1;
}
