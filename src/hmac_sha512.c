/****************************INFORMATION***********************************
* Copyright (c) 2021 Zontec
* Email: dehibeo@gmail.com
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
**************************************************************************/
/*!
*   @file hmac_sha512.c
*   @brief File contains HMAC SHA-512 implementation.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.04
*/

#include "hmac_sha512.h"

#define IPAD_BYTE           (U8(0x36))
#define OPAD_BYTE           (U8(0x5C))

#if (HMAC_SHA512_MIN_SIZE == ENABLED)
    #ifndef mem_xor
        #error "mem_xor not defined. See mem_xor interface in security.h"
    #endif /* mem_xor */
#endif /* HMAC_SHA512_MIN_SIZE */

security_status_e hmac_sha512_init(hmac_sha512_t *ctx, const uint8_t *key, 
                                    uint32_t key_len)
{
SECURITY_FUNCTION_BEGIN;

    uint8_t ipad_xor_arr[HMAC_SHA512_BLOCK_SIZE];

    SECURITY_CHECK_VALID_NOT_NULL(ctx);
    SECURITY_CHECK_VALID_NOT_NULL(key);

    SECURITY_CHECK_VALID_NOT_NULL(memset(ipad_xor_arr, 
                                IPAD_BYTE, sizeof(ipad_xor_arr)));
    SECURITY_CHECK_VALID_NOT_NULL(memset(ctx, 0x00, sizeof(hmac_sha512_t)));

    SECURITY_CHECK_RES(sha512_init(&ctx->sha_ctx));

    /* if key_len < HMAC_SHA512_BLOCK_SIZE we just copy data and pad with 0*/
    if (key_len > HMAC_SHA512_BLOCK_SIZE)
    {
        SECURITY_CHECK_RES(sha512(key, key_len, ctx->key));
    }
    else 
    {
        SECURITY_CHECK_VALID_NOT_NULL(memcpy(ctx->key, key, key_len));
    }

    /* xor IPAD and key */
#if (HMAC_SHA512_MIN_SIZE == ENABLED)
    mem_xor(ipad_xor_arr, ctx->key, HMAC_SHA512_BLOCK_SIZE);
#else /* HMAC_SHA512_MIN_SIZE */
    for (uint32_t i = 0; i < HMAC_SHA512_BLOCK_SIZE;)
    {
        ipad_xor_arr[i] = (ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        ipad_xor_arr[i] = (ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        ipad_xor_arr[i] = (ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        ipad_xor_arr[i] = (ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        ipad_xor_arr[i] = (ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        ipad_xor_arr[i] = (ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        ipad_xor_arr[i] = (ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        ipad_xor_arr[i] = (ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
    }
#endif /* HMAC_SHA512_MIN_SIZE */

    SECURITY_CHECK_RES(sha512_update(&ctx->sha_ctx, ipad_xor_arr, HMAC_SHA512_BLOCK_SIZE));


SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || (SECURED_HMAC_SHA512 == ENABLED)
    memset_safe(ipad_xor_arr, MAX_BYTE_VALUE, sizeof(ipad_xor_arr));
#endif /* SECURED_HMAC_SHA512 */

    SECURITY_FUNCTION_RETURN;
}


security_status_e hmac_sha512_update(hmac_sha512_t *ctx, const uint8_t *data, 
                                    uint32_t data_len)
{
SECURITY_FUNCTION_BEGIN;

    SECURITY_CHECK_VALID_NOT_NULL(ctx);
    SECURITY_CHECK_VALID_NOT_NULL(data);

    if (data_len == 0)
    {
        SECURITY_FUNCTION_RET_VAR = SECURITY_STATUS_FAIL_INCORRECT_FUNCTION_PARAM;
        goto SECURITY_FUNCTION_EXIT;
    }

    SECURITY_CHECK_RES(sha512_update(&ctx->sha_ctx, data, data_len));


SECURITY_FUNCTION_EXIT:
    SECURITY_FUNCTION_RETURN;
}


security_status_e hmac_sha512_finish(hmac_sha512_t *ctx, uint8_t *out)
{
SECURITY_FUNCTION_BEGIN;

    uint8_t opad_xor_arr[HMAC_SHA512_BLOCK_SIZE];

    SECURITY_CHECK_VALID_NOT_NULL(ctx);
    SECURITY_CHECK_VALID_NOT_NULL(out);

    SECURITY_CHECK_VALID_NOT_NULL(memset(opad_xor_arr, 
                                    OPAD_BYTE, sizeof(opad_xor_arr)));
    /* xor OPAD and key */
#if (HMAC_SHA512_MIN_SIZE == ENABLED)
    mem_xor(opad_xor_arr, ctx->key, HMAC_SHA512_BLOCK_SIZE);
#else /* HMAC_SHA512_MIN_SIZE */
    for (uint32_t i = 0; i < HMAC_SHA512_BLOCK_SIZE;)
    {
        opad_xor_arr[i] = (opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        opad_xor_arr[i] = (opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        opad_xor_arr[i] = (opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        opad_xor_arr[i] = (opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        opad_xor_arr[i] = (opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        opad_xor_arr[i] = (opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        opad_xor_arr[i] = (opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        opad_xor_arr[i] = (opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
    }
#endif /* HMAC_SHA512_MIN_SIZE */

    SECURITY_CHECK_RES(sha512_finish(&ctx->sha_ctx, out));
    
    SECURITY_CHECK_RES(sha512_init(&ctx->sha_ctx));
    SECURITY_CHECK_RES(sha512_update(&ctx->sha_ctx, opad_xor_arr, HMAC_SHA512_BLOCK_SIZE));
    SECURITY_CHECK_RES(sha512_update(&ctx->sha_ctx, out, HMAC_SHA512_HASH_SIZE));
    SECURITY_CHECK_RES(sha512_finish(&ctx->sha_ctx, out));


SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || (SECURED_HMAC_SHA512 == ENABLED)
    memset_safe(opad_xor_arr, MAX_BYTE_VALUE, sizeof(opad_xor_arr));
    if (SECURITY_FUNCTION_RET_VAR != SECURITY_STATUS_OK)
    {
        memset_safe(out, MAX_BYTE_VALUE, HMAC_SHA512_HASH_SIZE);
    }
#endif /* SECURED_HMAC_SHA512 */

    SECURITY_FUNCTION_RETURN;
}


security_status_e hmac_sha512(const uint8_t *key, uint32_t key_len, 
                            const uint8_t *data, uint32_t data_len, 
                            uint8_t *out)
{
SECURITY_FUNCTION_BEGIN;

    hmac_sha512_t ctx;

    SECURITY_CHECK_RES(hmac_sha512_init(&ctx, key, key_len));
    SECURITY_CHECK_RES(hmac_sha512_update(&ctx, data, data_len));
    SECURITY_CHECK_RES(hmac_sha512_finish(&ctx, out));


SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || (SECURED_HMAC_SHA512 == ENABLED)
    memset_safe(&ctx, MAX_BYTE_VALUE, sizeof(ctx));
#endif /* SECURED_HMAC_SHA512 */

    SECURITY_FUNCTION_RETURN;
}