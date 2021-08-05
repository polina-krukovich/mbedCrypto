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
*   @file hmac_sha1.c
*   @brief File contains HMAC implementation.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.04
*/

#include "hmac.h"

#define IPAD_BYTE                   (U8(0x36))
#define OPAD_BYTE                   (U8(0x5C))

#define HMAC_MAX_BLOCK_SIZE         (128)

static uint32_t get_hash_block_size_by_hash_type(mbcrypt_hash_type_e hash_type)
{
    uint32_t block_size = HMAC_MAX_BLOCK_SIZE;

    if (hash_type == MBCRYPT_HASH_TYPE_SHA1)
    {
        block_size = 64;
    } 
    else if (hash_type == MBCRYPT_HASH_TYPE_SHA256)
    {
        block_size = 64;
    } 
    else if (hash_type == MBCRYPT_HASH_TYPE_SHA512)
    {
        block_size = 128;
    }
    return block_size;
}

mbcrypt_status_e MBCRYPT_API mbcrypt_hmac_init(mbcrypt_hmac_t *ctx,
                                        const uint8_t *key, uint32_t key_len)
{
MBCRYPT_FUNCTION_BEGIN;

    uint8_t ipad_xor_arr[HMAC_MAX_BLOCK_SIZE];

    MBCRYPT_CHECK_VALID_NOT_NULL(ctx);
    MBCRYPT_CHECK_VALID_NOT_NULL(ctx->cbs);
    MBCRYPT_CHECK_VALID_NOT_NULL(key);

    /* aliasing */
    void *hash_ctx = ctx->cbs->hash_ctx;
    mbcrypt_hash_init_t p_hash_init = ctx->cbs->hash_init;
    mbcrypt_hash_update_t p_hash_update = ctx->cbs->hash_update;
    mbcrypt_hash_final_t p_hash_final = ctx->cbs->hash_final;

    uint32_t block_size = get_hash_block_size_by_hash_type(ctx->hash_type);
    /* full fill array with ipad */
    MBCRYPT_CHECK_VALID_NOT_NULL(memset(ctx->key, 0x00, HMAC_MAX_KEY_SIZE));

    MBCRYPT_CHECK_VALID_NOT_NULL(memset(ipad_xor_arr, IPAD_BYTE, block_size));

    if (key_len > block_size)
    {

        MBCRYPT_CHECK_RES(p_hash_init(hash_ctx));
        MBCRYPT_CHECK_RES(p_hash_update(hash_ctx, key, key_len));
        MBCRYPT_CHECK_RES(p_hash_final(hash_ctx, ctx->key));
        key_len = GET_HASH_SIZE_BY_HASH_TYPE(ctx->hash_type);
    }
    else 
    {
        MBCRYPT_CHECK_VALID_NOT_NULL(memcpy(ctx->key, key, key_len));
    }

    MBCRYPT_CHECK_RES(p_hash_init(hash_ctx));

    /* xor IPAD and key */
#if (HMAC_MIN_SIZE == ENABLED)
    mem_xor(ipad_xor_arr, ctx->key, block_size);
#else /* HMAC_MIN_SIZE */
    for (uint32_t i = 0; i < block_size;)
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
#endif /* HMAC_MIN_SIZE */

    MBCRYPT_CHECK_RES(p_hash_update(hash_ctx, ipad_xor_arr, block_size));


MBCRYPT_FUNCTION_EXIT:

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL)
    memset_safe(ipad_xor_arr, MAX_BYTE_VALUE, sizeof(ipad_xor_arr));
#endif /* MBCRYPT_LEVEL */

    MBCRYPT_FUNCTION_RETURN;
}

mbcrypt_status_e MBCRYPT_API mbcrypt_hmac_update(mbcrypt_hmac_t *ctx, const uint8_t *data, uint32_t data_len)
{
MBCRYPT_FUNCTION_BEGIN;

    MBCRYPT_CHECK_VALID_NOT_NULL(ctx);
    MBCRYPT_CHECK_VALID_NOT_NULL(data);

    void *hash_ctx = ctx->cbs->hash_ctx;
    mbcrypt_hash_update_t p_hash_update = ctx->cbs->hash_update;

    uint32_t block_size = get_hash_block_size_by_hash_type(ctx->hash_type);

    if (data_len == 0)
    {
        MBCRYPT_FUNCTION_RET_VAR = MBCRYPT_STATUS_FAIL_INCORRECT_FUNCTION_PARAM;
        goto MBCRYPT_FUNCTION_EXIT;
    }

    MBCRYPT_CHECK_RES(p_hash_update(hash_ctx, data, data_len));


MBCRYPT_FUNCTION_EXIT:
    MBCRYPT_FUNCTION_RETURN;
}


mbcrypt_status_e mbcrypt_hmac_final(mbcrypt_hmac_t *ctx, uint8_t *out)
{
MBCRYPT_FUNCTION_BEGIN;

    uint8_t opad_xor_arr[HMAC_MAX_BLOCK_SIZE];
    
    MBCRYPT_CHECK_VALID_NOT_NULL(ctx);
    MBCRYPT_CHECK_VALID_NOT_NULL(out);

    void *hash_ctx = ctx->cbs->hash_ctx;
    uint32_t hash_size = GET_HASH_SIZE_BY_HASH_TYPE(ctx->hash_type);

    mbcrypt_hash_init_t p_hash_init = ctx->cbs->hash_init;
    mbcrypt_hash_update_t p_hash_update = ctx->cbs->hash_update;
    mbcrypt_hash_final_t p_hash_final = ctx->cbs->hash_final;

    uint32_t block_size = get_hash_block_size_by_hash_type(ctx->hash_type);
    

    MBCRYPT_CHECK_VALID_NOT_NULL(memset(opad_xor_arr, 
                                    OPAD_BYTE, sizeof(opad_xor_arr)));
    /* xor OPAD and key */
#if (HMAC_MIN_SIZE == ENABLED)
    mem_xor(opad_xor_arr, ctx->key, block_size);
#else /* HMAC_MIN_SIZE */
    for (uint32_t i = 0; i < block_size;)
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
#endif /* HMAC_MIN_SIZE */

    MBCRYPT_CHECK_RES(p_hash_final(hash_ctx, out));
    
    MBCRYPT_CHECK_RES(p_hash_init(hash_ctx));
    MBCRYPT_CHECK_RES(p_hash_update(hash_ctx, opad_xor_arr, block_size));
    MBCRYPT_CHECK_RES(p_hash_update(hash_ctx, out, hash_size));
    MBCRYPT_CHECK_RES(p_hash_final(hash_ctx, out));


MBCRYPT_FUNCTION_EXIT:

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL)
    memset_safe(opad_xor_arr, MAX_BYTE_VALUE, sizeof(opad_xor_arr));
    if (MBCRYPT_FUNCTION_RET_VAR != MBCRYPT_STATUS_OK)
    {
        memset_safe(out, MAX_BYTE_VALUE, hash_size);
    }
#endif /* MBCRYPT_LEVEL */

    MBCRYPT_FUNCTION_RETURN;
}

mbcrypt_status_e MBCRYPT_API mbcrypt_hmac(mbcrypt_hash_type_e hash_type, mbcrypt_hash_callbacks_t *cbs,
                                    const uint8_t *key, uint32_t key_len, 
                                    const uint8_t *data, uint32_t data_len, 
                                    uint8_t *out)
{
MBCRYPT_FUNCTION_BEGIN;

    mbcrypt_hmac_t ctx;
    
    MBCRYPT_CHECK_VALID_NOT_NULL(memset(&ctx, 0x00, sizeof(mbcrypt_hmac_t)));
    
    ctx.hash_type = hash_type;
    ctx.cbs = cbs;

    MBCRYPT_CHECK_RES(mbcrypt_hmac_init(&ctx, key, key_len));
    MBCRYPT_CHECK_RES(mbcrypt_hmac_update(&ctx, data, data_len));
    MBCRYPT_CHECK_RES(mbcrypt_hmac_final(&ctx, out));


MBCRYPT_FUNCTION_EXIT:

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL)
    memset_safe(&ctx, MAX_BYTE_VALUE, sizeof(ctx));
#endif /* MBCRYPT_LEVEL */

    MBCRYPT_FUNCTION_RETURN;
}
