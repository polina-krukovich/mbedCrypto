#include "hmac_sha1.h"

#define IPAD_BYTE           (U8(0x36))
#define OPAD_BYTE           (U8(0x5C))


security_status_e hmac_sha1_init(hmac_sha1_t *ctx, const uint8_t *key, 
                                    uint32_t key_len)
{
SECURITY_FUNCTION_BEGIN;

    uint8_t ipad_xor_arr[HMAC_SHA1_BLOCK_SIZE];

    SECURITY_CHECK_VALID_NOT_NULL(ctx);
    SECURITY_CHECK_VALID_NOT_NULL(key);

    SECURITY_CHECK_VALID_NOT_NULL(memset(ipad_xor_arr, 
                                IPAD_BYTE, sizeof(ipad_xor_arr)));
    SECURITY_CHECK_VALID_NOT_NULL(memset(ctx, 0x00, sizeof(hmac_sha1_t)));

    SECURITY_CHECK_RES(sha1_init(&ctx->sha_ctx));

    /* if key_len < HMAC_SHA1_BLOCK_SIZE we just copy data and pad with 0*/
    if (key_len > HMAC_SHA1_BLOCK_SIZE)
    {
        SECURITY_CHECK_RES(sha1(key, key_len, ctx->key));
    }
    else 
    {
        SECURITY_CHECK_VALID_NOT_NULL(memcpy(ctx->key, key, key_len));
    }

    /* xor IPAD and key */
    for (uint32_t i = 0; i < HMAC_SHA1_BLOCK_SIZE;)
    {
        ipad_xor_arr[i] = (uint8_t)(ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        ipad_xor_arr[i] = (uint8_t)(ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        ipad_xor_arr[i] = (uint8_t)(ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        ipad_xor_arr[i] = (uint8_t)(ipad_xor_arr[i] ^ ctx->key[i]);
        ++i;
    }

    SECURITY_CHECK_RES(sha1_update(&ctx->sha_ctx, ipad_xor_arr, HMAC_SHA1_BLOCK_SIZE));


SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || (SECURED_HMAC_SHA1 == ENABLED)
    memset_safe(ipad_xor_arr, MAX_BYTE_VALUE, sizeof(ipad_xor_arr));
#endif /* SECURED_HMAC_SHA1 */

    SECURITY_FUNCTION_RETURN;
}


security_status_e hmac_sha1_update(hmac_sha1_t *ctx, const uint8_t *data, 
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

    SECURITY_CHECK_RES(sha1_update(&ctx->sha_ctx, data, data_len));


SECURITY_FUNCTION_EXIT:
    SECURITY_FUNCTION_RETURN;
}


security_status_e hmac_sha1_finish(hmac_sha1_t *ctx, uint8_t *out)
{
SECURITY_FUNCTION_BEGIN;

    uint8_t opad_xor_arr[HMAC_SHA1_BLOCK_SIZE];

    SECURITY_CHECK_VALID_NOT_NULL(ctx);
    SECURITY_CHECK_VALID_NOT_NULL(out);

    SECURITY_CHECK_VALID_NOT_NULL(memset(opad_xor_arr, 
                                    OPAD_BYTE, sizeof(opad_xor_arr)));
    /* xor OPAD and key */
    for (uint32_t i = 0; i < HMAC_SHA1_BLOCK_SIZE;)
    {
        opad_xor_arr[i] = U8(opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        opad_xor_arr[i] = U8(opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        opad_xor_arr[i] = U8(opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
        opad_xor_arr[i] = U8(opad_xor_arr[i] ^ ctx->key[i]);
        ++i;
    }

    SECURITY_CHECK_RES(sha1_finish(&ctx->sha_ctx, out));
    
    SECURITY_CHECK_RES(sha1_init(&ctx->sha_ctx));
    SECURITY_CHECK_RES(sha1_update(&ctx->sha_ctx, opad_xor_arr, HMAC_SHA1_BLOCK_SIZE));
    SECURITY_CHECK_RES(sha1_update(&ctx->sha_ctx, out, HMAC_SHA1_HASH_SIZE));
    SECURITY_CHECK_RES(sha1_finish(&ctx->sha_ctx, out));


SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || (SECURED_HMAC_SHA1 == ENABLED)
    memset_safe(opad_xor_arr, MAX_BYTE_VALUE, sizeof(opad_xor_arr));
    if (SECURITY_FUNCTION_RET_VAR != SECURITY_STATUS_OK)
    {
        memset_safe(out, MAX_BYTE_VALUE, HMAC_SHA1_HASH_SIZE);
    }
#endif /* SECURED_HMAC_SHA1 */

    SECURITY_FUNCTION_RETURN;
}


security_status_e hmac_sha1(const uint8_t *key, uint32_t key_len, 
                            const uint8_t *data, uint32_t data_len, 
                            uint8_t *out)
{
SECURITY_FUNCTION_BEGIN;

    hmac_sha1_t ctx;

    SECURITY_CHECK_RES(hmac_sha1_init(&ctx, key, key_len));
    SECURITY_CHECK_RES(hmac_sha1_update(&ctx, data, data_len));
    SECURITY_CHECK_RES(hmac_sha1_finish(&ctx, out));


SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || (SECURED_HMAC_SHA1 == ENABLED)
    memset_safe(&ctx, MAX_BYTE_VALUE, sizeof(ctx));
#endif /* SECURED_HMAC_SHA1 */

    SECURITY_FUNCTION_RETURN;
}