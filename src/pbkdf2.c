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
*   @file pbkdf2.c
*   @brief File contains PBKDF2 implementation.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.04
*/

#include "pbkdf2.h"


#define PBKDF2_HMAC_MAX_BUFFER_SIZE             (128)

mbcrypt_status_e mbcrypt_pbkdf2_hmac(mbcrypt_hash_type_e hash_type, mbcrypt_hmac_callbacks_t *cbs,
                                        const uint8_t *password, uint32_t pass_len, 
                                        const uint8_t *salt, uint32_t salt_len, 
                                        uint32_t iters,
                                        uint8_t *out, uint32_t out_len)
{
MBCRYPT_FUNCTION_BEGIN;

    uint8_t U[PBKDF2_HMAC_MAX_BUFFER_SIZE];
    uint8_t T[PBKDF2_HMAC_MAX_BUFFER_SIZE];
    uint32_t U_len = GET_HASH_SIZE_BY_HASH_TYPE(hash_type);

    uint8_t *out_p = out;
    uint8_t ctr[4];

    uint32_t use_len;
    uint32_t ctr_len = sizeof(ctr) / sizeof(uint8_t);

    /* check input params */
    MBCRYPT_CHECK_VALID_NOT_NULL(password);
    MBCRYPT_CHECK_VALID_NOT_NULL(salt);
    MBCRYPT_CHECK_VALID_NOT_NULL(out);

    void *ctx = cbs->hmac_ctx;
    mbcrypt_hmac_init_t p_hmac_init = cbs->hmac_init;
    mbcrypt_hmac_update_t p_hmac_update = cbs->hmac_update;
    mbcrypt_hmac_final_t p_hmac_final = cbs->hmac_final;

    if (!pass_len || !salt_len || !out_len || !iters)
    {
        MBCRYPT_FUNCTION_RET_VAR = MBCRYPT_STATUS_FAIL_INCORRECT_FUNCTION_PARAM;
        goto MBCRYPT_FUNCTION_EXIT;
    }

    MBCRYPT_CHECK_VALID_NOT_NULL(memset(ctr, 0x00, ctr_len));

    /* by default ctr = 1 */
    /* LE is used */
    ctr[3] = 1;

    while (out_len != 0)
    {
        /* salt||ctr */
        MBCRYPT_CHECK_RES(p_hmac_init(ctx, password, pass_len));

        MBCRYPT_CHECK_RES(p_hmac_update(ctx, salt, salt_len));
        MBCRYPT_CHECK_RES(p_hmac_update(ctx, ctr, ctr_len));
        MBCRYPT_CHECK_RES(p_hmac_final(ctx, T));
        
        MBCRYPT_CHECK_VALID_NOT_NULL(memcpy(U, T, U_len));

        MBCRYPT_CHECK_RES(p_hmac_init(ctx, password, pass_len));

        for(uint32_t i = 1; i < iters; ++i)
        {   
            /* Uj= HMAC(P, Uj-1) */
            MBCRYPT_CHECK_RES(p_hmac_update(ctx, U, U_len));
            MBCRYPT_CHECK_RES(p_hmac_final(ctx, U));
            MBCRYPT_CHECK_RES(p_hmac_init(ctx, password, pass_len));
            /* Ti = Ti xor Uj */
#if (PBKDF2_MIN_SIZE == ENABLED)

    /* If mem_xor if defined */
    #ifdef mem_xor
            mem_xor(T, U, U_len);
    #else   /* mem_xor */
            for(uint32_t j = 0; j < U_len; ++j)
            {
                T[j] ^= U[j];
            }
    #endif /* mem_xor */

#else /* PBKDF2_MIN_SIZE */
        for(uint32_t j = 0; j < U_len;)
        {
            T[j] ^= U[j], ++j;
            T[j] ^= U[j], ++j;
            T[j] ^= U[j], ++j;
            T[j] ^= U[j], ++j;
            T[j] ^= U[j], ++j;
            T[j] ^= U[j], ++j;
            T[j] ^= U[j], ++j;
            T[j] ^= U[j], ++j;
        }
#endif /* PBKDF2_MIN_SIZE */
        }

        use_len = (out_len < U_len) ? out_len : U_len;
        /* mk = T1 || T2 || … || Tlen<0…r-1> */
        MBCRYPT_CHECK_VALID_NOT_NULL(memcpy(out_p, T, use_len));

        /* next counter for new iter */
        out_len -= U32(use_len);
        out_p += use_len;
        /* if overflow happens then next byte + 1*/
        for(uint32_t i = 3; i > 0; --i)
        {
            ++ctr[i];
            if(ctr[i] != 0)
            {
                break;
            }
        }
    }


MBCRYPT_FUNCTION_EXIT:

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL)  \
    || defined(SECURED_PBKDF2_HMAC_SHA1)    \
    || defined(SECURED_PBKDF2_HMAC_SHA256)  \
    || defined(SECURED_PBKDF2_HMAC_SHA512)  \

    /* Clean local data*/
    memset_safe(U, MAX_BYTE_VALUE, sizeof(U));
    memset_safe(T, MAX_BYTE_VALUE, sizeof(T));
    out_p = MAX_WORD_VALUE;
    memset_safe(ctr, MAX_BYTE_VALUE, sizeof(ctr));

#endif /* MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL */

    MBCRYPT_FUNCTION_RETURN;
}
