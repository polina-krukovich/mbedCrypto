#include "pbkdf2.h"


#define PBKDF2_HMAC_SHA1_BUFFER_SIZE            (32)
#define PBKDF2_HMAC_SHA256_BUFFER_SIZE          (64)
#define PBKDF2_HMAC_SHA512_BUFFER_SIZE          (128)
#define PBKDF2_HMAC_MAX_BUFFER_SIZE             (PBKDF2_HMAC_SHA512_BUFFER_SIZE)

typedef uint32_t (*hmac_init_t)(void *, const uint8_t *, uint32_t );
typedef uint32_t (*hmac_update_t)(void *, const uint8_t *, uint32_t );
typedef uint32_t (*hmac_finish_t)(void *, const uint8_t *);



static security_status_e pbkdf2_hmac(void *ctx, hmac_init_t hmac_init,
                                        hmac_update_t hmac_update, 
                                        hmac_finish_t hmac_finish,
                                        uint32_t hmac_size, const uint8_t *password, 
                                        uint32_t pass_len, const uint8_t *salt, 
                                        uint32_t salt_len, uint32_t iters, 
                                        uint8_t *out, uint32_t out_len)
{
SECURITY_FUNCTION_BEGIN;

    uint8_t U[PBKDF2_HMAC_MAX_BUFFER_SIZE];
    uint8_t T[PBKDF2_HMAC_MAX_BUFFER_SIZE];
    uint32_t U_len = hmac_size;

    uint8_t *out_p = out;
    uint8_t ctr[4];

    uint32_t use_len;
    uint32_t ctr_len = sizeof(ctr) / sizeof(uint8_t);

    /* check input params */
    SECURITY_CHECK_VALID_NOT_NULL(password);
    SECURITY_CHECK_VALID_NOT_NULL(salt);
    SECURITY_CHECK_VALID_NOT_NULL(out);

    if (!pass_len || !salt_len || !out_len || !iters)
    {
        SECURITY_FUNCTION_RET_VAR = SECURITY_STATUS_FAIL_INCORRECT_FUNCTION_PARAM;
        goto SECURITY_FUNCTION_EXIT;
    }


    SECURITY_CHECK_VALID_NOT_NULL(memset(ctr, 0x00, ctr_len));

    /* by default ctr = 1 */
    /* LE is used */
    ctr[3] = 1;

    while (out_len != 0)
    {
        /* salt||ctr */
        SECURITY_CHECK_RES(hmac_init(ctx, password, pass_len));
        SECURITY_CHECK_RES(hmac_update(ctx, salt, salt_len));
        SECURITY_CHECK_RES(hmac_update(ctx, ctr, ctr_len));
        SECURITY_CHECK_RES(hmac_finish(ctx, T));
        
        
    
        SECURITY_CHECK_VALID_NOT_NULL(memcpy(U, T, U_len));

        SECURITY_CHECK_RES(hmac_init(ctx, password, pass_len));
        
        for(uint32_t i = 1; i < iters; ++i)
        {   
            /* Uj= HMAC(P, Uj-1) */
            SECURITY_CHECK_RES(hmac_update(ctx, U, U_len));
            SECURITY_CHECK_RES(hmac_finish(ctx, U));
            SECURITY_CHECK_RES(hmac_init(ctx, password, pass_len));
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
        SECURITY_CHECK_VALID_NOT_NULL(memcpy(out_p, T, use_len));

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


SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL)  \
    || defined(SECURED_PBKDF2_HMAC_SHA1)    \
    || defined(SECURED_PBKDF2_HMAC_SHA256)  \
    || defined(SECURED_PBKDF2_HMAC_SHA512)  \

    /* Clean local data*/
    memset_safe(U, MAX_BYTE_VALUE, sizeof(U));
    memset_safe(T, MAX_BYTE_VALUE, sizeof(T));
    out_p = MAX_WORD_VALUE;
    memset_safe(ctr, MAX_BYTE_VALUE, sizeof(ctr));

#endif /* SECURITY_LEVEL == MAX_SECURITY_LEVEL */

    SECURITY_FUNCTION_RETURN;
}



/*=============================== PBKDF2_HMAC_SHA1 ===============================*/
#if (PBKDF2_HMAC_SHA1 == ENABLED)

#include "hmac_sha1.h"

security_status_e pbkdf2_hmac_sha1(const uint8_t *password, uint32_t pass_len,
                                    const uint8_t *salt, uint32_t salt_len, 
                                    uint32_t iters, uint8_t *out, uint32_t out_len)
{
SECURITY_FUNCTION_BEGIN;
    
    hmac_sha1_t hmac;

    SECURITY_CHECK_RES(
        pbkdf2_hmac(&hmac, hmac_sha1_init, hmac_sha1_update, hmac_sha1_finish,
                HMAC_SHA1_HASH_SIZE, password, pass_len, salt, salt_len, iters,
                out, out_len)
    );

    
SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || defined(SECURED_PBKDF2_HMAC_SHA1)    
    memset_safe(&hmac, MAX_BYTE_VALUE, sizeof(hmac));
#endif /* SECURITY_LEVEL == MAX_SECURITY_LEVEL */

    SECURITY_FUNCTION_RETURN;
}

#endif /* (PBKDF2_HMAC_SHA1 == ENABLED) */



/*=============================== PBKDF2_HMAC_SHA256 ===============================*/
#if (PBKDF2_HMAC_SHA256 == ENABLED)

#include "hmac_sha256.h"

security_status_e pbkdf2_hmac_sha256(const uint8_t *password, uint32_t pass_len,
                                    const uint8_t *salt, uint32_t salt_len, 
                                    uint32_t iters, uint8_t *out, uint32_t out_len)
{
SECURITY_FUNCTION_BEGIN;
    
    hmac_sha256_t hmac;

    SECURITY_CHECK_RES(
        pbkdf2_hmac(&hmac, hmac_sha256_init, hmac_sha256_update, hmac_sha256_finish,
                HMAC_SHA256_HASH_SIZE, password, pass_len, salt, salt_len, iters,
                out, out_len)
    );

    
SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || defined(SECURED_PBKDF2_HMAC_SHA256)    
    memset_safe(&hmac, MAX_BYTE_VALUE, sizeof(hmac));
#endif /* SECURITY_LEVEL == MAX_SECURITY_LEVEL */

    SECURITY_FUNCTION_RETURN;
}

#endif /* (PBKDF2_HMAC_SHA256 == ENABLED) */



/*=============================== PBKDF2_HMAC_SHA512 ===============================*/
#if (PBKDF2_HMAC_SHA512 == ENABLED)

#include "hmac_sha512.h"

security_status_e pbkdf2_hmac_sha512(const uint8_t *password, uint32_t pass_len,
                                    const uint8_t *salt, uint32_t salt_len, 
                                    uint32_t iters, uint8_t *out, uint32_t out_len)
{
SECURITY_FUNCTION_BEGIN;
    
    hmac_sha512_t hmac;

    SECURITY_CHECK_RES(
        pbkdf2_hmac(&hmac, hmac_sha512_init, hmac_sha512_update, hmac_sha512_finish,
                HMAC_SHA512_HASH_SIZE, password, pass_len, salt, salt_len, iters,
                out, out_len)
    );

    
SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || defined(SECURED_PBKDF2_HMAC_SHA512)    
    memset_safe(&hmac, MAX_BYTE_VALUE, sizeof(hmac));
#endif /* SECURITY_LEVEL == MAX_SECURITY_LEVEL */

    SECURITY_FUNCTION_RETURN;
}

#endif /* (PBKDF2_HMAC_SHA512 == ENABLED) */

