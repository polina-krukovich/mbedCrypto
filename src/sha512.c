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
*   @file sha512.c
*   @brief File contains SHA-512 implementation.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.04
*/

#include "sha512.h"

#define SHIFT_RIGHT(x, n)   (x >> n)
#define ROT_RIGHT(x, n)     (SHIFT_RIGHT(x,n) | (x << (64 - n)))

#define SUB0(x)             (ROT_RIGHT(x, 1) ^ ROT_RIGHT(x, 8) ^  SHIFT_RIGHT(x, 7))
#define SUB1(x)             (ROT_RIGHT(x, 19) ^ ROT_RIGHT(x, 61) ^  SHIFT_RIGHT(x, 6))
#define SUB2(x)             (ROT_RIGHT(x, 28) ^ ROT_RIGHT(x, 34) ^ ROT_RIGHT(x, 39))
#define SUB3(x)             (ROT_RIGHT(x, 14) ^ ROT_RIGHT(x, 18) ^ ROT_RIGHT(x, 41))

#define F0(x, y, z)         ((x & y) | (z & (x | y)))
#define F1(x, y, z)         (z ^ (x & (y ^ z)))

#define PAD(a, b, c, d, e, f, g, h, x, _K)           \
{                                                   \
    tmp1 = h + SUB3(e) + F1(e, f, g) + _K + x;       \
    tmp2 = SUB2(a) + F0(a, b, c);                   \
    d += tmp1;                                      \
    h = tmp1 + tmp2;                                \
}


static const uint64_t _K[80] =
{
    U64(0x428A2F98D728AE22),  U64(0x7137449123EF65CD),
    U64(0xB5C0FBCFEC4D3B2F),  U64(0xE9B5DBA58189DBBC),
    U64(0x3956C25BF348B538),  U64(0x59F111F1B605D019),
    U64(0x923F82A4AF194F9B),  U64(0xAB1C5ED5DA6D8118),
    U64(0xD807AA98A3030242),  U64(0x12835B0145706FBE),
    U64(0x243185BE4EE4B28C),  U64(0x550C7DC3D5FFB4E2),
    U64(0x72BE5D74F27B896F),  U64(0x80DEB1FE3B1696B1),
    U64(0x9BDC06A725C71235),  U64(0xC19BF174CF692694),
    U64(0xE49B69C19EF14AD2),  U64(0xEFBE4786384F25E3),
    U64(0x0FC19DC68B8CD5B5),  U64(0x240CA1CC77AC9C65),
    U64(0x2DE92C6F592B0275),  U64(0x4A7484AA6EA6E483),
    U64(0x5CB0A9DCBD41FBD4),  U64(0x76F988DA831153B5),
    U64(0x983E5152EE66DFAB),  U64(0xA831C66D2DB43210),
    U64(0xB00327C898FB213F),  U64(0xBF597FC7BEEF0EE4),
    U64(0xC6E00BF33DA88FC2),  U64(0xD5A79147930AA725),
    U64(0x06CA6351E003826F),  U64(0x142929670A0E6E70),
    U64(0x27B70A8546D22FFC),  U64(0x2E1B21385C26C926),
    U64(0x4D2C6DFC5AC42AED),  U64(0x53380D139D95B3DF),
    U64(0x650A73548BAF63DE),  U64(0x766A0ABB3C77B2A8),
    U64(0x81C2C92E47EDAEE6),  U64(0x92722C851482353B),
    U64(0xA2BFE8A14CF10364),  U64(0xA81A664BBC423001),
    U64(0xC24B8B70D0F89791),  U64(0xC76C51A30654BE30),
    U64(0xD192E819D6EF5218),  U64(0xD69906245565A910),
    U64(0xF40E35855771202A),  U64(0x106AA07032BBD1B8),
    U64(0x19A4C116B8D2D0C8),  U64(0x1E376C085141AB53),
    U64(0x2748774CDF8EEB99),  U64(0x34B0BCB5E19B48A8),
    U64(0x391C0CB3C5C95A63),  U64(0x4ED8AA4AE3418ACB),
    U64(0x5B9CCA4F7763E373),  U64(0x682E6FF3D6B2B8A3),
    U64(0x748F82EE5DEFB2FC),  U64(0x78A5636F43172F60),
    U64(0x84C87814A1F0AB72),  U64(0x8CC702081A6439EC),
    U64(0x90BEFFFA23631E28),  U64(0xA4506CEBDE82BDE9),
    U64(0xBEF9A3F7B2C67915),  U64(0xC67178F2E372532B),
    U64(0xCA273ECEEA26619C),  U64(0xD186B8C721C0C207),
    U64(0xEADA7DD6CDE0EB1E),  U64(0xF57D4F7FEE6ED178),
    U64(0x06F067AA72176FBA),  U64(0x0A637DC5A2C898A6),
    U64(0x113F9804BEF90DAE),  U64(0x1B710B35131C471B),
    U64(0x28DB77F523047D84),  U64(0x32CAAB7B40C72493),
    U64(0x3C9EBE0A15C9BEBC),  U64(0x431D67C49C100D4C),
    U64(0x4CC5D4BECB3E42B6),  U64(0x597F299CFC657E2A),
    U64(0x5FCB6FAB3AD6FAEC),  U64(0x6C44198C4A475817)
};

static const uint8_t _sha512_padding[MBCRYPT_SHA512_BUFFER_SIZE] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


static void _sha512_process(mbcrypt_sha512_t *ctx, const uint8_t *data)
{
    uint64_t tmp1;
    uint64_t tmp2;
    uint64_t W[80];

    uint64_t A;
    uint64_t B;
    uint64_t C;
    uint64_t D;
    uint64_t E;
    uint64_t F;
    uint64_t G;
    uint64_t H;

    A = ctx->h0;
    B = ctx->h1;
    C = ctx->h2;
    D = ctx->h3;
    E = ctx->h4;
    F = ctx->h5;
    G = ctx->h6;
    H = ctx->h7;

#ifdef SHA512_MIN_SIZE

    uint32_t i = 0;

    for (i = 0; i < 16; ++i)
    {
        GET_UINT64_BE(W[i], data, i << 3);
    }

    for (; i < 80; ++i)
    {
        W[i] = SUB1(W[i - 2]) + W[i - 7] +
               SUB0(W[i - 15]) + W[i - 16];
    }
    
    i = 0;

    do
    {
        PAD(A, B, C, D, E, F, G, H, W[i], _K[i]); 
        ++i;
        PAD(H, A, B, C, D, E, F, G, W[i], _K[i]); 
        ++i;
        PAD(G, H, A, B, C, D, E, F, W[i], _K[i]); 
        ++i;
        PAD(F, G, H, A, B, C, D, E, W[i], _K[i]); 
        ++i;
        PAD(E, F, G, H, A, B, C, D, W[i], _K[i]); 
        ++i;
        PAD(D, E, F, G, H, A, B, C, W[i], _K[i]); 
        ++i;
        PAD(C, D, E, F, G, H, A, B, W[i], _K[i]); 
        ++i;
        PAD(B, C, D, E, F, G, H, A, W[i], _K[i]); 
        ++i;
    } while (i < 80);

#else /* SHA512_MIN_SIZE */

    uint32_t i = 16;

    GET_UINT64_BE(W[0], data, 0);
    GET_UINT64_BE(W[1], data, 8);
    GET_UINT64_BE(W[2], data, 16);
    GET_UINT64_BE(W[3], data, 24);
    GET_UINT64_BE(W[4], data, 32);
    GET_UINT64_BE(W[5], data, 40);
    GET_UINT64_BE(W[6], data, 48);
    GET_UINT64_BE(W[7], data, 56);
    GET_UINT64_BE(W[8], data, 64);
    GET_UINT64_BE(W[9], data, 72);
    GET_UINT64_BE(W[10], data,80);
    GET_UINT64_BE(W[11], data, 88);
    GET_UINT64_BE(W[12], data, 96);
    GET_UINT64_BE(W[13], data, 104);
    GET_UINT64_BE(W[14], data, 112);
    GET_UINT64_BE(W[15], data, 120);

#define TMP_BLOC_K \
{ \
    W[i] = SUB1(W[i - 2]) + W[i - 7] + SUB0(W[i - 15]) + W[i - 16]; \
    ++i; \
}  
    while (i < 80)
    {
        TMP_BLOC_K;
        TMP_BLOC_K;
        TMP_BLOC_K;
        TMP_BLOC_K;
        TMP_BLOC_K;
        TMP_BLOC_K;
        TMP_BLOC_K;
        TMP_BLOC_K;
    }
#undef TMP_BLOC_K
    
    i = 0;

    do
    {
        PAD(A, B, C, D, E, F, G, H, W[i], _K[i]); 
        ++i;
        PAD(H, A, B, C, D, E, F, G, W[i], _K[i]); 
        ++i;
        PAD(G, H, A, B, C, D, E, F, W[i], _K[i]); 
        ++i;
        PAD(F, G, H, A, B, C, D, E, W[i], _K[i]); 
        ++i;
        PAD(E, F, G, H, A, B, C, D, W[i], _K[i]); 
        ++i;
        PAD(D, E, F, G, H, A, B, C, W[i], _K[i]); 
        ++i;
        PAD(C, D, E, F, G, H, A, B, W[i], _K[i]); 
        ++i;
        PAD(B, C, D, E, F, G, H, A, W[i], _K[i]); 
        ++i;
    } while (i < 80);

#endif /* SHA512_MIN_SIZE */

    ctx->h0 += A;
    ctx->h1 += B;
    ctx->h2 += C;
    ctx->h3 += D;
    ctx->h4 += E;
    ctx->h5 += F;
    ctx->h6 += G;
    ctx->h7 += H;

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL) || defined(SECURED_SHA512)
    A = MAX_DWORD_VALUE;
    B = MAX_DWORD_VALUE;
    C = MAX_DWORD_VALUE;
    D = MAX_DWORD_VALUE;
    E = MAX_DWORD_VALUE;
    F = MAX_DWORD_VALUE;
    G = MAX_DWORD_VALUE;
    H = MAX_DWORD_VALUE;
    tmp1 = MAX_DWORD_VALUE;
    tmp2 = MAX_DWORD_VALUE;
    memset_safe(W, MAX_BYTE_VALUE, 80 * sizeof(W[0]));
#endif /* SECURED_SHA512 */

}


mbcrypt_status_e mbcrypt_sha512_init(mbcrypt_sha512_t *ctx)
{
MBCRYPT_FUNCTION_BEGIN;

    MBCRYPT_CHECK_VALID_NOT_NULL(ctx);

    MBCRYPT_CHECK_VALID_NOT_NULL(memset(ctx, 0x00, sizeof(mbcrypt_sha512_t)));

    ctx->h0 = U64(0x6A09E667F3BCC908);
    ctx->h1 = U64(0xBB67AE8584CAA73B);
    ctx->h2 = U64(0x3C6EF372FE94F82B);
    ctx->h3 = U64(0xA54FF53A5F1D36F1);
    ctx->h4 = U64(0x510E527FADE682D1);
    ctx->h5 = U64(0x9B05688C2B3E6C1F);
    ctx->h6 = U64(0x1F83D9ABFB41BD6B);
    ctx->h7 = U64(0x5BE0CD19137E2179);

MBCRYPT_FUNCTION_EXIT:
    MBCRYPT_FUNCTION_RETURN;
}


mbcrypt_status_e mbcrypt_sha512_update(mbcrypt_sha512_t *ctx, 
                                const uint8_t *data, uint32_t data_len)
{
MBCRYPT_FUNCTION_BEGIN;

    uint32_t fill;
    uint32_t left;

    if (data_len == 0)
    {
        goto MBCRYPT_FUNCTION_EXIT;
    }

    left = (unsigned int) (ctx->total[0] & 0b01111111); // 0x7F
    fill = MBCRYPT_SHA512_BUFFER_SIZE - left;

    ctx->total[0] += (uint64_t)data_len;

    if (ctx->total[0] < (uint64_t)data_len)
    {
        ctx->total[1]++;
    }

    if (left && data_len >= fill)
    {
        MBCRYPT_CHECK_VALID_NOT_NULL(memcpy((void *)(ctx->buffer + left), 
                                        data, fill));
        _sha512_process(ctx, ctx->buffer);
        data += fill;
        data_len -= fill;
        left = 0;
    }

    /* if not a complite package */
    while (data_len >= MBCRYPT_SHA512_BUFFER_SIZE)
    {
        _sha512_process(ctx, data);
        data += MBCRYPT_SHA512_BUFFER_SIZE;
        data_len -= MBCRYPT_SHA512_BUFFER_SIZE;
    }

    if (data_len > 0)
    {
        MBCRYPT_CHECK_VALID_NOT_NULL(memcpy((void *)(ctx->buffer + left), 
                                        data, data_len));
    }

MBCRYPT_FUNCTION_EXIT:

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL) || defined(SECURED_SHA512)
    fill = MAX_WORD_VALUE;
    left = MAX_WORD_VALUE;
#endif /* SECURED_SHA512 */

    MBCRYPT_FUNCTION_RETURN;
}

mbcrypt_status_e mbcrypt_sha512_final(mbcrypt_sha512_t *ctx, uint8_t *out)
{
MBCRYPT_FUNCTION_BEGIN;

    uint32_t last;
    uint32_t padn;
    uint64_t high;
    uint64_t low;
    uint8_t msglen[16];

    MBCRYPT_CHECK_VALID_NOT_NULL(ctx);
    MBCRYPT_CHECK_VALID_NOT_NULL(out);

    /* message len in BE */
    high = (ctx->total[0] >> 61)
         | (ctx->total[1] << 3);
    low  = (ctx->total[0] << 3);

    PUT_UINT64_BE(high, msglen, 0);
    PUT_UINT64_BE(low, msglen, 8);

    last = (uint32_t)(ctx->total[0] & 0x7F);
    padn = (last < 112) ? (112 - last) : (240 - last);

    MBCRYPT_CHECK_RES(mbcrypt_sha512_update(ctx, _sha512_padding, padn));
    MBCRYPT_CHECK_RES(mbcrypt_sha512_update(ctx, msglen, 16));

    PUT_UINT64_BE(ctx->h0, out, 0);
    PUT_UINT64_BE(ctx->h1, out, 8);
    PUT_UINT64_BE(ctx->h2, out, 16);
    PUT_UINT64_BE(ctx->h3, out, 24);
    PUT_UINT64_BE(ctx->h4, out, 32);
    PUT_UINT64_BE(ctx->h5, out, 40);
    PUT_UINT64_BE(ctx->h6, out, 48);
    PUT_UINT64_BE(ctx->h7, out, 56);

MBCRYPT_FUNCTION_EXIT:

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL) || defined(SECURED_SHA512)
    last = MAX_WORD_VALUE;
    padn = MAX_WORD_VALUE;
    high = MAX_DWORD_VALUE;
    low =  MAX_DWORD_VALUE;
    memset_safe(msglen, MAX_BYTE_VALUE, 16 * sizeof(msglen[0]));
#endif /* SECURED_SHA512 */

    MBCRYPT_FUNCTION_RETURN;  
}

mbcrypt_status_e mbcrypt_sha512(const uint8_t *data, uint32_t data_len, uint8_t *out)
{
MBCRYPT_FUNCTION_BEGIN;

    mbcrypt_sha512_t ctx;

    MBCRYPT_CHECK_RES(mbcrypt_sha512_init(&ctx));
    MBCRYPT_CHECK_RES(mbcrypt_sha512_update(&ctx, data, data_len));
    MBCRYPT_CHECK_RES(mbcrypt_sha512_final(&ctx, out));

MBCRYPT_FUNCTION_EXIT:

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL) || defined(SECURED_SHA512)
    memset_safe(&ctx, 0xFF, sizeof(ctx));
#endif /* SECURED_SHA512 */

    MBCRYPT_FUNCTION_RETURN;
}