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
*   @file sha1.c
*   @brief File contains SHA-1 implementation.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.04
*/

#include "sha1.h"

#define SHIFT_LEFT(x, n) ((x << n) | ((x & MAX_WORD_VALUE) >> (32 - n)))

/* Shift left 30 == shift right 1 */
#define PAD(a, b, c, d, e, f)                       \
{                                                   \
    e += SHIFT_LEFT(a, 5) + F(b, c, d) + K + f;     \
    b = SHIFT_LEFT(b, 30);                          \
}

#define ROT(t)                                        \
(                                                   \
    temp = W[(t - 3) & 0x0F] ^ W[(t - 8) & 0x0F] ^  \
           W[(t - 14) & 0x0F] ^ W[t & 0x0F],        \
    (W[t & 0x0F] = SHIFT_LEFT(temp, 1))             \
)


static const uint8_t _sha1_padding[SHA1_BUFFER_SIZE] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void _sha1_process(sha1_t *ctx, const uint8_t *data)
{
    uint32_t temp;
    uint32_t W[16];
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
    uint32_t E;

    A = ctx->h0;
    B = ctx->h1;
    C = ctx->h2;
    D = ctx->h3;
    E = ctx->h4;

/* Select what implimentation should be */
#if (SHA1_MIN_SIZE == ENABLED)

    for (uint32_t i = 0; i < 16; ++i)
    {
        GET_UINT32_BE(W[i], data, (i << 2));
    }

#define F(x, y, z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    for (uint32_t i = 0; i < 15; i += 5)
    {
        PAD(A, B, C, D, E, W[i + 0]);
        PAD(E, A, B, C, D, W[i + 1]);
        PAD(D, E, A, B, C, W[i + 2]);
        PAD(C, D, E, A, B, W[i + 3]);
        PAD(B, C, D, E, A, W[i + 4]);
    }

    PAD(A, B, C, D, E, W[15]);
    PAD(E, A, B, C, D, ROT(16));
    PAD(D, E, A, B, C, ROT(17));
    PAD(C, D, E, A, B, ROT(18));
    PAD(B, C, D, E, A, ROT(19));

#undef K
#undef F

#define F(x, y, z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    for (uint32_t i = 20; i < 40; i += 5)
    {
        PAD(A, B, C, D, E, ROT(i + 0));
        PAD(E, A, B, C, D, ROT(i + 1));
        PAD(D, E, A, B, C, ROT(i + 2));
        PAD(C, D, E, A, B, ROT(i + 3));
        PAD(B, C, D, E, A, ROT(i + 4));
    }

#undef K
#undef F

#define F(x, y, z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    for (uint32_t i = 40; i < 60; i += 5)
    {
        PAD(A, B, C, D, E, ROT(i + 0));
        PAD(E, A, B, C, D, ROT(i + 1));
        PAD(D, E, A, B, C, ROT(i + 2));
        PAD(C, D, E, A, B, ROT(i + 3));
        PAD(B, C, D, E, A, ROT(i + 4));
    }

#undef K
#undef F

#define F(x, y, z) (x ^ y ^ z)
#define K 0xCA62C1D6

    for (uint32_t i = 60; i < 80; i += 5)
    {
        PAD(A, B, C, D, E, ROT(i + 0));
        PAD(E, A, B, C, D, ROT(i + 1));
        PAD(D, E, A, B, C, ROT(i + 2));
        PAD(C, D, E, A, B, ROT(i + 3));
        PAD(B, C, D, E, A, ROT(i + 4));
    }

#undef K
#undef F

#else /* SHA1_MIN_SIZE */

    GET_UINT32_BE(W[0], data, 0);
    GET_UINT32_BE(W[1], data, 4);
    GET_UINT32_BE(W[2], data, 8);
    GET_UINT32_BE(W[3], data, 12);
    GET_UINT32_BE(W[4], data, 16);
    GET_UINT32_BE(W[5], data, 20);
    GET_UINT32_BE(W[6], data, 24);
    GET_UINT32_BE(W[7], data, 28);
    GET_UINT32_BE(W[8], data, 32);
    GET_UINT32_BE(W[9], data, 36);
    GET_UINT32_BE(W[10], data, 40);
    GET_UINT32_BE(W[11], data, 44);
    GET_UINT32_BE(W[12], data, 48);
    GET_UINT32_BE(W[13], data, 52);
    GET_UINT32_BE(W[14], data, 56);
    GET_UINT32_BE(W[15], data, 60);

#define F(x, y, z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    PAD(A, B, C, D, E, W[0]);
    PAD(E, A, B, C, D, W[1]);
    PAD(D, E, A, B, C, W[2]);
    PAD(C, D, E, A, B, W[3]);
    PAD(B, C, D, E, A, W[4]);
    
    PAD(A, B, C, D, E, W[5]);
    PAD(E, A, B, C, D, W[6]);
    PAD(D, E, A, B, C, W[7]);
    PAD(C, D, E, A, B, W[8]);
    PAD(B, C, D, E, A, W[9]);

    PAD(A, B, C, D, E, W[10]);
    PAD(E, A, B, C, D, W[11]);
    PAD(D, E, A, B, C, W[12]);
    PAD(C, D, E, A, B, W[13]);
    PAD(B, C, D, E, A, W[14]);

    PAD(A, B, C, D, E, W[15]);
    PAD(E, A, B, C, D, ROT(16));
    PAD(D, E, A, B, C, ROT(17));
    PAD(C, D, E, A, B, ROT(18));
    PAD(B, C, D, E, A, ROT(19));

#undef K
#undef F

#define F(x, y, z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    PAD(A, B, C, D, E, ROT(20));
    PAD(E, A, B, C, D, ROT(21));
    PAD(D, E, A, B, C, ROT(22));
    PAD(C, D, E, A, B, ROT(23));
    PAD(B, C, D, E, A, ROT(24));
    
    PAD(A, B, C, D, E, ROT(25));
    PAD(E, A, B, C, D, ROT(26));
    PAD(D, E, A, B, C, ROT(27));
    PAD(C, D, E, A, B, ROT(28));
    PAD(B, C, D, E, A, ROT(29));

    PAD(A, B, C, D, E, ROT(30));
    PAD(E, A, B, C, D, ROT(31));
    PAD(D, E, A, B, C, ROT(32));
    PAD(C, D, E, A, B, ROT(33));
    PAD(B, C, D, E, A, ROT(34));

    PAD(A, B, C, D, E, ROT(35));
    PAD(E, A, B, C, D, ROT(36));
    PAD(D, E, A, B, C, ROT(37));
    PAD(C, D, E, A, B, ROT(38));
    PAD(B, C, D, E, A, ROT(39));

#undef K
#undef F

#define F(x, y, z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    PAD(A, B, C, D, E, ROT(40));
    PAD(E, A, B, C, D, ROT(41));
    PAD(D, E, A, B, C, ROT(42));
    PAD(C, D, E, A, B, ROT(43));
    PAD(B, C, D, E, A, ROT(44));

    PAD(A, B, C, D, E, ROT(45));
    PAD(E, A, B, C, D, ROT(46));
    PAD(D, E, A, B, C, ROT(47));
    PAD(C, D, E, A, B, ROT(48));
    PAD(B, C, D, E, A, ROT(49));

    PAD(A, B, C, D, E, ROT(50));
    PAD(E, A, B, C, D, ROT(51));
    PAD(D, E, A, B, C, ROT(52));
    PAD(C, D, E, A, B, ROT(53));
    PAD(B, C, D, E, A, ROT(54));

    PAD(A, B, C, D, E, ROT(55));
    PAD(E, A, B, C, D, ROT(56));
    PAD(D, E, A, B, C, ROT(57));
    PAD(C, D, E, A, B, ROT(58));
    PAD(B, C, D, E, A, ROT(59)); 

#undef K
#undef F

#define F(x, y, z) (x ^ y ^ z)
#define K 0xCA62C1D6

    PAD(A, B, C, D, E, ROT(60));
    PAD(E, A, B, C, D, ROT(61));
    PAD(D, E, A, B, C, ROT(62));
    PAD(C, D, E, A, B, ROT(63));
    PAD(B, C, D, E, A, ROT(64));

    PAD(A, B, C, D, E, ROT(65));
    PAD(E, A, B, C, D, ROT(66));
    PAD(D, E, A, B, C, ROT(67));
    PAD(C, D, E, A, B, ROT(68));
    PAD(B, C, D, E, A, ROT(69));

    PAD(A, B, C, D, E, ROT(70));
    PAD(E, A, B, C, D, ROT(71));
    PAD(D, E, A, B, C, ROT(72));
    PAD(C, D, E, A, B, ROT(73));
    PAD(B, C, D, E, A, ROT(74));

    PAD(A, B, C, D, E, ROT(75));
    PAD(E, A, B, C, D, ROT(76));
    PAD(D, E, A, B, C, ROT(77));
    PAD(C, D, E, A, B, ROT(78));
    PAD(B, C, D, E, A, ROT(79));

#undef K
#undef F
#endif /* SHA1_MIN_SIZE */

    ctx->h0 += A;
    ctx->h1 += B;
    ctx->h2 += C;
    ctx->h3 += D;
    ctx->h4 += E;
    
#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL) || (SECURED_SHA1 == ENABLED)
    temp = MAX_WORD_VALUE;
    A = MAX_WORD_VALUE;
    B = MAX_WORD_VALUE;
    C = MAX_WORD_VALUE;
    D = MAX_WORD_VALUE;
    E = MAX_WORD_VALUE;
    memset_safe(W, MAX_BYTE_VALUE, 16 * sizeof(W[0]));
#endif /* SECURED_SHA1 */

}

mbcrypt_status_e sha1_init(sha1_t *ctx)
{
MBCRYPT_FUNCTION_BEGIN;

    MBCRYPT_CHECK_VALID_NOT_NULL(ctx);

    MBCRYPT_CHECK_VALID_NOT_NULL(memset(ctx, 0x00, sizeof(sha1_t)));

    ctx->h0 = 0x67452301;
    ctx->h1 = 0xEFCDAB89;
    ctx->h2 = 0x98BADCFE;
    ctx->h3 = 0x10325476;
    ctx->h4 = 0xC3D2E1F0;

MBCRYPT_FUNCTION_EXIT:
    MBCRYPT_FUNCTION_RETURN;
}

mbcrypt_status_e sha1_update(sha1_t *ctx, const uint8_t *data, uint32_t data_len)
{
MBCRYPT_FUNCTION_BEGIN;

    uint32_t fill;
    uint32_t left;

    MBCRYPT_CHECK_VALID_NOT_NULL(ctx);
    MBCRYPT_CHECK_VALID_NOT_NULL(data);

    if (data_len == 0)
    {
        goto MBCRYPT_FUNCTION_EXIT;
    }

    left = ctx->total[0] & 0b00111111; // 63 == 0x3F
    fill = SHA1_BUFFER_SIZE - left;

    ctx->total[0] += data_len;
    ctx->total[0] &= MAX_WORD_VALUE;

    if (ctx->total[0] < data_len)
    {
        ctx->total[1]++;
    }

    if (left != 0 && data_len >= fill)
    {
        MBCRYPT_CHECK_VALID_NOT_NULL(memcpy((void *)(ctx->buffer + left), 
                                        data, fill));
        _sha1_process(ctx, ctx->buffer);
        data += fill;
        data_len -= fill;
        left = 0;
    }

    /* if not a complite package */
    while (data_len >= SHA1_BUFFER_SIZE)
    {
        _sha1_process(ctx, data);
        data += SHA1_BUFFER_SIZE;
        data_len  -= SHA1_BUFFER_SIZE;
    }

    if(data_len > 0)
    {
         MBCRYPT_CHECK_VALID_NOT_NULL(memcpy((void *)(ctx->buffer + left), 
                                        data, data_len));
    }
    
MBCRYPT_FUNCTION_EXIT:

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL) || (SECURED_SHA1 == ENABLED)
    fill = MAX_WORD_VALUE;
    left = MAX_WORD_VALUE;
#endif /* SECURED_SHA1 */

     MBCRYPT_FUNCTION_RETURN;
}

mbcrypt_status_e sha1_finish(sha1_t *ctx, uint8_t *out)
{
MBCRYPT_FUNCTION_BEGIN;

    uint32_t last;
    uint32_t padn;
    uint32_t high;
    uint32_t low;

    uint8_t msglen[8];

    MBCRYPT_CHECK_VALID_NOT_NULL(ctx);
    MBCRYPT_CHECK_VALID_NOT_NULL(out);

    /* message len in BE */
    high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    low  = (ctx->total[0] << 3);

    PUT_UINT32_BE(high, msglen, 0);
    PUT_UINT32_BE(low, msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    MBCRYPT_CHECK_RES(sha1_update(ctx, _sha1_padding, padn));
    MBCRYPT_CHECK_RES(sha1_update(ctx, msglen, 8));

    PUT_UINT32_BE(ctx->h0, out, 0);
    PUT_UINT32_BE(ctx->h1, out, 4);
    PUT_UINT32_BE(ctx->h2, out, 8);
    PUT_UINT32_BE(ctx->h3, out, 12);
    PUT_UINT32_BE(ctx->h4, out, 16);

MBCRYPT_FUNCTION_EXIT:

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL) || (SECURED_SHA1 == ENABLED)
    last = MAX_WORD_VALUE;
    padn = MAX_WORD_VALUE;
    high = MAX_WORD_VALUE;
    low =  MAX_WORD_VALUE;
    memset_safe(msglen, MAX_BYTE_VALUE, 8 * sizeof(msglen[0]));
#endif /* SECURED_SHA1 */

     MBCRYPT_FUNCTION_RETURN;
}

mbcrypt_status_e sha1(const uint8_t *data, uint32_t data_len, uint8_t *out)
{
MBCRYPT_FUNCTION_BEGIN;

    sha1_t ctx;

    MBCRYPT_CHECK_RES(sha1_init(&ctx));
    MBCRYPT_CHECK_RES(sha1_update(&ctx, data, data_len));
    MBCRYPT_CHECK_RES(sha1_finish(&ctx, out));

MBCRYPT_FUNCTION_EXIT:

#if (MBCRYPT_LEVEL == MAX_MBCRYPT_LEVEL) || (SECURED_SHA1 == ENABLED)
    memset_safe(&ctx, MAX_BYTE_VALUE, sizeof(ctx));
#endif /* SECURED_SHA1 */

    MBCRYPT_FUNCTION_RETURN;
}