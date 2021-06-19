#include "sha1.h"

#define SHIFT_LEFT(x, n) ((x << n) | ((x & MAX_WORD_VALUE) >> (32 - n)))

/* Shift left 30 == shift right 1 */
#define PAD(a, b, c, d, e, f)                       \
{                                                   \
    e += SHIFT_LEFT(a, 5) + F(b, c, d) + K + f;     \
    b = SHIFT_LEFT(b, 30);                          \
}

static const uint8_t sha1_padding[SHA1_BUFFER_SIZE] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void sha1_process(sha1_t *ctx, const uint8_t *data)
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

#define R(t)                                        \
(                                                   \
    temp = W[(t - 3) & 0x0F] ^ W[(t - 8) & 0x0F] ^  \
        W[(t - 14) & 0x0F] ^ W[t & 0x0F],           \
    (W[t & 0x0F] = SHIFT_LEFT(temp, 1))             \
)

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
    PAD(E, A, B, C, D, R(16));
    PAD(D, E, A, B, C, R(17));
    PAD(C, D, E, A, B, R(18));
    PAD(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x, y, z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    for (uint32_t i = 20; i < 40; i += 5)
    {
        PAD(A, B, C, D, E, R(i + 0));
        PAD(E, A, B, C, D, R(i + 1));
        PAD(D, E, A, B, C, R(i + 2));
        PAD(C, D, E, A, B, R(i + 3));
        PAD(B, C, D, E, A, R(i + 4));
    }

#undef K
#undef F

#define F(x, y, z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    for (uint32_t i = 40; i < 60; i += 5)
    {
        PAD(A, B, C, D, E, R(i + 0));
        PAD(E, A, B, C, D, R(i + 1));
        PAD(D, E, A, B, C, R(i + 2));
        PAD(C, D, E, A, B, R(i + 3));
        PAD(B, C, D, E, A, R(i + 4));
    }

#undef K
#undef F

#define F(x, y, z) (x ^ y ^ z)
#define K 0xCA62C1D6

    for (uint32_t i = 60; i < 80; i += 5)
    {
        PAD(A, B, C, D, E, R(i + 0));
        PAD(E, A, B, C, D, R(i + 1));
        PAD(D, E, A, B, C, R(i + 2));
        PAD(C, D, E, A, B, R(i + 3));
        PAD(B, C, D, E, A, R(i + 4));
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


#define R(t)                                        \
(                                                   \
    temp = W[(t - 3) & 0x0F] ^ W[(t - 8) & 0x0F] ^  \
           W[(t - 14) & 0x0F] ^ W[t & 0x0F],        \
    (W[t & 0x0F] = SHIFT_LEFT(temp, 1))             \
)

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
    PAD(E, A, B, C, D, R(16));
    PAD(D, E, A, B, C, R(17));
    PAD(C, D, E, A, B, R(18));
    PAD(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x, y, z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    PAD(A, B, C, D, E, R(20));
    PAD(E, A, B, C, D, R(21));
    PAD(D, E, A, B, C, R(22));
    PAD(C, D, E, A, B, R(23));
    PAD(B, C, D, E, A, R(24));
    
    PAD(A, B, C, D, E, R(25));
    PAD(E, A, B, C, D, R(26));
    PAD(D, E, A, B, C, R(27));
    PAD(C, D, E, A, B, R(28));
    PAD(B, C, D, E, A, R(29));

    PAD(A, B, C, D, E, R(30));
    PAD(E, A, B, C, D, R(31));
    PAD(D, E, A, B, C, R(32));
    PAD(C, D, E, A, B, R(33));
    PAD(B, C, D, E, A, R(34));

    PAD(A, B, C, D, E, R(35));
    PAD(E, A, B, C, D, R(36));
    PAD(D, E, A, B, C, R(37));
    PAD(C, D, E, A, B, R(38));
    PAD(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x, y, z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    PAD(A, B, C, D, E, R(40));
    PAD(E, A, B, C, D, R(41));
    PAD(D, E, A, B, C, R(42));
    PAD(C, D, E, A, B, R(43));
    PAD(B, C, D, E, A, R(44));

    PAD(A, B, C, D, E, R(45));
    PAD(E, A, B, C, D, R(46));
    PAD(D, E, A, B, C, R(47));
    PAD(C, D, E, A, B, R(48));
    PAD(B, C, D, E, A, R(49));

    PAD(A, B, C, D, E, R(50));
    PAD(E, A, B, C, D, R(51));
    PAD(D, E, A, B, C, R(52));
    PAD(C, D, E, A, B, R(53));
    PAD(B, C, D, E, A, R(54));

    PAD(A, B, C, D, E, R(55));
    PAD(E, A, B, C, D, R(56));
    PAD(D, E, A, B, C, R(57));
    PAD(C, D, E, A, B, R(58));
    PAD(B, C, D, E, A, R(59)); 

#undef K
#undef F

#define F(x, y, z) (x ^ y ^ z)
#define K 0xCA62C1D6

    PAD(A, B, C, D, E, R(60));
    PAD(E, A, B, C, D, R(61));
    PAD(D, E, A, B, C, R(62));
    PAD(C, D, E, A, B, R(63));
    PAD(B, C, D, E, A, R(64));

    PAD(A, B, C, D, E, R(65));
    PAD(E, A, B, C, D, R(66));
    PAD(D, E, A, B, C, R(67));
    PAD(C, D, E, A, B, R(68));
    PAD(B, C, D, E, A, R(69));

    PAD(A, B, C, D, E, R(70));
    PAD(E, A, B, C, D, R(71));
    PAD(D, E, A, B, C, R(72));
    PAD(C, D, E, A, B, R(73));
    PAD(B, C, D, E, A, R(74));

    PAD(A, B, C, D, E, R(75));
    PAD(E, A, B, C, D, R(76));
    PAD(D, E, A, B, C, R(77));
    PAD(C, D, E, A, B, R(78));
    PAD(B, C, D, E, A, R(79));

#undef K
#undef F
#endif /* SHA1_MIN_SIZE */

    ctx->h0 += A;
    ctx->h1 += B;
    ctx->h2 += C;
    ctx->h3 += D;
    ctx->h4 += E;
    
#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || (SECURED_SHA1 == ENABLED)
    temp = MAX_WORD_VALUE;
    A = MAX_WORD_VALUE;
    B = MAX_WORD_VALUE;
    C = MAX_WORD_VALUE;
    D = MAX_WORD_VALUE;
    E = MAX_WORD_VALUE;
    memset_safe(W, MAX_BYTE_VALUE, 16 * sizeof(W[0]));
#endif /* SECURED_SHA1 */

}

security_status_e sha1_init(sha1_t *ctx)
{
SECURITY_FUNCTION_BEGIN;

    SECURITY_CHECK_VALID_NOT_NULL(ctx);

    SECURITY_CHECK_VALID_NOT_NULL(memset(ctx, 0x00, sizeof(sha1_t)));

    ctx->h0 = 0x67452301;
    ctx->h1 = 0xEFCDAB89;
    ctx->h2 = 0x98BADCFE;
    ctx->h3 = 0x10325476;
    ctx->h4 = 0xC3D2E1F0;

SECURITY_FUNCTION_EXIT:
    SECURITY_FUNCTION_RETURN;
}

security_status_e sha1_update(sha1_t *ctx, const uint8_t *data, uint32_t data_len)
{
SECURITY_FUNCTION_BEGIN;

    uint32_t fill;
    uint32_t left;

    SECURITY_CHECK_VALID_NOT_NULL(ctx);
    SECURITY_CHECK_VALID_NOT_NULL(data);

    if (data_len == 0)
    {
        goto SECURITY_FUNCTION_EXIT;
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
        SECURITY_CHECK_VALID_NOT_NULL(memcpy((void *)(ctx->buffer + left), 
                                        data, fill));
        sha1_process(ctx, ctx->buffer);
        data += fill;
        data_len -= fill;
        left = 0;
    }

    /* if not a complite package */
    while (data_len >= SHA1_BUFFER_SIZE)
    {
        sha1_process(ctx, data);
        data += SHA1_BUFFER_SIZE;
        data_len  -= SHA1_BUFFER_SIZE;
    }

    if(data_len > 0)
    {
         SECURITY_CHECK_VALID_NOT_NULL(memcpy((void *)(ctx->buffer + left), 
                                        data, data_len));
    }
    
SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || (SECURED_SHA1 == ENABLED)
    fill = MAX_WORD_VALUE;
    left = MAX_WORD_VALUE;
#endif /* SECURED_SHA1 */

     SECURITY_FUNCTION_RETURN;
}

security_status_e sha1_finish(sha1_t *ctx, uint8_t *out)
{
SECURITY_FUNCTION_BEGIN;

    uint32_t last;
    uint32_t padn;
    uint32_t high;
    uint32_t low;

    uint8_t msglen[8];

    SECURITY_CHECK_VALID_NOT_NULL(ctx);
    SECURITY_CHECK_VALID_NOT_NULL(out);

    /* message len in BE */
    high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    low  = (ctx->total[0] << 3);

    PUT_UINT32_BE(high, msglen, 0);
    PUT_UINT32_BE(low, msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    SECURITY_CHECK_RES(sha1_update(ctx, sha1_padding, padn));
    SECURITY_CHECK_RES(sha1_update(ctx, msglen, 8));

    PUT_UINT32_BE(ctx->h0, out, 0);
    PUT_UINT32_BE(ctx->h1, out, 4);
    PUT_UINT32_BE(ctx->h2, out, 8);
    PUT_UINT32_BE(ctx->h3, out, 12);
    PUT_UINT32_BE(ctx->h4, out, 16);

SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || (SECURED_SHA1 == ENABLED)
    last = MAX_WORD_VALUE;
    padn = MAX_WORD_VALUE;
    high = MAX_WORD_VALUE;
    low =  MAX_WORD_VALUE;
    memset_safe(msglen, MAX_BYTE_VALUE, 8 * sizeof(msglen[0]));
#endif /* SECURED_SHA1 */

     SECURITY_FUNCTION_RETURN;
}

security_status_e sha1(const uint8_t *data, uint32_t data_len, uint8_t *out)
{
SECURITY_FUNCTION_BEGIN;

    sha1_t ctx;

    SECURITY_CHECK_RES(sha1_init(&ctx));
    SECURITY_CHECK_RES(sha1_update(&ctx, data, data_len));
    SECURITY_CHECK_RES(sha1_finish(&ctx, out));

SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || (SECURED_SHA1 == ENABLED)
    memset_safe(&ctx, MAX_BYTE_VALUE, sizeof(ctx));
#endif /* SECURED_SHA1 */

    SECURITY_FUNCTION_RETURN;
}