#include "sha256.h"

#define SHIFT_RIGHT(x, n)   ((x & MAX_WORD_VALUE) >> n)
#define ROT_RIGHT(x, n)     (SHIFT_RIGHT(x, n) | (x << (32 - n)))

#define SUB0(x)             (ROT_RIGHT(x, 7) ^ ROT_RIGHT(x, 18) ^  SHIFT_RIGHT(x, 3))
#define SUB1(x)             (ROT_RIGHT(x, 17) ^ ROT_RIGHT(x, 19) ^  SHIFT_RIGHT(x, 10))
#define SUB2(x)             (ROT_RIGHT(x, 2) ^ ROT_RIGHT(x, 13) ^ ROT_RIGHT(x, 22))
#define SUB3(x)             (ROT_RIGHT(x, 6) ^ ROT_RIGHT(x, 11) ^ ROT_RIGHT(x, 25))

#define F0(x, y, z)         ((x & y) | (z & (x | y)))
#define F1(x, y, z)         (z ^ (x & (y ^ z)))

#define ROT(t)                                  \
(                                               \
    W[t] = SUB1(W[t - 2]) + W[t - 7] +          \
           SUB0(W[t - 15]) + W[t - 16]          \
)

#define PAD(a, b, c, d, e, f, g, h, x, _K)       \
{                                               \
    tmp1 = h + SUB3(e) + F1(e, f, g) + _K + x;   \
    tmp2 = SUB2(a) + F0(a, b, c);               \
    d += tmp1;                                  \
    h = tmp1 + tmp2;                            \
}


static const uint8_t _sha256_padding[SHA256_BUFFER_SIZE] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static const uint32_t _K[SHA256_BUFFER_SIZE] =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};


static void sha256_process(sha256_t *ctx, const uint8_t *data)
{
    uint32_t tmp1;
    uint32_t tmp2;
    uint32_t W[SHA256_BUFFER_SIZE];
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
    uint32_t E;
    uint32_t F;
    uint32_t G;
    uint32_t H;

    A = ctx->h0;
    B = ctx->h1;
    C = ctx->h2;
    D = ctx->h3;
    E = ctx->h4;
    F = ctx->h5;
    G = ctx->h6;
    H = ctx->h7;

/* Select what implimentation should be */
#ifdef SHA256_MIN_SIZE

    for (uint32_t i = 0; i < 16; ++i)
    {
        GET_UINT32_BE(W[i], data, (i << 2));
    }

    for (uint32_t i = 0; i < 16; i+= 8)
    {
        PAD(A, B, C, D, E, F, G, H, W[i + 0], _K[i + 0]);
        PAD(H, A, B, C, D, E, F, G, W[i + 1], _K[i + 1]);
        PAD(G, H, A, B, C, D, E, F, W[i + 2], _K[i + 2]);
        PAD(F, G, H, A, B, C, D, E, W[i + 3], _K[i + 3]);
        PAD(E, F, G, H, A, B, C, D, W[i + 4], _K[i + 4]);
        PAD(D, E, F, G, H, A, B, C, W[i + 5], _K[i + 5]);
        PAD(C, D, E, F, G, H, A, B, W[i + 6], _K[i + 6]);
        PAD(B, C, D, E, F, G, H, A, W[i + 7], _K[i + 7]);
    }

    for (uint32_t i = 16; i < 64; i += 8)
    {
        PAD(A, B, C, D, E, F, G, H, ROT(i + 0), _K[i + 0]);
        PAD(H, A, B, C, D, E, F, G, ROT(i + 1), _K[i + 1]);
        PAD(G, H, A, B, C, D, E, F, ROT(i + 2), _K[i + 2]);
        PAD(F, G, H, A, B, C, D, E, ROT(i + 3), _K[i + 3]);
        PAD(E, F, G, H, A, B, C, D, ROT(i + 4), _K[i + 4]);
        PAD(D, E, F, G, H, A, B, C, ROT(i + 5), _K[i + 5]);
        PAD(C, D, E, F, G, H, A, B, ROT(i + 6), _K[i + 6]);
        PAD(B, C, D, E, F, G, H, A, ROT(i + 7), _K[i + 7]);
    }

#else /* SHA256_MIN_SIZE */

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
    
    PAD(A, B, C, D, E, F, G, H, W[0], _K[0]);
    PAD(H, A, B, C, D, E, F, G, W[1], _K[1]);
    PAD(G, H, A, B, C, D, E, F, W[2], _K[2]);
    PAD(F, G, H, A, B, C, D, E, W[3], _K[3]);
    PAD(E, F, G, H, A, B, C, D, W[4], _K[4]);
    PAD(D, E, F, G, H, A, B, C, W[5], _K[5]);
    PAD(C, D, E, F, G, H, A, B, W[6], _K[6]);
    PAD(B, C, D, E, F, G, H, A, W[7], _K[7]);

    PAD(A, B, C, D, E, F, G, H, W[8], _K[8]);
    PAD(H, A, B, C, D, E, F, G, W[9], _K[9]);
    PAD(G, H, A, B, C, D, E, F, W[10], _K[10]);
    PAD(F, G, H, A, B, C, D, E, W[11], _K[11]);
    PAD(E, F, G, H, A, B, C, D, W[12], _K[12]);
    PAD(D, E, F, G, H, A, B, C, W[13], _K[13]);
    PAD(C, D, E, F, G, H, A, B, W[14], _K[14]);
    PAD(B, C, D, E, F, G, H, A, W[15], _K[15]);

    PAD(A, B, C, D, E, F, G, H, ROT(16), _K[16]);
    PAD(H, A, B, C, D, E, F, G, ROT(17), _K[17]);
    PAD(G, H, A, B, C, D, E, F, ROT(18), _K[18]);
    PAD(F, G, H, A, B, C, D, E, ROT(19), _K[19]);
    PAD(E, F, G, H, A, B, C, D, ROT(20), _K[20]);
    PAD(D, E, F, G, H, A, B, C, ROT(21), _K[21]);
    PAD(C, D, E, F, G, H, A, B, ROT(22), _K[22]);
    PAD(B, C, D, E, F, G, H, A, ROT(23), _K[23]);

    PAD(A, B, C, D, E, F, G, H, ROT(24), _K[24]);
    PAD(H, A, B, C, D, E, F, G, ROT(25), _K[25]);
    PAD(G, H, A, B, C, D, E, F, ROT(26), _K[26]);
    PAD(F, G, H, A, B, C, D, E, ROT(27), _K[27]);
    PAD(E, F, G, H, A, B, C, D, ROT(28), _K[28]);
    PAD(D, E, F, G, H, A, B, C, ROT(29), _K[29]);
    PAD(C, D, E, F, G, H, A, B, ROT(30), _K[30]);
    PAD(B, C, D, E, F, G, H, A, ROT(31), _K[31]);

    PAD(A, B, C, D, E, F, G, H, ROT(32), _K[32]);
    PAD(H, A, B, C, D, E, F, G, ROT(33), _K[33]);
    PAD(G, H, A, B, C, D, E, F, ROT(34), _K[34]);
    PAD(F, G, H, A, B, C, D, E, ROT(35), _K[35]);
    PAD(E, F, G, H, A, B, C, D, ROT(36), _K[36]);
    PAD(D, E, F, G, H, A, B, C, ROT(37), _K[37]);
    PAD(C, D, E, F, G, H, A, B, ROT(38), _K[38]);
    PAD(B, C, D, E, F, G, H, A, ROT(39), _K[39]);
    
    PAD(A, B, C, D, E, F, G, H, ROT(40), _K[40]);
    PAD(H, A, B, C, D, E, F, G, ROT(41), _K[41]);
    PAD(G, H, A, B, C, D, E, F, ROT(42), _K[42]);
    PAD(F, G, H, A, B, C, D, E, ROT(43), _K[43]);
    PAD(E, F, G, H, A, B, C, D, ROT(44), _K[44]);
    PAD(D, E, F, G, H, A, B, C, ROT(45), _K[45]);
    PAD(C, D, E, F, G, H, A, B, ROT(46), _K[46]);
    PAD(B, C, D, E, F, G, H, A, ROT(47), _K[47]);

    PAD(A, B, C, D, E, F, G, H, ROT(48), _K[48]);
    PAD(H, A, B, C, D, E, F, G, ROT(49), _K[49]);
    PAD(G, H, A, B, C, D, E, F, ROT(50), _K[50]);
    PAD(F, G, H, A, B, C, D, E, ROT(51), _K[51]);
    PAD(E, F, G, H, A, B, C, D, ROT(52), _K[52]);
    PAD(D, E, F, G, H, A, B, C, ROT(53), _K[53]);
    PAD(C, D, E, F, G, H, A, B, ROT(54), _K[54]);
    PAD(B, C, D, E, F, G, H, A, ROT(55), _K[55]);

    PAD(A, B, C, D, E, F, G, H, ROT(56), _K[56]);
    PAD(H, A, B, C, D, E, F, G, ROT(57), _K[57]);
    PAD(G, H, A, B, C, D, E, F, ROT(58), _K[58]);
    PAD(F, G, H, A, B, C, D, E, ROT(59), _K[59]);
    PAD(E, F, G, H, A, B, C, D, ROT(60), _K[60]);
    PAD(D, E, F, G, H, A, B, C, ROT(61), _K[61]);
    PAD(C, D, E, F, G, H, A, B, ROT(62), _K[62]);
    PAD(B, C, D, E, F, G, H, A, ROT(63), _K[63]);

#endif

    ctx->h0 += A;
    ctx->h1 += B;
    ctx->h2 += C;
    ctx->h3 += D;
    ctx->h4 += E;
    ctx->h5 += F;
    ctx->h6 += G;
    ctx->h7 += H;

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || defined(SECURED_SHA256)
    tmp1 = MAX_WORD_VALUE;
    tmp2 = MAX_WORD_VALUE;
    A = MAX_WORD_VALUE;
    B = MAX_WORD_VALUE;
    C = MAX_WORD_VALUE;
    D = MAX_WORD_VALUE;
    E = MAX_WORD_VALUE;
    F = MAX_WORD_VALUE;
    G = MAX_WORD_VALUE;
    H = MAX_WORD_VALUE;
    memset_safe(W, MAX_BYTE_VALUE, SHA256_BUFFER_SIZE * sizeof(W[0]));
#endif /* SECURED_SHA256 */

}


security_status_e sha256_init(sha256_t *ctx)
{
SECURITY_FUNCTION_BEGIN;

    SECURITY_CHECK_VALID_NOT_NULL(ctx);

    SECURITY_CHECK_VALID_NOT_NULL(memset(ctx, 0x00, sizeof(sha256_t)));

    ctx->h0 = 0x6A09E667;
    ctx->h1 = 0xBB67AE85;
    ctx->h2 = 0x3C6EF372;
    ctx->h3 = 0xA54FF53A;
    ctx->h4 = 0x510E527F;
    ctx->h5 = 0x9B05688C;
    ctx->h6 = 0x1F83D9AB;
    ctx->h7 = 0x5BE0CD19;

SECURITY_FUNCTION_EXIT:
    SECURITY_FUNCTION_RETURN;
}


security_status_e sha256_update(sha256_t *ctx, 
                                const uint8_t *data, uint32_t data_len)
{
SECURITY_FUNCTION_BEGIN;

    uint32_t fill;
    uint32_t left;

    SECURITY_CHECK_VALID_NOT_NULL(data);
    SECURITY_CHECK_VALID_NOT_NULL(ctx);

    if (data_len == 0)
    {
        goto SECURITY_FUNCTION_EXIT;
    }

    left = ctx->total[0] & 0b00111111; // 63 == 0x3F
    fill = SHA256_BUFFER_SIZE - left;

    ctx->total[0] += data_len;
    ctx->total[0] &= MAX_WORD_VALUE;

    if (ctx->total[0] < data_len)
    {
        ctx->total[1]++;
    }

    if (left && data_len >= fill)
    {
        SECURITY_CHECK_VALID_NOT_NULL(memcpy((void *)(ctx->buffer + left), 
                                        data, fill));
        sha256_process(ctx, ctx->buffer);
        data += fill;
        data_len -= fill;
        left = 0;
    }

    /* if not a complite package */
    while (data_len >= SHA256_BUFFER_SIZE)
    {
        sha256_process(ctx, data);
        data += SHA256_BUFFER_SIZE;
        data_len  -= SHA256_BUFFER_SIZE;
    }

    if (data_len > 0)
    {
        SECURITY_CHECK_VALID_NOT_NULL(memcpy((void *)(ctx->buffer + left), 
                                        data, data_len));
    }

SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || defined(SECURED_SHA256)
    fill = MAX_WORD_VALUE;
    left = MAX_WORD_VALUE;
#endif /* SECURED_SHA256 */

    SECURITY_FUNCTION_RETURN;
}


security_status_e sha256_finish(sha256_t *ctx, uint8_t *out)
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
    high = (ctx->total[0] >> 29)
         | (ctx->total[1] << 3);
    low  = (ctx->total[0] << 3);

    PUT_UINT32_BE(high, msglen, 0);
    PUT_UINT32_BE(low, msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    SECURITY_CHECK_RES(sha256_update(ctx, _sha256_padding, padn));
    SECURITY_CHECK_RES(sha256_update(ctx, msglen, 8));

    PUT_UINT32_BE(ctx->h0, out, 0);
    PUT_UINT32_BE(ctx->h1, out, 4);
    PUT_UINT32_BE(ctx->h2, out, 8);
    PUT_UINT32_BE(ctx->h3, out, 12);
    PUT_UINT32_BE(ctx->h4, out, 16);
    PUT_UINT32_BE(ctx->h5, out, 20);
    PUT_UINT32_BE(ctx->h6, out, 24);
    PUT_UINT32_BE(ctx->h7, out, 28);

SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || defined(SECURED_SHA256)
    last = MAX_WORD_VALUE;
    padn = MAX_WORD_VALUE;
    high = MAX_WORD_VALUE;
    low =  MAX_WORD_VALUE;
    memset_safe(msglen, MAX_BYTE_VALUE, 8 * sizeof(msglen[0]));
#endif /* SECURED_SHA256 */

    SECURITY_FUNCTION_RETURN;
}


security_status_e sha256(const uint8_t *data, uint32_t data_len, uint8_t *out)
{
SECURITY_FUNCTION_BEGIN;

    sha256_t ctx;

    SECURITY_CHECK_RES(sha256_init(&ctx));
    SECURITY_CHECK_RES(sha256_update(&ctx, data, data_len));
    SECURITY_CHECK_RES(sha256_finish(&ctx, out));

SECURITY_FUNCTION_EXIT:

#if (SECURITY_LEVEL == MAX_SECURITY_LEVEL) || defined(SECURED_SHA256)
    memset_safe(&ctx, MAX_BYTE_VALUE, sizeof(ctx));
#endif /* SECURED_SHA256 */

    SECURITY_FUNCTION_RETURN;
}