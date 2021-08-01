#include "rand.h"
#include <math.h>

#define BASE_SEED_SIZE      (64)
#define ENTROPY_TESTS       (1000000)
#define ENTROPY_MOD         (1000)
#define INF                 (1000000000)

double get_entropy(int (*rnd)())
{
    uint32_t cnt[ENTROPY_MOD] = {0};
    double sum = 0;

    for(uint32_t i = 0; i < ENTROPY_TESTS; ++i)
    {
        cnt[rnd() % ENTROPY_MOD]++;
    }

    for (uint32_t i = 0; i < ENTROPY_MOD; ++i)
    {
        if (cnt[i] == 0)
        {
            continue;
        }
        double p = (double)(cnt[i]) / (double)(ENTROPY_TESTS);
        sum += (p * log2(p));
    }
    sum *= -1;
    return sum;
}

union u32_e
{
    uint32_t dw;
    uint16_t w;
    uint8_t b[4];
};

static volatile uint8_t _seed[BASE_SEED_SIZE] = {0};

static void inc_seed()
{
    uint32_t i = 0;

    while (++_seed[i] == 0 && i < BASE_SEED_SIZE)
    {
        ++i;
    }
    
}

void srand(uint32_t seed)
{
    union u32_e tmp_seed;

    tmp_seed.dw = seed;

#if defined(PLATFORM_LE)
    _seed[0] = tmp_seed.b[0];
    _seed[1] = tmp_seed.b[1];
    _seed[2] = tmp_seed.b[2];
    _seed[3] = tmp_seed.b[3];
#else
    _seed[0] = tmp_seed.b[3];
    _seed[1] = tmp_seed.b[2];
    _seed[2] = tmp_seed.b[1];
    _seed[3] = tmp_seed.b[0];
#endif /* PLATFORM_LE */

    for (uint32_t i = 4; i < BASE_SEED_SIZE; ++i)
    {
        _seed[i] = _seed[i - 1] + _seed[i - 2];
    }
}

void rand_bytes_ex(uint8_t *dst, uint32_t size, int32_t (*rnd_gen)())
{
    union u32_e tmp;
    uint32_t blocks = size >> 2;
    uint32_t left = size & 3;
    
#if defined(PLATFORM_LE)
    for (uint32_t i = 0; i < blocks; ++i, dst += 4)
    {
        tmp.dw = U32(rnd_gen());
        dst[0] = tmp.b[0];
        dst[1] = tmp.b[1];
        dst[2] = tmp.b[2];
        dst[3] = tmp.b[3];
    }
    while (left--)
    {
        dst[left] = tmp.b[left];
    }
#else
    for (uint32_t i = 0; i < blocks; ++i, dst += 4)
    {
        tmp.dw = U32(rnd_gen());
        dst[0] = tmp.b[3];
        dst[1] = tmp.b[2];
        dst[2] = tmp.b[1];
        dst[3] = tmp.b[0];
    }
    uint32_t j = 0;
    while (left--)
    {
        dst[0 + j++] = tmp.b[left];
    }
#endif /* PLATFORM_LE */

}

#if (RAND_PRNG_SHA256 == ENABLED)

#include "sha256.h"

int32_t rand()
{
    uint8_t hash[SHA256_HASH_SIZE];
    int32_t res = 0;

    sha256(_seed, BASE_SEED_SIZE, hash);

    res |= hash[0];
    res <<= 8;

    res |= hash[1];
    res <<= 8;

    res |= hash[2];
    res <<= 8;

    res |= hash[3];

    inc_seed();

    memset(hash, 0xFF, SHA256_HASH_SIZE);

    return res;
}

void rand_bytes(uint8_t *dst, uint32_t size)
{
    if (!size || !dst)
    {
        return;
    }

    uint8_t hash[SHA256_HASH_SIZE];
    uint32_t blocks = size / SHA256_HASH_SIZE;
    uint32_t left = size - blocks * SHA256_HASH_SIZE;

    for (uint32_t i = 0; i < blocks; ++i, dst += SHA256_HASH_SIZE)
    {
        sha256(_seed, SHA256_HASH_SIZE, dst);
        inc_seed();
    }

    if (left)
    {
        sha256(_seed, SHA256_HASH_SIZE, hash);
        memcpy(dst, hash, left);
        memset(hash, 0xFF, SHA256_HASH_SIZE);
        inc_seed();
    }
}

#elif (RAND_CTR_DRBG == ENABLED)

#endif




#ifdef RAND_EXPERIMENTAL


//holdrand = holdrand * 214013L + 2531011L
void srand(uint32_t seed)
{
    for (uint32_t i = 0; i < BASE_SEED_SIZE; ++i)
    {
        _seed[i] = _seed[i] ^ ((seed >> (i & 3)) & 0xFF);
    }
}

int32_t rand()
{
    int32_t res = 0;
#if (RAND_FAST == ENABLED)
    uint8_t hash[SHA256_HASH_SIZE];
    security_status_e sec_ret = 0;
    
    ASSERT(sha256(_seed, BASE_SEED_SIZE, hash) == SECURITY_STATUS_OK, "SHA256 return status not OK!")
    
    res = (U32(hash[3]) << 24) | (U32(hash[23]) << 16) 
        | (U32(hash[7]) << 8) | (U32(hash[16]));
    for (uint32_t i = 0; i < BASE_SEED_SIZE; ++i)
    {
        _seed[i] ^= hash[i] + 0xff7f;
        LEFT_ROTATE(_seed[i], (_seed[i] ^ res) & 0x10);
    }
#else
    *(UPTR32(_seed)) = ((*(UPTR32(_seed)) * 214013L + 2531011L) >> 16) & 0x7fff;
    for (uint32_t i = 1; i < 8; i++)
    {
        *(UPTR32(_seed) + i) ^= (*(UPTR32(_seed + i - 1)) * 214013L + 2531011L);
        LEFT_ROTATE(_seed[i], 16);

    }
    res = (U32(_seed[3]) << 24) | (U32(_seed[23]) << 16) 
        | (U32(_seed[7]) << 8) | (U32(_seed[16]));
#endif
    return res;
}

#endif /* RAND_EXPERIMENTAL */
