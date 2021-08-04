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
*   @file drbg.c
*   @brief File contains DRBG implementation.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.04
*/

#include "rand.h"


#if (MEASURE_ENTROPY == ENABLED)

#include <math.h>

#define ENTROPY_TESTS       (1000000)
#define ENTROPY_MOD         (1000)

double get_entropy(rnd_callback_t rnd)
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
#endif /* MEASURE_ENTROPY */

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

void srand_bytes(uint8_t *seed, uint32_t seed_len)
{
    if (seed_len > BASE_SEED_SIZE) 
    {
        seed_len = BASE_SEED_SIZE;
    }

    memcpy(_seed, seed, seed_len);

    if (seed_len < BASE_SEED_SIZE)
    {
        memset(_seed, BASE_SEED_SIZE - seed_len, BASE_SEED_SIZE - seed_len);
    }
}

void rand_bytes(uint8_t *dst, uint32_t size)
{
   rand_bytes_ex(dst, size, NULL);
}

void rand_bytes_ex(uint8_t *dst, uint32_t size, rnd_callback_t rnd)
{
    union u32_e tmp;
    rnd_callback_t lrand = rnd;
    uint32_t blocks = size >> 2;
    uint32_t left = size & 3;
    
    if (lrand == NULL)
    {
        lrand = rand;
    }

#if defined(PLATFORM_LE)
    for (uint32_t i = 0; i < blocks; ++i, dst += 4)
    {
        tmp.dw = U32(lrand());
        dst[0] = tmp.b[0];
        dst[1] = tmp.b[1];
        dst[2] = tmp.b[2];
        dst[3] = tmp.b[3];
    }
    /* Full fill left bytes */
    while (left--)
    {
        dst[left] = tmp.b[left];
    }
#else
    for (uint32_t i = 0; i < blocks; ++i, dst += 4)
    {
        tmp.dw = U32(lrand());
        dst[0] = tmp.b[3];
        dst[1] = tmp.b[2];
        dst[2] = tmp.b[1];
        dst[3] = tmp.b[0];
    }

    uint32_t j = 0;
    /* Full fill left bytes */
    while (left--)
    {
        dst[0 + j++] = tmp.b[left];
    }

#endif /* PLATFORM_LE */

}


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
    mbcrypt_status_e sec_ret = 0;
    
    ASSERT(sha256(_seed, BASE_SEED_SIZE, hash) == MBCRYPT_STATUS_OK, "SHA256 return status not OK!")
    
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
