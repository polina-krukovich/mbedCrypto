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
*   @file rc4.c
*   @brief File contains RC4 implementation.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.04
*/

#include "rc4.h"


#define ROUNDS                  (256)

#define IS_POWER_OF_2(x)        !((x) & (x-1))

#if IS_POWER_OF_2(ROUND)
#define MOD(x)    & U32((x)-1)
#else
#define MOD(x)    % U32(x)
#endif /* MOD */


/* ONE_ROUND define */
#define ONE_ROUND \
        do {                                                            \
            j = (j + U32(s[i]) + U32(key[i % key_len])) MOD(rounds);    \
            swap8u(&s[i], &s[j]);                                       \
            ++i;                                                        \
        } while (0);


static void swap8u(uint8_t *a, uint8_t *b) 
{
    uint8_t tmp = *a;
    *a = *b;
    *b = tmp;
}

static void ksa(uint8_t *key, uint32_t key_len, uint8_t *s) 
{
    for (uint32_t i = 0; i < ROUNDS; ++i)
    {
        s[i] = i;
    }

    uint32_t j = 0;
    const uint32_t rounds = U32(ROUNDS);

    for(uint32_t i = 0; i < rounds;) 
    {
#if defined(RC4_MIN_SIZE) && (ROUNDS % 2 == 0)
        ONE_ROUND;
        ONE_ROUND;
#if (ROUNDS % 4 == 0)
        ONE_ROUND;
        ONE_ROUND;
#endif
#if (ROUNDS % 8 == 0)
        ONE_ROUND;
        ONE_ROUND;
        ONE_ROUND;
        ONE_ROUND;
#endif
#else
        ONE_ROUND;
#endif
    }
}


void rc4(uint8_t *key, uint32_t key_len, uint8_t *data, uint32_t data_len, uint8_t *out, uint32_t skip) 
{

    uint8_t s[ROUNDS] = {0};

    uint32_t k = 0;
    uint32_t j = 0;
    uint32_t t = 0;

    const uint32_t rounds = U32(ROUNDS);

    ksa(key, key_len, s);

    while(skip--)
    {
        k = (k + 1) MOD(rounds);           
        j = (j + s[k]) MOD(rounds);        
        swap8u(&s[k], &s[j]);    
    }
 
    for (uint32_t i = 0; i < data_len; ++i)
    {
        k = (k + 1) MOD(rounds);           
        j = (j + s[k]) MOD(rounds);        
        swap8u(&s[k], &s[j]);  

        t = s[(s[k] + s[j]) MOD(rounds)];
        out[i] = t ^ data[i];
    }
}
