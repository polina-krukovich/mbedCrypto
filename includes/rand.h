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
*   @file rand.h
*   @brief File contains API for rundom number and sequnces generating.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.19
*/
#ifndef RAND_H
#define RAND_H

#include "security.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set new seed for random functions
 * @param seed Seed to be set for random functions
 */
void srand(uint32_t seed);

/**
 * @brief Function generate determenistic rundom nambersed. It implements it 
 * based on 4 ways:
 * 1) If RAND_PRF macro is defined as RAND_PRF_SHA - SHA 256 with 
 * counter(inc seed) is used
 * 2) If RAND_PRF macro is defined as RAND_PRF_AES - AES 256 with 
 * counter(inc seed) is used
 * 3) If RAND_PRF macro is defined as RAND_PRF_FAST - fast option 
 * based on POSIX rand function
 * @return int32_t random number
 */
int32_t rand();

/**
 * @brief 
 * 
 * @return int32_t 
 */
int32_t secure_rand();

#ifdef HW_TRNG || DOXYGEN

/**
 * @brief True rundom number generator
 * 
 * @return int32_t 
 */
int32_t trng_rand();

#endif

void rand_bytes_ex(uint8_t *dst, uint32_t size, int32_t (*rnd_gen)());

void rand_bytes(uint8_t *dst, uint32_t size);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /* RAND_H */