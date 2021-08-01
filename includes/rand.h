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

#define BASE_SEED_SIZE      (64)

#ifdef __cplusplus
extern "C" {
#endif


typedef int32_t (*rnd_callback_t)();

/**
 * @brief Count entropy for a specialized random generator
 * @param rnd Function that entropy should be counted for
 * @return Counted entropy
 */
double get_entropy(rnd_callback_t rnd);

/**
 * @brief Set new seed for random functions
 * @param seed Seed to be set for random functions
 */
void srand(uint32_t seed);

/**
 * @brief Set new seed with a byte array for random functions
 * @param seed Seed to be set for random functions
 * @param seed_len Seed length. Shouldn't be more than BASE_SEED_SIZE. In that case seed will be full
 * filled with only first BASE_SEED_SIZE numebrs. If seed len less than BASE_SEED_SIZE
 * will be padded as PKCS7 standart
 */
void srand_bytes(uint8_t *seed, uint32_t seed_len);

/**
 * @brief Function generate deterministic random number
 * @return Random number
 */
int32_t rand();

/**
 * @brief Function generate an array of bytes
 * @param dst Destination array random bytes to be saved
 * @param size Number of random bytes to be generated
 * @param rnd Random number function generator
 */
void rand_bytes_ex(uint8_t *dst, uint32_t size, rnd_callback_t rnd);

/**
 * @brief Function generate an array of bytes
 * @param dst Destination array random bytes to be saved
 * @param size Number of random bytes to be generated
 */
void rand_bytes(uint8_t *dst, uint32_t size);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* RAND_H */