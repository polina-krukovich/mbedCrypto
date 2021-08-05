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
*   @file sha512.h
*   @brief File contains SHA512 API functions.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.19
*/

#ifndef SHA512_H
#define SHA512_H

#include "mbcrypt.h"

#define MBCRYPT_SHA512_HASH_SIZE              (64)
#define MBCRYPT_SHA512_BUFFER_SIZE            (128)

typedef struct mbcrypt_sha512_t
{
    uint64_t h0;
    uint64_t h1;
    uint64_t h2;
    uint64_t h3;
    uint64_t h4;
    uint64_t h5;
    uint64_t h6;
    uint64_t h7;
    uint32_t total[2];
    uint8_t buffer[MBCRYPT_SHA512_BUFFER_SIZE];
} mbcrypt_sha512_t;


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function inits sha512 context with default values
 * 
 * @param[in,out] ctx SHA context to be initialized
 * @return mbcrypt_status_e 
 */
mbcrypt_status_e MBCRYPT_API mbcrypt_sha512_init(mbcrypt_sha512_t *ctx);

/**
 * @brief Function updates the context with new hash computations based on 
 * input data.
 * 
 * @param[in,out] ctx SHA512 context
 * @param[in] data Input data to be hashed
 * @param[in] data_len Input data len
 * @return mbcrypt_status_e 
 */
mbcrypt_status_e MBCRYPT_API mbcrypt_sha512_update(mbcrypt_sha512_t *ctx, 
                                            const uint8_t *data, uint32_t data_len);

/**
 * @brief Function finishes computations and produce final hash
 * 
 * @param[in] ctx SHA512 context
 * @param[out] out Output hash. Should be at least allocated SHA512_HASH_SIZE memory
 * @return mbcrypt_status_e 
 */
mbcrypt_status_e MBCRYPT_API mbcrypt_sha512_final(mbcrypt_sha512_t *ctx, uint8_t *out);

/**
 * @brief Function implements step be step three functions: 
 * sha512_init, sha512_update, sha512_finish
 * 
 * @param[in] data Input data to be hashed
 * @param[in] data_len Input data len
 * @param[out] out Output hash. Should be at least allocated SHA512_HASH_SIZE memory
 * @return mbcrypt_status_e 
 */
mbcrypt_status_e MBCRYPT_API mbcrypt_sha512(const uint8_t *data, 
                                    uint32_t data_len, uint8_t *out);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SHA512_H */
