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
*   @file sha1.h
*   @brief File contains SHA1 API functions.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.19
*/

#ifndef SHA1_H
#define SHA1_H

#include "mbcrypt.h"

#define MBCRYPT_SHA1_HASH_SIZE              (20)
#define MBCRYPT_SHA1_BUFFER_SIZE            (64)

typedef struct mbcrypt_sha1_t
{
    uint32_t h0;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t h4;
    uint32_t total[2];
    uint8_t buffer[MBCRYPT_SHA1_BUFFER_SIZE];
} mbcrypt_sha1_t;


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function inits sha1 context with default values
 * 
 * @param[in,out] ctx SHA context to be initialized
 * @return mbcrypt_status_e 
 */
mbcrypt_status_e MBCRYPT_API mbcrypt_sha1_init(mbcrypt_sha1_t *ctx);

/**
 * @brief Function updates the context with new hash computations based on 
 * input data.
 * 
 * @param[in,out] ctx SHA1 context
 * @param[in] data Input data to be hashed
 * @param[in] data_len Input data len
 * @return mbcrypt_status_e 
 */
mbcrypt_status_e MBCRYPT_API mbcrypt_sha1_update(mbcrypt_sha1_t *ctx, 
                                            const uint8_t *data, uint32_t data_len);

/**
 * @brief Function finishes computations and produce final hash
 * 
 * @param[in] ctx SHA1 context
 * @param[out] out Output hash. Should be at least allocated SHA1_HASH_SIZE memory
 * @return mbcrypt_status_e 
 */
mbcrypt_status_e MBCRYPT_API mbcrypt_sha1_final(mbcrypt_sha1_t *ctx, uint8_t *out);

/**
 * @brief Function implements step be step three functions: 
 * mbcrypt_sha1_init, sha1_update, sha1_finish
 * 
 * @param[in] data Input data to be hashed
 * @param[in] data_len Input data len
 * @param[out] out Output hash. Should be at least allocated SHA1_HASH_SIZE memory
 * @return mbcrypt_status_e 
 */
mbcrypt_status_e MBCRYPT_API mbcrypt_sha1(const uint8_t *data, 
                                    uint32_t data_len, uint8_t *out);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SHA1_H */
