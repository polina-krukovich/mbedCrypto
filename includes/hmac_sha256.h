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
*   @file hmac_sha256.h
*   @brief File contains HMAC_SHA256 API functions.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.19
*/

#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include "security.h"
#include "sha256.h"

#define HMAC_SHA256_BLOCK_SIZE            (64)
#define HMAC_SHA256_HASH_SIZE             (SHA256_HASH_SIZE)


typedef struct hmac_sha256_t
{
    sha256_t sha_ctx;
    uint8_t key[HMAC_SHA256_BLOCK_SIZE];
} hmac_sha256_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function implements the following functions step by step:
 * hmac_sha256_init, hmac_sha256_update, hmac_sha256_finish
 * 
 * @param[in] key Key used for HMAC
 * @param[in] key_len Key len
 * @param[in] data Data to be used in HMAC
 * @param[in] data_len Data len
 * @param[out] out HMAC result. Array should be at least HMAC_SHA256_HASH_SIZE len
 * @return security_status_e 
 */
security_status_e SECURITY_API hmac_sha256(const uint8_t *key, uint32_t key_len, 
                                            const uint8_t *data, uint32_t data_len, 
                                            uint8_t *out);


/**
 * @brief Inits the context with the proper key
 * 
 * @param[in,out] ctx HMAC context
 * @param[in] key Key used for HMAC
 * @param[in] key_len Key len
 * @return security_status_e 
 */
security_status_e SECURITY_API hmac_sha256_init(hmac_sha256_t *ctx, 
                                                const uint8_t *key, uint32_t key_len);

/**
 * @brief Updates HMAC context with new data
 * 
 * @param[in,out] ctx HMAC context
 * @param[in] data Data to be used in HMAC
 * @param[in] data_len Data len
 * @return security_status_e 
 */
security_status_e SECURITY_API hmac_sha256_update(hmac_sha256_t *ctx, 
                                                const uint8_t *data, uint32_t data_len);


/**
 * @brief Finish computations and produce final HMAC result
 * 
 * @param[in] ctx HMAC context
 * @param[out] out HMAC result. Array should be at least HMAC_SHA256_HASH_SIZE len
 * @return security_status_e 
 */
security_status_e SECURITY_API hmac_sha256_finish(hmac_sha256_t *ctx, uint8_t *out);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /* HMAC_SHA256_H */