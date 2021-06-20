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
*   @file kbkdf.h
*   @brief File contains API for KBKDf function.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.19
*/

#ifndef KBKDF_H
#define KBKDF_H

#include "security.h"

/**
 * @brief Hash type to be used in KBKDF
 */
typedef enum kbkdf_hash_type_e
{
    KBKDF_HASH_TYPE_SHA256 = 0,
    KBKDF_HASH_TYPE_SHA384 = 1,
    KBKDF_HASH_TYPE_SHA512 = 2,
} kbkdf_hash_type_e;

/**
 * @brief HMAC init callback
 */
typedef uint32_t(*hmac_init)(void *ctx, const uint8_t *key, const uint32_t key_size);
/**
 * @brief HMAC init update
 */
typedef uint32_t(*hmac_update)(void *ctx, 
                                const uint8_t *data, const uint32_t data_size);
/**
 * @brief HMAC init final
 */
typedef uint32_t(*hmac_final)(void *ctx, uint8_t *hmac);

/**
 * @brief Struct contains callbacks for hmac functions that used in KBKDF
 */
typedef struct kbkdf_hmac_callbacks_t
{
    hmac_init hmac_init;
    hmac_update hmac_update;
    hmac_final hmac_final;
} kbkdf_hmac_callbacks_t;

/**
 * @brief Extra options for KBKDf
 */
typedef struct kbkdf_opts_t
{
    uint32_t ctr_rlen; /* Counter len to be used in bytes. Can be from 1 to 4 bytes */
    int32_t ctr_rpos; /* Counter position. Can be less than 0 relatevly to fixed input*/
} kbkdf_opts_t;

/**
 * @brief KBKDF mode type
 * 
 */
typedef enum kbkdf_mode_e
{
    KBKDF_MODE_COUNTER = 0,
    KBKDF_MODE_FEEDBACK = 1,
    KBKDF_MODE_DOUBLE_PIPELINE = 2,
} kbkdf_mode_e;


#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief This function derives a key based on the provided key and fixed input string using HMAC KBKDF algorithm.
*
* @param[in] mode KBKDF mode to be used
* @param[in] hash_type Hash type to use in hmac
* @param[in] hmac_callbacks Input structure with HMAC callbacks
* @param[in] key_in Input key buffer
* @param[in] key_in_len Input key length in bytes
* @param[in] iv_in Input IV buffer
* @param[in] iv_in_len Input IV length in bytes
* @param[in] fixed_input Fixed input buffer
* @param[in] fixed_input_len Fixed input length in bytes
* @param[out] key_out Start address of the KBKDF key
* @param[in] key_out_len Required output key length
* @param[in] opts Counter options
* @return security_status_e
*/
security_status_e kbkdf(kbkdf_mode_e mode, kbkdf_hash_type_e hash_type,
                        kbkdf_hmac_callbacks_t hmac_callbacks,
                        const uint8_t* key_in, const uint32_t key_in_len,
                        const uint8_t* iv_in, const uint32_t iv_in_len,
                        uint8_t* fixed_input, const uint32_t fixed_input_len,
                        uint8_t* key_out, const uint32_t key_out_len,
                        kbkdf_opts_t* opts);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /* KBKDF_H */