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
*   @file aes.h
*   @brief File contains AES API functions.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.02
*/

#ifndef AES_H
#define AES_H

#include "mbcrypt.h"

#define AES_BLOCK_SIZE              (16)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum aes_type_e
{
    AES128 = 0,
    AES192 = 1,
    AES256 = 2,
} aes_type_e;

typedef enum aes_mode_e
{
    AES_ECB =   0,
    AES_CBC =   1,
    AES_OFB =   2,
    AES_CFB =   3,
    AES_CTR =   4,
    AES_GCM =   5,
    AES_AEAD =  6,
    AES_XTS  =  7,
} aes_mode_e;

typedef enum aes_key_expansion_hash_type_e
{
    AES_KEY_EXPANSION_SHA1 =            0,
    AES_KEY_EXPANSION_SHA256 =          1,
    AES_KEY_EXPANSION_SHA512 =          2,
    AES_KEY_EXPANSION_NOT_REQUIRED =    3,
} aes_key_expansion_hash_type_e;

typedef struct aes_key_t
{
    uint8_t *w;
    aes_type_e aes_type;
} aes_key_t;

typedef struct aes_input_t
{
    uint8_t *key;
    uint32_t *key_len;
    uint8_t *data;
    uint32_t *data_len;
    uint8_t *iv;
    uint32_t *iv_len;
    uint8_t *auth_data;
    uint32_t auth_data_len;
} aes_input_t;

typedef struct aes_output_t
{
    uint8_t *out;
    uint32_t out_len;
    uint8_t *tag;
    uint32_t tag_len;
} aes_output_t;

mbcrypt_status_e aes_key_init(aes_type_e aes_type, aes_key_t *aes_key);

mbcrypt_status_e aes_key_expand(aes_key_expansion_hash_type_e key_exp_hash_type,
                                    const uint8_t *key_in, uint32_t key_in_len, aes_key_t *key_out);

mbcrypt_status_e aes_ecb_encrypt_ex(aes_type_e aes_type, aes_key_expansion_hash_type_e key_exp_hash_type, 
                                const uint8_t *data, uint32_t data_len, 
                                uint8_t *key, uint32_t key_len, uint8_t *out);

void aes_key_free(aes_key_t *aes_key);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_H */