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
*	@date 2021.07.04
*/

#ifndef AES_H
#define AES_H

#include "mbcrypt.h"

#define MBCRYPT_AES_BLOCK_SIZE          (16)


typedef enum mbcrypt_aes_type_e
{
    AES128 = 0,
    AES192 = 1,
    AES256 = 2,
} mbcrypt_aes_type_e;

typedef enum mbcrypt_aes_mode_e
{
    MBCRYPT_AES_ECB =   0,
    MBCRYPT_AES_CBC =   1,
    MBCRYPT_AES_OFB =   2,
    MBCRYPT_AES_CFB =   3,
    MBCRYPT_AES_CTR =   4,
    MBCRYPT_AES_GCM =   5,
    MBCRYPT_AES_AEAD =  6,
    MBCRYPT_AES_XTS  =  7,
} mbcrypt_aes_mode_e;

typedef enum mbcrypt_aes_key_expansion_hash_type_e
{
    MBCRYPT_AES_KEY_EXPANSION_SHA1 =            0,
    MBCRYPT_AES_KEY_EXPANSION_SHA256 =          1,
    MBCRYPT_AES_KEY_EXPANSION_SHA512 =          2,
    MBCRYPT_AES_KEY_EXPANSION_NOT_REQUIRED =    3,
} mbcrypt_aes_key_expansion_hash_type_e;

typedef struct mbcrypt_aes_key_t
{
    uint8_t *w;
    mbcrypt_aes_type_e mbcrypt_aes_type;
} mbcrypt_aes_key_t;

typedef struct mbcrypt_aes_input_t
{
    uint8_t *key;
    uint32_t *key_len;
    uint8_t *data;
    uint32_t *data_len;
    uint8_t *iv;
    uint32_t *iv_len;
    uint8_t *auth_data;
    uint32_t auth_data_len;
} mbcrypt_aes_input_t;

typedef struct mbcrypt_aes_output_t
{
    uint8_t *out;
    uint32_t out_len;
    uint8_t *tag;
    uint32_t tag_len;
} mbcrypt_aes_output_t;


#ifdef __cplusplus
extern "C" {
#endif

mbcrypt_status_e mbcrypt_aes_key_init(mbcrypt_aes_type_e mbcrypt_aes_type, 
                                        mbcrypt_aes_key_t *mbcrypt_aes_key);

mbcrypt_status_e mbcrypt_aes_key_expand(mbcrypt_aes_key_expansion_hash_type_e key_exp_hash_type,
                                    const uint8_t *key_in, uint32_t key_in_len, mbcrypt_aes_key_t *key_out);

mbcrypt_status_e mbcrypt_aes_ecb_encrypt_ex(mbcrypt_aes_type_e mbcrypt_aes_type, 
                                mbcrypt_aes_key_expansion_hash_type_e key_exp_hash_type, 
                                const uint8_t *data, uint32_t data_len, 
                                uint8_t *key, uint32_t key_len, uint8_t *out);

void mbcrypt_aes_key_free(mbcrypt_aes_key_t *mbcrypt_aes_key);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_H */