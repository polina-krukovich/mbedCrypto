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
*   @file hmac_sha1.h
*   @brief File contains HMAC SHA1 API functions.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.19
*/

#ifndef HMAC_H
#define HMAC_H


#include "mbcrypt.h"

#define HMAC_MAX_KEY_SIZE       (128)

typedef struct mbcrypt_hmac_t
{
    mbcrypt_hash_callbacks_t *cbs;
    mbcrypt_hash_type_e hash_type;
    uint8_t key[HMAC_MAX_KEY_SIZE];
} mbcrypt_hmac_t;


#ifdef __cplusplus
extern "C" {
#endif


mbcrypt_status_e MBCRYPT_API mbcrypt_hmac(mbcrypt_hash_type_e hash_type, mbcrypt_hash_callbacks_t *cbs, 
                                            const uint8_t *key, uint32_t key_len, 
                                            const uint8_t *data, uint32_t data_len, 
                                            uint8_t *out);

mbcrypt_status_e MBCRYPT_API mbcrypt_hmac_init(mbcrypt_hmac_t *ctx,
                                                const uint8_t *key, uint32_t key_len);

mbcrypt_status_e MBCRYPT_API mbcrypt_hmac_update(mbcrypt_hmac_t *ctx, 
                                                const uint8_t *data, uint32_t data_len);

mbcrypt_status_e MBCRYPT_API mbcrypt_hmac_final(mbcrypt_hmac_t *ctx, uint8_t *out);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HMAC_H */