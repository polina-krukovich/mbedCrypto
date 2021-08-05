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
*   @file pbkdf2.h
*   @brief File contains API for PBKDF functions.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.19
*/

#ifndef PBKDF2_H
#define PBKDF2_H

#include "mbcrypt.h"

#ifdef __cplusplus
extern "C" {
#endif


mbcrypt_status_e mbcrypt_pbkdf2_hmac(mbcrypt_hash_type_e hash_type, mbcrypt_hmac_callbacks_t *cbs,
                                        const uint8_t *password, uint32_t pass_len, 
                                        const uint8_t *salt, uint32_t salt_len, 
                                        uint32_t iters,
                                        uint8_t *out, uint32_t out_len);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PBKDF2_H */