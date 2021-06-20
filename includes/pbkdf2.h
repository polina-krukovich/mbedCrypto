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

#include "security.h"

#if (PBKDF2_HMAC_SHA1 == ENABLED) || defined(DOXYGEN)

/**
 * @brief PBKDF2 function that uses HMAC SHA1
 * 
 * @param[in] password Password for key derivation
 * @param[in] pass_len Password len
 * @param[in] salt PBKDF salt
 * @param[in] salt_len Salt len
 * @param[in] iters Number of iterations should be performed for key derivation
 * @param[out] out Derived key. Array should be out_len size at least
 * @param[in] out_len Key len in bytes.
 * @return security_status_e 
 */
security_status_e pbkdf2_hmac_sha1(const uint8_t *password, uint32_t pass_len,
                        const uint8_t *salt, uint32_t salt_len, uint32_t iters, 
                        uint8_t *out, uint32_t out_len);

#endif /* (PBKDF2_HMAC_SHA1 == ENABLED) */


#if (PBKDF2_HMAC_SHA256 == ENABLED) || defined(DOXYGEN)

/**
 * @brief PBKDF2 function that uses HMAC SHA256
 * 
 * @param[in] password Password for key derivation
 * @param[in] pass_len Password len
 * @param[in] salt PBKDF salt
 * @param[in] salt_len Salt len
 * @param[in] iters Number of iterations should be performed for key derivation
 * @param[out] out Derived key. Array should be out_len size at least
 * @param[in] out_len Key len in bytes.
 * @return security_status_e 
 */
security_status_e pbkdf2_hmac_sha256(const uint8_t *password, uint32_t pass_len,
                        const uint8_t *salt, uint32_t salt_len, uint32_t iters, 
                        uint8_t *out, uint32_t out_len);

#endif /* (PBKDF2_HMAC_SHA256 == ENABLED) */


#if (PBKDF2_HMAC_SHA512 == ENABLED) || defined(DOXYGEN)

/**
 * @brief PBKDF2 function that uses HMAC SHA512
 * 
 * @param[in] password Password for key derivation
 * @param[in] pass_len Password len
 * @param[in] salt PBKDF salt
 * @param[in] salt_len Salt len
 * @param[in] iters Number of iterations should be performed for key derivation
 * @param[out] out Derived key. Array should be out_len size at least
 * @param[in] out_len Key len in bytes.
 * @return security_status_e 
 */
security_status_e pbkdf2_hmac_sha512(const uint8_t *password, uint32_t pass_len,
                        const uint8_t *salt, uint32_t salt_len, uint32_t iters, 
                        uint8_t *out, uint32_t out_len);

#endif /* (PBKDF2_HMAC_SHA512 == ENABLED) */

#endif /* PBKDF2_H */