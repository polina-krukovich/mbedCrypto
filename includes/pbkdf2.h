#ifndef PBKDF2_H
#define PBKDF2_H

#include "security.h"

#if (PBKDF2_HMAC_SHA1 == ENABLED) || defined(DOXYGEN)

security_status_e pbkdf2_hmac_sha1(const uint8_t *password, uint32_t pass_len,
                        const uint8_t *salt, uint32_t salt_len, uint32_t iters, 
                        uint8_t *out, uint32_t out_len);

#endif /* (PBKDF2_HMAC_SHA1 == ENABLED) */


#if (PBKDF2_HMAC_SHA256 == ENABLED) || defined(DOXYGEN)

security_status_e pbkdf2_hmac_sha256(const uint8_t *password, uint32_t pass_len,
                        const uint8_t *salt, uint32_t salt_len, uint32_t iters, 
                        uint8_t *out, uint32_t out_len);

#endif /* (PBKDF2_HMAC_SHA256 == ENABLED) */


#if (PBKDF2_HMAC_SHA512 == ENABLED) || defined(DOXYGEN)

security_status_e pbkdf2_hmac_sha512(const uint8_t *password, uint32_t pass_len,
                        const uint8_t *salt, uint32_t salt_len, uint32_t iters, 
                        uint8_t *out, uint32_t out_len);

#endif /* (PBKDF2_HMAC_SHA512 == ENABLED) */

#endif /* PBKDF2_H */