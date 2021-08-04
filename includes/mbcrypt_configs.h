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
*   @file mbcrypt_configs.h
*   @brief File contains configuarations for a library.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.02
*/

#ifndef MBCRYPT_CONFIGS_H
#define MBCRYPT_CONFIGS_H

#include "mbcrypt_defines.h"


/**
 * @brief MBCRYPT_LEVEL provides the library which way it should implement 
 * algorithms. In some cases higher level provides higher time consumption.
 */
#ifndef MBCRYPT_LEVEL
	#define MBCRYPT_LEVEL                            (MIN_MBCRYPT_LEVEL)
#endif /* MBCRYPT_LEVEL */



/**
 * @brief SHA256 as PRNG
 */
#define RAND_PRNG_SHA256           					  (ENABLED)


/**
 * @brief Counter mode for Deterministic Random Bit Generator
 */
#define RAND_CTR_DRBG           					  (DISABLED)


/**
 * @brief Dual Elliptic Curve mode for Deterministic Random Bit Generator
 */
#define RAND_DUAL_EC_DRBG       					  (DISABLED)


#if (RAND_CTR_DRBG + RAND_DUAL_EC_DRBG + RAND_PRNG_SHA256 != 1)
	#error "Only one option for RAND can be enabled"
#endif


/**
 * @brief PBKDF2_HMAC_SHA1 does enable or disable PBKDF2(PKCS #5 v2.0 - RFC 2898)
 *  with HMAC function based on SHA1. 
 */
#ifndef PBKDF2_HMAC_SHA1
	#define PBKDF2_HMAC_SHA1                          (ENABLED) 
#endif


/**
 * @brief PBKDF2_HMAC_SHA256 does enable or disable PBKDF2(PKCS #5 v2.0 - RFC 2898)
 *  with HMAC function based on SHA256. 
 */
#ifndef PBKDF2_HMAC_SHA256
	#define PBKDF2_HMAC_SHA256                        (ENABLED) 
#endif


/**
 * @brief PBKDF2_HMAC_SHA512 does enable or disable PBKDF2(PKCS #5 v2.0 - RFC 2898)
 *  with HMAC function based on SHA512. 
 */
#ifndef PBKDF2_HMAC_SHA512
	#define PBKDF2_HMAC_SHA512                        (ENABLED) 
#endif


/**
 * @brief When SECURED_SHA1 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_SHA1
	#define SECURED_SHA1                        	  (ENABLED)
#endif


/**
 * @brief When SECURED_SHA256 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_SHA256
	#define SECURED_SHA256                      	  (ENABLED)
#endif


/**
 * @brief When SECURED_SHA512 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_SHA512
	#define SECURED_SHA512                      	  (ENABLED)
#endif


/**
 * @brief When SECURED_HMAC_SHA1 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_HMAC_SHA1
	#define SECURED_HMAC_SHA1                        (ENABLED)
#endif 


/**
 * @brief When SECURED_HMAC_SHA256 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_HMAC_SHA256
	#define SECURED_HMAC_SHA256                      (ENABLED)
#endif


/**
 * @brief When SECURED_HMAC_SHA512 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_HMAC_SHA512
	#define SECURED_HMAC_SHA512                      (ENABLED)
#endif


/**
 * @brief When SECURED_PBKDF2_HMAC_SHA1 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_PBKDF2_HMAC_SHA1
	#define SECURED_PBKDF2_HMAC_SHA1                 (ENABLED)
#endif 


/**
 * @brief When SECURED_PBKDF2_HMAC_SHA256 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_PBKDF2_HMAC_SHA256
	#define SECURED_PBKDF2_HMAC_SHA256               (ENABLED)
#endif


/**
 * @brief When SECURED_PBKDF2_HMAC_SHA512 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_PBKDF2_HMAC_SHA512
	#define SECURED_PBKDF2_HMAC_SHA512               (ENABLED)
#endif


/**
 * @brief When SECURED_KBKDF_HMAC_SHA1 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_KBKDF_HMAC_SHA1
	#define SECURED_KBKDF_HMAC_SHA1                  (ENABLED)
#endif 


/**
 * @brief When SECURED_KBKDF_HMAC_SHA256 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_KBKDF_HMAC_SHA256
	#define SECURED_KBKDF_HMAC_SHA256                (ENABLED)
#endif


/**
 * @brief When SECURED_KBKDF_HMAC_SHA512 is enabled algorithm get rid of mbcrypt 
 * sensitive data after that.
 */
#ifndef SECURED_KBKDF_HMAC_SHA512
	#define SECURED_KBKDF_HMAC_SHA512                (ENABLED)
#endif


/**
 * @brief When this macro is enabled algorithm try to implementation that
 * takes less physical memory but much time.
 */
#ifndef SHA1_MIN_SIZE
	#define SHA1_MIN_SIZE                            (ENABLED)
#endif

/**
 * @brief When this macro is enabled algorithm try to implementation that
 * takes less physical memory but much time.
 */
#ifndef SHA256_MIN_SIZE
	#define SHA256_MIN_SIZE                          (ENABLED)
#endif

/**
 * @brief When this macro is enabled algorithm try to implementation that
 * takes less physical memory but much time.
 */
#ifndef SHA512_MIN_SIZE
	#define SHA512_MIN_SIZE                          (ENABLED)
#endif

/**
 * @brief When this macro is enabled algorithm try to implementation that
 * takes less physical memory but much time.
 */
#ifndef HMAC_SHA1_MIN_SIZE
	#define HMAC_SHA1_MIN_SIZE                       (ENABLED)
#endif

/**
 * @brief When this macro is enabled algorithm try to implementation that
 * takes less physical memory but much time.
 */
#ifndef HMAC_SHA256_MIN_SIZE
	#define HMAC_SHA256_MIN_SIZE                     (ENABLED)
#endif

/**
 * @brief When this macro is enabled algorithm try to implementation that
 * takes less physical memory but much time.
 */
#ifndef HMAC_SHA512_MIN_SIZE
	#define HMAC_SHA512_MIN_SIZE                     (ENABLED)
#endif

/**
 * @brief When this macro is enabled algorithm try to implementation that
 * takes less physical memory but much time.
 */
#ifndef PBKDF2_MIN_SIZE
	#define PBKDF2_MIN_SIZE                			 (ENABLED)
#endif

/**
 * @brief When this macro is enabled algorithm try to implementation that
 * takes less physical memory but much time.
 */
#ifndef KBKDF_MIN_SIZE
	#define KBKDF_MIN_SIZE                 			 (ENABLED)
#endif


#endif /* MBCRYPT_CONFIGS_H */