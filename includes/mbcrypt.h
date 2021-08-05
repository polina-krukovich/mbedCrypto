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
*   @file mbcrypt.h
*   @brief File contains important function definitions for mbcrypt library.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.19
*/

#ifndef MBCRYPT_H
#define MBCRYPT_H

#include <stdlib.h>
#include <stdint.h>

#include "macros.h"
#include "mbcrypt_defines.h"
#include "mbcrypt_configs.h"



typedef uint32_t (*mbcrypt_hmac_init_t)(void * __restrict ctx,
                                        const uint8_t * __restrict key, uint32_t key_len);
typedef uint32_t (*mbcrypt_hmac_update_t)(void * __restrict ctx, 
                                        const uint8_t * __restrict data, uint32_t data_len);
typedef uint32_t (*mbcrypt_hmac_final_t)(void * __restrict ctx, 
                                        const uint8_t * __restrict hmac_out);

typedef uint32_t (*mbcrypt_hash_init_t)(void * __restrict ctx);

typedef uint32_t (*mbcrypt_hash_update_t)(void * __restrict ctx, 
                                        const uint8_t * __restrict data, uint32_t data_len);
                                    
typedef uint32_t (*mbcrypt_hash_final_t)(void * __restrict ctx, const uint8_t * __restrict hash_out);


typedef struct mbcrypt_hmac_callbacks_t{
    void *hmac_ctx;
    mbcrypt_hmac_init_t *hmac_init;
    mbcrypt_hmac_update_t *hmac_update;
    mbcrypt_hmac_final_t *hmac_final;
} mbcrypt_hmac_callbacks_t;


typedef struct mbcrypt_hash_callbacks_t{
    void *hash_ctx;
    mbcrypt_hash_init_t *hash_init;
    mbcrypt_hash_update_t *hash_update;
    mbcrypt_hash_final_t *hash_final;
} mbcrypt_hash_callbacks_t;

typedef enum mbcrypt_hash_type_e{
    MBCRYPT_HASH_TYPE_SHA1 =   0,
    MBCRYPT_HASH_TYPE_SHA224 = 1,
    MBCRYPT_HASH_TYPE_SHA256 = 2,
    MBCRYPT_HASH_TYPE_SHA384 = 3,
    MBCRYPT_HASH_TYPE_SHA512 = 4,
    MBCRYPT_HASH_TYPE_MD5    = 5,
} mbcrypt_hash_type_e;

static const uint32_t hash_size_lookup[] = {
    20,
    28,
    32,
    48,
    64,
    16,
};

#define GET_HASH_SIZE_BY_HASH_TYPE(hash_type) hash_size_lookup[hash_type]

/**
 * @brief Should be defined a safe function for memset with no return value.
 * By default: memset
 */
#ifndef memset_safe
    #define memset_safe                           memset
#endif 

#ifndef mem_xor
    #define mem_xor                               mem_xor_secured
#endif 

#define MAX_BYTE_VALUE                            0xFF
#define MAX_SHORT_VALUE                           0xFFFF
#define MAX_WORD_VALUE                            0xFFFFFFFF
#define MAX_DWORD_VALUE                           0xFFFFFFFFFFFFFFFF

#define MBCRYPT_API

#define MBCRYPT_FUNCTION_EXIT                    mbcrypt_exit
#define MBCRYPT_FUNCTION_RET_VAR                 mbcrypt_ret
#define MBCRYPT_FUNCTION_BEGIN                   mbcrypt_status_e MBCRYPT_FUNCTION_RET_VAR = \
                                                    MBCRYPT_STATUS_OK;
#define MBCRYPT_FUNCTION_RETURN                  return MBCRYPT_FUNCTION_RET_VAR;

/**
 * @brief Macro for checking pointer value. if NULL then jumps MBCRYPT_FUNCTION_EXIT
 */
#define MBCRYPT_CHECK_VALID_NOT_NULL(x)         \
do{                                             \
    if ((x) == NULL)                            \
    {                                           \
        MBCRYPT_FUNCTION_RET_VAR =              \
        MBCRYPT_STATUS_FAIL_NULL_PTR;           \
        goto MBCRYPT_FUNCTION_EXIT;             \
    }                                           \
} while (0)                                     \

/**
 * @brief Macro for checking mbcrypt function result. 
 * if not MBCRYPT_STATUS_OK then jumps MBCRYPT_FUNCTION_EXIT
 */
#define MBCRYPT_CHECK_RES(x)                    \
do{                                             \
    if (MBCRYPT_FUNCTION_RET_VAR = (x)          \
        != MBCRYPT_STATUS_OK)                   \
    {                                           \
        goto MBCRYPT_FUNCTION_EXIT;             \
    }                                           \
} while (0)                                     \


/**
 * @brief Contains enums with error status codes for mbcrypt functions
 */
typedef enum 
{
    MBCRYPT_STATUS_OK =                                0x00000000,
    MBCRYPT_STATUS_FAIL =                              0x0000000A,
    MBCRYPT_STATUS_FAIL_NOT_IMPLEMENTED =              0x0000000B,
    MBCRYPT_STATUS_FAIL_MEMORY_ALLOCATION_ERROR =      0x0000000C,
    MBCRYPT_STATUS_FAIL_NULL_PTR =                     0x0000000D,
    MBCRYPT_STATUS_FAIL_INCORRECT_FUNCTION_PARAM =     0x0000000E,
} mbcrypt_status_e;


#endif /* MBCRYPT_H */