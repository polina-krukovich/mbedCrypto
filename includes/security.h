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
*   @file security.h
*   @brief File contains important function definitions for security library.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.19
*/

#ifndef SECURITY_H
#define SECURITY_H

#include <stdlib.h>
#include <stdint.h>

#include "macros.h"
#include "security_defines.h"
#include "security_configs.h"



typedef uint32_t (*hmac_init_t)(void * __restrict, const uint8_t * __restrict, uint32_t );
typedef uint32_t (*hmac_update_t)(void * __restrict, const uint8_t * __restrict, uint32_t );
typedef uint32_t (*hmac_final_t)(void * __restrict, const uint8_t * __restrict);

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

#define SECURITY_API

#define SECURITY_FUNCTION_EXIT                    sec_exit
#define SECURITY_FUNCTION_RET_VAR                 sec_ret
#define SECURITY_FUNCTION_BEGIN                   security_status_e SECURITY_FUNCTION_RET_VAR = \
                                                    SECURITY_STATUS_OK;
#define SECURITY_FUNCTION_RETURN                  return SECURITY_FUNCTION_RET_VAR;

/**
 * @brief Macro for checking pointer value. if NULL then jumps SECURITY_FUNCTION_EXIT
 */
#define SECURITY_CHECK_VALID_NOT_NULL(x)        \
do{                                             \
    if ((x) == NULL)                            \
    {                                           \
        SECURITY_FUNCTION_RET_VAR =             \
        SECURITY_STATUS_FAIL_NULL_PTR;          \
        goto SECURITY_FUNCTION_EXIT;            \
    }                                           \
} while (0)                                     \

/**
 * @brief Macro for checking security function result. 
 * if not SECURITY_STATUS_OK then jumps SECURITY_FUNCTION_EXIT
 */
#define SECURITY_CHECK_RES(x)                   \
do{                                             \
    if (SECURITY_FUNCTION_RET_VAR = (x)         \
        != SECURITY_STATUS_OK)                  \
    {                                           \
        goto SECURITY_FUNCTION_EXIT;            \
    }                                           \
} while (0)                                     \


/**
 * @brief Contains enums with error status codes for security functions
 */
typedef enum 
{
    SECURITY_STATUS_OK =                                0x00000000,
    SECURITY_STATUS_FAIL =                              0x0000000A,
    SECURITY_STATUS_FAIL_NOT_IMPLEMENTED =              0x0000000B,
    SECURITY_STATUS_FAIL_MEMORY_ALLOCATION_ERROR =      0x0000000C,
    SECURITY_STATUS_FAIL_NULL_PTR =                     0x0000000D,
    SECURITY_STATUS_FAIL_INCORRECT_FUNCTION_PARAM =     0x0000000E,
} security_status_e;


#endif /* SECURITY_H */