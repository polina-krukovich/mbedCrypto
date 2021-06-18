#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdlib.h>
#include <stdint.h>

#include "macros.h"
#include "security_defines.h"
#include "security_configs.h"

#define memset_safe memset

#define MAX_BYTE_VALUE              0xFF
#define MAX_SHORT_VALUE             0xFFFF
#define MAX_WORD_VALUE              0xFFFFFFFF
#define MAX_DWORD_VALUE             0xFFFFFFFFFFFFFFFF


typedef enum security_status_e
{
    SECURITY_STATUS_OK =                                0x00000000,
    SECURITY_STATUS_FAIL =                              0x0000000A,
    SECURITY_STATUS_FAIL_NOT_IMPLEMENTED =              0x0000000B,
    SECURITY_STATUS_FAIL_MEMORY_ALLOCATION_ERROR =      0x0000000C,
    SECURITY_STATUS_FAIL_NULL_PTR =                     0x0000000D,
    SECURITY_STATUS_FAIL_INCORRECT_FUNCTION_PARAM =     0x0000000E,
} security_status_e;

#define SECURITY_API

#define SECURITY_FUNCTION_EXIT                    sec_exit

#define SECURITY_FUNCTION_RET_VAR                 sec_ret

#define SECURITY_FUNCTION_BEGIN                   security_status_e SECURITY_FUNCTION_RET_VAR = \
                                                    SECURITY_STATUS_OK;

#define SECURITY_FUNCTION_RETURN                  return SECURITY_FUNCTION_RET_VAR;


#define SECURITY_CHECK_VALID_NOT_NULL(x)    \
do{                                         \
    if ((x) == NULL)                        \
    {                                       \
        SECURITY_FUNCTION_RET_VAR =         \
        SECURITY_STATUS_FAIL_NULL_PTR;      \
        goto SECURITY_FUNCTION_EXIT;        \
    }                                       \
} while (0)                                 \


#define SECURITY_CHECK_RES(x)               \
do{                                         \
    if (SECURITY_FUNCTION_RET_VAR = (x)     \
        != SECURITY_STATUS_OK)              \
    {                                       \
        goto SECURITY_FUNCTION_EXIT;        \
    }                                       \
} while (0)                                 \

#define SHA1_MIN_SIZE
#define SHA256_MIN_SIZE
#define SHA512_MIN_SIZE

#endif /*__SECURITY_H__*/