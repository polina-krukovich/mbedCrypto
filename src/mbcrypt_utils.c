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
*   @file mbcrypt_utils.c
*   @brief File contains mbcrypt utils implementation.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.04
*/

#include "mbcrypt_utils.h"

void mem_xor_secured(uint8_t *dst, const uint8_t *src, uint32_t size)
{
    if (!dst || !src)
    {
        return;
    }
    for (uint32_t i = 0; i < size; ++i)
    {
        dst[i] ^= src[i];
    }
}

uint32_t is_le()
{
    uint16_t d = 1;
    return (d & 0xff);
}

