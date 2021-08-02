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
*   @file bignum.h
*   @brief File contains big number API functions.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.02
*/
#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdio.h>
#include <stdint.h>

typedef uint32_t bignum_uint;
typedef int32_t bignum_int;

#define BIG_NUM_MAX_LIMBS 1000

typedef struct bignum_t
{
    int32_t sign;
    uint32_t size;
    bignum_uint *p;
} bignum_t;
#ifdef __cplusplus
extern "C" {
#endif

void bignum_init(bignum_t *x);

void bignum_free(bignum_t *x);

int32_t bignum_grow(bignum_t *x, uint32_t nblimbs);

int32_t bignum_shrink(bignum_t *x, uint32_t nblimbs);

int32_t bignum_copy(bignum_t *dst_x, const bignum_t *src_x);

void bignum_swap(bignum_t *x, bignum_t *y);

int32_t bignum_lset(bignum_t *x, bignum_int z);

uint32_t bignum_lsb(const bignum_t *x);

uint32_t bignum_bitlen(const bignum_t *x);

uint32_t bignum_size(const bignum_t *x);

uint32_t bignum_add(bignum_t *x, const bignum_t *a, const bignum_t *b);

char *bignum_to_dec_string(const bignum_t *x);

char *bignum_to_hex_string(const bignum_t *x);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BIGNUM_H */