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
*   @file rsa.c
*   @brief File contains RSA implementation.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.04
*/

#include "rsa.h"

typedef struct rsa_info_t 
{
    bignum_t N;
    bignum_t P;
    bignum_t Q;
    bignum_t Fn;
    bignum_t D;
    bignum_t E;
    uint32_t rsa_key_size;
} rsa_info_t;

void rsa()
{
    mp_int x, y, g, data, enc, dec, tmp;
    mp_int p, q, n, fn;
    mp_int e, d;

    mp_init(&x);
    mp_init(&y);
    mp_init(&g);
    mp_init(&data);
    mp_init(&enc);
    mp_init(&dec);
    mp_init(&tmp);
    mp_init(&p);
    mp_init(&q);
    mp_init(&n);
    mp_init(&fn);
    mp_init(&e);
    mp_init(&d);


    mp_zero(&x);
    mp_zero(&y);
    mp_zero(&g);
    mp_zero(&data);
    mp_zero(&enc);
    mp_zero(&dec);
    mp_zero(&tmp);
    mp_zero(&p);
    mp_zero(&q);
    mp_zero(&n);
    mp_zero(&fn);
    mp_zero(&e);
    mp_zero(&d);

    /* P */
    mp_set_u32(&p, 131);
    /* Q */
    mp_set_u32(&q, 127);
    /* Data */
    mp_set_u32(&data, 13524);
    /* E */
    mp_set_u32(&e, 17);
    /* N */
    mp_mul(&p, &q, &n);
    /* Fn = (p-1)*(q-1) */
    mp_decr(&p);
    mp_decr(&q);
    mp_mul(&p, &q, &fn);
    /* X and Y*/
    mp_exteuclid(&e, &fn, &x, &y, &g);
    /* D */

    mp_mul(&fn, &y, &tmp);
    mp_sub(&x, &tmp, &d);


    /* encrypt */
    rsa_procceed(&data, &e, &n, &enc);
    rsa_procceed(&enc, &d, &n, &tmp);

    printf("%d\n", mp_get_u32(&tmp));
}


void rsa_procceed(const bignum_t *restrict data, const bignum_t *restrict key, 
                    const bignum_t *restrict mod, const bignum_t *restrict res)
{
    mp_exptmod(data, key, mod, res);
}