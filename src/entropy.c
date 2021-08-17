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
*   @file entropy.c
*   @brief File contains entropy implementation.
*	@author Zontec
*	@version 1.1
*	@date 2021.07.04
*/

#include "entropy.h"


#if (MEASURE_ENTROPY == ENABLED)

#include <math.h>

#define ENTROPY_TESTS       (1000000)
#define ENTROPY_MOD         (1000)

double get_entropy(rnd_callback_t rnd)
{
    uint32_t cnt[ENTROPY_MOD] = {0};
    double sum = 0;

    for(uint32_t i = 0; i < ENTROPY_TESTS; ++i)
    {
        cnt[rnd() % ENTROPY_MOD]++;
    }

    for (uint32_t i = 0; i < ENTROPY_MOD; ++i)
    {
        if (cnt[i] == 0)
        {
            continue;
        }
        double p = (double)(cnt[i]) / (double)(ENTROPY_TESTS);
        sum += (p * log2(p));
    }
    sum *= -1;
    return sum;
}
#endif