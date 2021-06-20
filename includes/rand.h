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
*   @file rand.h
*   @brief File contains API for PRNG functions.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.19
*/
#ifndef RAND_H
#define RAND_H

#include "security.h"

/**
 * @brief PRNG function
 * 
 * @return int32_t random number
 */
int32_t rand();

/**
 * @brief Set new seed for PRNG
 * 
 * @param seed Seed to be set for PRNG
 */
void srand(uint32_t seed);

#endif /* RAND_H */