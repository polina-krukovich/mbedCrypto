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
*   @file mbcrypt_defines.h
*   @brief File contains key definitions for mbcrypt configuration file.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.18
*/

#ifndef MBCRYPT_DEFINES_H
#define MBCRYPT_DEFINES_H


#ifndef ENABLED
    #define ENABLED                 (1)
#endif


#ifndef DISABLED
    #define DISABLED                (0)
#endif


/**
 * @brief MIN_MBCRYPT_LEVEL has no any additional protection for crypto algorithms.
 */
#ifndef MIN_MBCRYPT_LEVEL
    #define MIN_MBCRYPT_LEVEL      (0)
#endif


/**
 * @brief MID_MBCRYPT_LEVEL provides some basic protection that has no big influence
 * on algorithms performance.
 */
#ifndef MID_MBCRYPT_LEVEL
    #define MID_MBCRYPT_LEVEL      (1)
#endif


/**
 * @brief MAX_MBCRYPT_LEVEL provides all available 
 * protection for any crypto function.
 */
#ifndef MAX_MBCRYPT_LEVEL
    #define MAX_MBCRYPT_LEVEL      (2)
#endif


#endif /* MBCRYPT_DEFINES_H */