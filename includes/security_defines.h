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
*   @file security_defines.h
*   @brief File contains key definitions for security configuration file.
*	@author Zontec
*	@version 1.1
*	@date 2021.06.18
*/

#ifndef SECURITY_DEFINES_H
#define SECURITY_DEFINES_H


#ifndef ENABLED
    #define ENABLED                 (1)
#endif


#ifndef DISABLED
    #define DISABLED                (0)
#endif


/**
 * @brief MIN_SECURITY_LEVEL has no any additional protection for crypto algorithms.
 */
#ifndef MIN_SECURITY_LEVEL
    #define MIN_SECURITY_LEVEL      (0)
#endif


/**
 * @brief MID_SECURITY_LEVEL provides some basic protection that has no big influence
 * on algorithms performance.
 */
#ifndef MID_SECURITY_LEVEL
    #define MID_SECURITY_LEVEL      (1)
#endif


/**
 * @brief MAX_SECURITY_LEVEL provides all available 
 * protection for any crypto function.
 */
#ifndef MAX_SECURITY_LEVEL
    #define MAX_SECURITY_LEVEL      (2)
#endif


#endif /* SECURITY_DEFINES_H */