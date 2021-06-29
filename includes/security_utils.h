#ifndef SECURITY_UTILS_H
#define SECURITY_UTILS_H

#include "security.h"

#ifdef __cplusplus
extern "C" {
#endif

void mem_xor_secured(uint8_t *dst, const uint8_t *src, uint32_t size);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /* SECURITY_UTILS_H */