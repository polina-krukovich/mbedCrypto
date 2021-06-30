#include "security_utils.h"

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
