#ifndef WEBP_HUFF_H
#define WEBP_HUFF_H
#include <stddef.h>
#include <stdint.h>
int webp_huff_decode(const uint8_t *data, size_t len);
#endif
