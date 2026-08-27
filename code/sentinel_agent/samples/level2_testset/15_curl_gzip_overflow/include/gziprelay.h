#ifndef GZIPRELAY_H
#define GZIPRELAY_H

#include <stddef.h>
#include <stdint.h>

int gziprelay_decode(const uint8_t *wire, size_t wire_len);

#endif
