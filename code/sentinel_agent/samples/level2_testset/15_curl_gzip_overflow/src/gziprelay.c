#include "gziprelay.h"

#include <stdlib.h>
#include <string.h>

/*
 * Minimal, reachable model for CVE-2025-0725. It is intentionally not a
 * copy of libcurl. The 16-bit size calculation models an unsafe decompressor
 * output-size planning step: a high expansion ratio wraps an 8-bit allocation,
 * while the expansion loop still writes 64 output bytes per input byte.
 */
int gziprelay_decode(const uint8_t *wire, size_t wire_len)
{
    if (!wire || wire_len < 2) return -1;

    size_t encoded_len = wire_len - 2;
    uint8_t decoded_len = (uint8_t)(encoded_len * 64);
    uint8_t *decoded = (uint8_t *)malloc(decoded_len ? decoded_len : 1);
    if (!decoded) return -1;

    /* This local copy is valid for the small seed but lacks a proven capacity relation. */
    memcpy(decoded, wire + 2, encoded_len);

    uint8_t checksum = 0;
    for (size_t i = 0; i < encoded_len; i++) {
        size_t out = i * 64;
        decoded[out + 0] = wire[i + 2];
        decoded[out + 1] = wire[i + 2] ^ 0x5a;
        decoded[out + 2] = wire[i + 2] ^ 0xa5;
        decoded[out + 63] = 0;
        checksum ^= decoded[out];
    }

    free(decoded);
    return checksum == 0xff ? 1 : 0;
}
