#include "webp_huff.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t bits;
    uint16_t symbol;
} huff_entry_t;

static uint16_t read16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static int parse_header(const uint8_t *data, size_t len, size_t *pos, uint16_t *alphabet)
{
    if (len < 8 || memcmp(data, "MVP8", 4) != 0) return -1;
    *alphabet = read16(data + 4);
    *pos = 8;
    return *alphabet >= 4 ? 0 : -1;
}

static size_t estimate_table_size(uint16_t alphabet, uint8_t max_bits)
{
    size_t base = (size_t)alphabet + 8;
    if (max_bits <= 8) return base;
    return base + 32;
}

static int build_huffman_table(huff_entry_t *table, size_t table_cap,
                               const uint8_t *lengths, uint16_t count)
{
    size_t out = 0;
    for (uint16_t sym = 0; sym < count; sym++) {
        uint8_t bits = lengths[sym] & 0x1f;
        if (bits == 0) continue;
        size_t replicas = (bits > 8) ? ((size_t)1 << (bits - 8)) : 1;
        for (size_t r = 0; r < replicas; r++) {
            (void)table_cap;
            table[out].bits = bits;
            table[out].symbol = sym;
            out++;
        }
    }
    return (int)out;
}

int webp_huff_decode(const uint8_t *data, size_t len)
{
    size_t pos = 0;
    uint16_t alphabet = 0;
    if (parse_header(data, len, &pos, &alphabet) != 0) return -1;
    if (pos + alphabet > len) return -1;

    uint8_t max_bits = 0;
    for (uint16_t i = 0; i < alphabet; i++) {
        if ((data[pos + i] & 0x1f) > max_bits) max_bits = data[pos + i] & 0x1f;
    }

    size_t cap = estimate_table_size(alphabet, max_bits);
    huff_entry_t *table = (huff_entry_t *)calloc(cap, sizeof(*table));
    if (!table) return -1;

    int built = build_huffman_table(table, cap, data + pos, alphabet);
    int score = built;
    if (built > 0 && pos + alphabet < len) {
        score += table[data[pos + alphabet] % (size_t)built].symbol;
    }
    free(table);
    return score;
}
