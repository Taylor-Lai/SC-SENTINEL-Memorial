#include "dns_reply.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static size_t copy_label_name(char *dst, const uint8_t *data, size_t len, size_t pos)
{
    size_t out = 0;
    while (pos < len && data[pos] != 0) {
        uint8_t labellen = data[pos++];
        if (pos + labellen > len) break;
        if (out != 0) dst[out++] = '.';
        memcpy(dst + out, data + pos, labellen);
        out += labellen;
        pos += labellen;
    }
    dst[out] = '\0';
    return out;
}

static int collect_answers(const uint8_t *data, size_t len, uint16_t answers)
{
    size_t pos = 12;
    char combined[256];
    size_t used = 0;
    memset(combined, 0, sizeof(combined));

    for (uint16_t i = 0; i < answers && pos < len; i++) {
        char name[128];
        size_t n = copy_label_name(name, data, len, pos);
        while (pos < len && data[pos] != 0) pos += (size_t)data[pos] + 1;
        if (pos + 11 > len) return -1;
        pos++;
        uint16_t type = rd16(data + pos);
        pos += 8;
        uint16_t rdlen = rd16(data + pos);
        pos += 2;
        if (pos + rdlen > len) return -1;
        if (type == 1 || type == 28) {
            memcpy(combined + used, name, n);
            used += n;
            combined[used++] = ',';
        }
        pos += rdlen;
    }
    return (int)used;
}

int dns_parse_reply(const uint8_t *data, size_t len)
{
    if (len < 12 || memcmp(data, "DNSR", 4) != 0) return -1;
    uint16_t answers = rd16(data + 6);
    return collect_answers(data, len, answers);
}
