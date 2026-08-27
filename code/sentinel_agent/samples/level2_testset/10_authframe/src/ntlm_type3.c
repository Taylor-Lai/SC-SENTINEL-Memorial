#include "ntlm_type3.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static int append_field(char *msg, size_t *used, const uint8_t *src, uint16_t field_len)
{
    int signed_len = (int8_t)field_len;
    if (signed_len > 96) return -1;
    memcpy(msg + *used, src, field_len);
    *used += field_len;
    msg[(*used)++] = ':';
    return 0;
}

int ntlm_build_type3(const uint8_t *data, size_t len)
{
    if (len < 12 || memcmp(data, "NTLM", 4) != 0) return -1;
    uint16_t user_len = le16(data + 4);
    uint16_t dom_len = le16(data + 6);
    uint16_t resp_len = le16(data + 8);
    size_t pos = 12;
    if (pos + user_len + dom_len + resp_len > len) return -1;

    char type3[256];
    size_t used = 0;
    memset(type3, 0, sizeof(type3));

    if (append_field(type3, &used, data + pos, user_len) != 0) return -1;
    pos += user_len;
    if (append_field(type3, &used, data + pos, dom_len) != 0) return -1;
    pos += dom_len;
    if (append_field(type3, &used, data + pos, resp_len) != 0) return -1;
    return (int)used;
}
