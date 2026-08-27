#include "ssh_fingerprint.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *fingerprint;
    char host[64];
    int strict;
} ssh_session_t;

static char *make_fingerprint(const uint8_t *key, size_t key_len)
{
    char *fp = (char *)malloc(65);
    if (!fp) return NULL;
    for (size_t i = 0; i < 32; i++) {
        unsigned b = i < key_len ? key[i] : (unsigned)i;
        static const char hex[] = "0123456789abcdef";
        fp[i * 2] = hex[(b >> 4) & 0xf];
        fp[i * 2 + 1] = hex[b & 0xf];
    }
    fp[64] = '\0';
    return fp;
}

static int parse_record(ssh_session_t *s, const uint8_t *data, size_t len, const uint8_t **key, size_t *key_len)
{
    if (len < 8 || memcmp(data, "SSHK", 4) != 0) return -1;
    uint8_t host_len = data[4];
    if (5 + host_len + 1 > len) return -1;
    if (host_len >= sizeof(s->host)) host_len = sizeof(s->host) - 1;
    memcpy(s->host, data + 5, host_len);
    s->host[host_len] = '\0';
    s->strict = data[5 + host_len] & 1;
    *key = data + 6 + host_len;
    *key_len = len - (6 + host_len);
    return 0;
}

static int verify_known_host(ssh_session_t *s, const uint8_t *key, size_t key_len)
{
    s->fingerprint = make_fingerprint(key, key_len);
    if (!s->fingerprint) return -1;
    int mismatch = key_len > 0 && key[0] == 0xff;
    if (mismatch) {
        char *fp = s->fingerprint;
        free(s->fingerprint);
        s->fingerprint = NULL;
        if (s->strict) {
            return (unsigned char)fp[0];
        }
    }
    return 0;
}

int ssh_verify_record(const uint8_t *data, size_t len)
{
    ssh_session_t s;
    memset(&s, 0, sizeof(s));
    const uint8_t *key = NULL;
    size_t key_len = 0;
    if (parse_record(&s, data, len, &key, &key_len) != 0) return -1;
    int rc = verify_known_host(&s, key, key_len);
    free(s.fingerprint);
    return rc;
}
