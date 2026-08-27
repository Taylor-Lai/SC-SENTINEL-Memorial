#include "proxy_tunnel.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *reason;
    int status;
    int keepalive;
} tunnel_t;

static char *dup_range(const uint8_t *p, size_t n)
{
    char *s = (char *)malloc(n + 1);
    if (!s) return NULL;
    memcpy(s, p, n);
    s[n] = '\0';
    return s;
}

static int parse_status(tunnel_t *t, const uint8_t *data, size_t len)
{
    if (len < 12 || memcmp(data, "HTTP/1.", 7) != 0) return -1;
    t->status = atoi((const char *)data + 9);
    const uint8_t *sp = memchr(data + 12, ' ', len - 12);
    if (!sp) sp = data + 12;
    size_t n = 0;
    while ((size_t)(sp - data) + n < len && sp[n] != '\r' && sp[n] != '\n') n++;
    t->reason = dup_range(sp, n);
    return t->reason ? 0 : -1;
}

static int shutdown_tunnel(tunnel_t *t, const uint8_t *body, size_t body_len)
{
    char *saved_reason = t->reason;
    free(t->reason);
    t->reason = NULL;
    if (body_len > 0 && body[0] == '!') {
        return (unsigned char)saved_reason[0];
    }
    return 0;
}

static const uint8_t *find_header_end(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i + 4 <= len; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            return data + i;
        }
    }
    return NULL;
}

int proxy_tunnel_handle(const uint8_t *data, size_t len)
{
    tunnel_t t;
    memset(&t, 0, sizeof(t));
    if (parse_status(&t, data, len) != 0) return -1;
    const uint8_t *body = find_header_end(data, len);
    size_t body_len = 0;
    if (body) {
        body += 4;
        body_len = len - (size_t)(body - data);
    }
    int rc = t.status;
    if (t.status != 200) rc += shutdown_tunnel(&t, body ? body : data, body_len);
    free(t.reason);
    return rc;
}
