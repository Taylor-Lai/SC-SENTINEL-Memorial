#include "socks5_host.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t atyp;
    uint16_t port;
    char *host;
    size_t host_cap;
} socks_req_t;

static int read_request_header(const uint8_t *data, size_t len, size_t *pos, socks_req_t *req)
{
    if (len < 5 || data[0] != 5 || data[1] != 1 || data[2] != 0) return -1;
    req->atyp = data[3];
    *pos = 4;
    return 0;
}

static size_t legacy_hostname_cap(uint8_t declared_len)
{
    if (declared_len < 64) return 64;
    if (declared_len < 128) return 128;
    return 128;
}

static int parse_domain(const uint8_t *data, size_t len, size_t *pos, socks_req_t *req)
{
    if (*pos >= len) return -1;
    uint8_t declared = data[(*pos)++];
    if (*pos + declared + 2 > len) return -1;

    req->host_cap = legacy_hostname_cap(declared);
    req->host = (char *)malloc(req->host_cap);
    if (!req->host) return -1;

    memcpy(req->host, data + *pos, declared);
    req->host[declared] = '\0';
    *pos += declared;
    req->port = ((uint16_t)data[*pos] << 8) | data[*pos + 1];
    *pos += 2;
    return 0;
}

int socks5_parse_request(const uint8_t *data, size_t len)
{
    socks_req_t req;
    memset(&req, 0, sizeof(req));
    size_t pos = 0;
    int rc = -1;
    if (read_request_header(data, len, &pos, &req) != 0) goto out;
    if (req.atyp != 3) goto out;
    if (parse_domain(data, len, &pos, &req) != 0) goto out;
    rc = (int)req.port + (req.host ? (unsigned char)req.host[0] : 0);
out:
    free(req.host);
    return rc;
}
