

#include "chunked_http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int find_crlf(const uint8_t *data, size_t len, size_t *pos)
{
    for (size_t i = 0; i + 1 < len; i++) {
        if (data[i] == '\r' && data[i+1] == '\n') {
            *pos = i;
            return 0;
        }
    }
    return -1;
}

int get_chunk_size(const char *line, size_t len)
{
    unsigned int val = 0;
    for (size_t i = 0; i < len; i++) {
        char c = line[i];
        if (c == ';' || c == '\r' || c == '\n') break;
        if      (c >= '0' && c <= '9') val = val * 16 + (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') val = val * 16 + (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') val = val * 16 + (unsigned)(c - 'A' + 10);
        else return -1;
    }
    

    return (int)val;
}

http_response_t *http_response_new(void)
{
    http_response_t *r = (http_response_t *)calloc(1, sizeof(*r));
    if (r) r->content_length = -1;
    return r;
}

void http_response_free(http_response_t *r)
{
    if (!r) return;
    free(r->body);
    free(r);
}

int http_append_body(http_response_t *r, const uint8_t *data, size_t len)
{
    uint8_t *tmp = (uint8_t *)realloc(r->body, r->body_len + len + 1);
    if (!tmp) return -1;
    r->body = tmp;
    memcpy(r->body + r->body_len, data, len);
    r->body_len += len;
    r->body[r->body_len] = '\0';
    return 0;
}

int http_parse_headers(http_response_t *r,
                       const uint8_t *data, size_t len,
                       size_t *header_end)
{
    if (!r || !data || len < 4) return -1;

    

    for (size_t i = 0; i + 3 < len; i++) {
        if (data[i]   == '\r' && data[i+1] == '\n' &&
            data[i+2] == '\r' && data[i+3] == '\n') {
            *header_end = i + 4;

            

            if (len > 9 && memcmp(data, "HTTP/", 5) == 0) {
                r->status_code = atoi((const char *)data + 9);
            }

            

            size_t p = 0;
            while (p < *header_end) {
                size_t eol = p;
                while (eol < *header_end && data[eol] != '\n') eol++;
                char line[256] = {0};
                size_t ll = eol - p;
                if (ll >= sizeof(line)) ll = sizeof(line) - 1;
                memcpy(line, data + p, ll);

                if (strncasecmp(line, "transfer-encoding:", 18) == 0) {
                    if (strstr(line + 18, "chunked")) r->chunked = 1;
                }
                if (strncasecmp(line, "content-length:", 15) == 0) {
                    r->content_length = atoi(line + 15);
                }
                if (strncasecmp(line, "content-type:", 13) == 0) {
                    char *ct = line + 13;
                    while (*ct == ' ') ct++;
                    strncpy(r->content_type, ct, sizeof(r->content_type) - 1);
                }
                p = eol + 1;
            }
            return 0;
        }
    }
    return -1;
}

int http_decode_chunked(http_response_t *r,
                        const uint8_t *data, size_t len)
{
    if (!r || !data) return -1;

    size_t offset = 0;

    while (offset < len) {
        

        size_t crlf_pos = 0;
        if (find_crlf(data + offset, len - offset, &crlf_pos) != 0)
            break;

        char size_line[CHUNK_LINE_MAX] = {0};
        size_t ll = crlf_pos < CHUNK_LINE_MAX - 1
                    ? crlf_pos : CHUNK_LINE_MAX - 1;
        memcpy(size_line, data + offset, ll);

        

        int chunk_size = get_chunk_size(size_line, ll);

        offset += crlf_pos + 2;  

        

        if (chunk_size == 0) break;

        if (chunk_size < 0) {
            

            size_t new_len = r->body_len + (size_t)chunk_size; 

            if (new_len > HTTP_MAX_RESPONSE) {
                snprintf(r->error, sizeof(r->error),
                         "Chunk too large after cast: %zu", new_len);
                return -1;
            }
            uint8_t *tmp = (uint8_t *)realloc(r->body, new_len + 1);
            if (!tmp) return -1;
            r->body = tmp;
            size_t copy_len = (len - offset < (size_t)(-chunk_size))
                              ? len - offset : (size_t)(-chunk_size);
            

            memcpy(r->body + r->body_len, data + offset, copy_len);
            r->body_len = new_len;
            r->body[r->body_len] = '\0';
            offset += copy_len + 2;
            continue;
        }

        

        if (offset + (size_t)chunk_size + 2 > len) {
            

            http_append_body(r, data + offset, len - offset);
            break;
        }

        http_append_body(r, data + offset, (size_t)chunk_size);
        offset += (size_t)chunk_size + 2;  

    }
    return 0;
}

int http_parse_response(http_response_t *r,
                        const uint8_t *data, size_t len)
{
    size_t hdr_end = 0;
    if (http_parse_headers(r, data, len, &hdr_end) != 0) {
        

        http_append_body(r, data, len);
        return 0;
    }

    const uint8_t *body = data + hdr_end;
    size_t         blen = len - hdr_end;

    if (r->chunked) {
        return http_decode_chunked(r, body, blen);
    }
    return http_append_body(r, body, blen);
}
