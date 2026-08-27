#ifndef CHUNKED_HTTP_H
#define CHUNKED_HTTP_H

#include <stddef.h>
#include <stdint.h>

#define HTTP_MAX_RESPONSE  (4 * 1024 * 1024)  

#define CHUNK_LINE_MAX     32

typedef struct {
    int      status_code;
    char     content_type[64];
    int      content_length;    

    int      chunked;           

    uint8_t *body;              

    size_t   body_len;

    char     error[128];
} http_response_t;

http_response_t *http_response_new(void);
void             http_response_free(http_response_t *r);

int  http_parse_headers(http_response_t *r,
                        const uint8_t *data, size_t len,
                        size_t *header_end);
int  http_decode_chunked(http_response_t *r,
                         const uint8_t *data, size_t len);   

int  http_parse_response(http_response_t *r,
                         const uint8_t *data, size_t len);

int  get_chunk_size(const char *line, size_t len);            

int  http_append_body(http_response_t *r,
                      const uint8_t *data, size_t len);

#endif 

