

#include "chunked_http.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT (1 << 20)

int main(int argc, char *argv[])
{
    FILE *fp = stdin;
    if (argc >= 2) {
        fp = fopen(argv[1], "rb");
        if (!fp) { perror("fopen"); return 1; }
    }

    uint8_t *buf = (uint8_t *)malloc(MAX_INPUT);
    if (!buf) return 1;
    size_t len = fread(buf, 1, MAX_INPUT - 1, fp);
    if (argc >= 2) fclose(fp);

    http_response_t *r = http_response_new();
    if (!r) { free(buf); return 1; }

    http_parse_response(r, buf, len);

    if (r->body && r->body_len > 0)
        printf("Body length: %zu\n", r->body_len);

    http_response_free(r);
    free(buf);
    return 0;
}
