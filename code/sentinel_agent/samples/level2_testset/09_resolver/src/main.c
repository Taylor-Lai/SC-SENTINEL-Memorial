

#include "dns_reply.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT (1 << 20)

int main(int argc, char **argv)
{
    FILE *fp = stdin;
    if (argc >= 2) {
        fp = fopen(argv[1], "rb");
        if (!fp) { perror("fopen"); return 1; }
    }
    unsigned char *buf = (unsigned char *)malloc(MAX_INPUT);
    if (!buf) return 1;
    size_t len = fread(buf, 1, MAX_INPUT, fp);
    if (argc >= 2) fclose(fp);
    int rc = dns_parse_reply(buf, len);
    free(buf);
    return rc < 0 ? 1 : 0;
}
