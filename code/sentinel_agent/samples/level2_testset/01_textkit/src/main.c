

#include "json_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT (1 << 20)  

int main(int argc, char *argv[])
{
    FILE   *fp  = stdin;
    char   *buf = NULL;
    size_t  len = 0;

    if (argc >= 2) {
        fp = fopen(argv[1], "rb");
        if (!fp) { perror("fopen"); return 1; }
    }

    buf = (char *)malloc(MAX_INPUT);
    if (!buf) { fputs("OOM\n", stderr); return 1; }

    len = fread(buf, 1, MAX_INPUT - 1, fp);
    if (argc >= 2) fclose(fp);
    buf[len] = '\0';

    json_value_t *root = json_parse(buf, len);
    if (!root) {
        fprintf(stderr, "Parse error\n");
        free(buf);
        return 1;
    }

    json_print(root, 0);
    json_free(root);
    free(buf);
    return 0;
}
