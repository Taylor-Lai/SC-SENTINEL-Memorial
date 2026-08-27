#ifndef SENTINEL_LEVEL1_CTF_INPUT_H
#define SENTINEL_LEVEL1_CTF_INPUT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_challenge_input(int argc, char **argv, size_t *out_len) {
    FILE *fp = NULL;
    unsigned char *buf = NULL;
    size_t cap = 0;
    size_t len = 0;

    if (argc > 1) {
        fp = fopen(argv[1], "rb");
    }
    if (!fp) {
        fp = stdin;
    }

    cap = 4096;
    buf = (unsigned char *)malloc(cap + 1);
    if (!buf) {
        *out_len = 0;
        return NULL;
    }

    len = fread(buf, 1, cap, fp);
    if (fp != stdin) {
        fclose(fp);
    }

    if (len == 0) {
        const char *fallback = "SC";
        len = strlen(fallback);
        memcpy(buf, fallback, len);
    }

    buf[len] = '\0';
    *out_len = len;
    return buf;
}

static int has_byte(const unsigned char *data, size_t len, unsigned char needle) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] == needle) {
            return 1;
        }
    }
    return 0;
}

static size_t byte_or(const unsigned char *data, size_t len, size_t idx, size_t fallback) {
    if (idx < len) {
        return (size_t)data[idx];
    }
    return fallback;
}

#endif
