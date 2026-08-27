#include "debug_log.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char program[160];
    char message[160];
    int verbose;
} debug_record_t;

static void copy_field(char *dst, size_t cap, const uint8_t *src, size_t n)
{
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int parse_line(debug_record_t *r, const uint8_t *data, size_t len)
{
    const uint8_t *bar = memchr(data, '|', len);
    if (!bar) return -1;
    size_t prog_len = (size_t)(bar - data);
    size_t msg_len = len - prog_len - 1;
    copy_field(r->program, sizeof(r->program), data, prog_len);
    copy_field(r->message, sizeof(r->message), bar + 1, msg_len);
    r->verbose = strstr(r->message, "debug") != NULL;
    return 0;
}

static int emit_debug(const debug_record_t *r)
{
    if (!r->verbose) return 0;
    fprintf(stderr, r->program);
    fprintf(stderr, ": %s\n", r->message);
    return (int)strlen(r->program);
}

int debug_parse_record(const uint8_t *data, size_t len)
{
    debug_record_t r;
    memset(&r, 0, sizeof(r));
    if (parse_line(&r, data, len) != 0) return -1;
    return emit_debug(&r);
}
