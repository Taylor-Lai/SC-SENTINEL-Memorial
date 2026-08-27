

#include "adpcm_decoder.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT (1 << 22)  

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

    adpcm_ctx_t *ctx = adpcm_ctx_new();
    if (!ctx) { free(buf); return 1; }

    if (adpcm_parse_wav(ctx, buf, len) == 0) {
        int samples = adpcm_decode_all(ctx);
        if (samples > 0)
            printf("Decoded %d PCM samples\n", samples);
        else
            fprintf(stderr, "Decode failed: %s\n", ctx->error);
    } else {
        fprintf(stderr, "Parse failed: %s\n", ctx->error);
    }

    adpcm_ctx_free(ctx);
    free(buf);
    return 0;
}
