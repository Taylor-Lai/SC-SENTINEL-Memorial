

#include "png_loader.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT (1 << 20)

static void on_chunk(const chunk_ctx_t *ctx, void *userdata)
{
    (void)userdata;
    

    printf("Chunk type: 0x%08X, length: %u\n",
           ctx->type, ctx->length);
}

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

    png_image_t *img = png_image_create();
    if (!img) { free(buf); return 1; }

    png_register_callback(img, on_chunk, NULL);

    png_load(img, buf, len);

    

    png_image_free(img);

    free(buf);
    return 0;
}
