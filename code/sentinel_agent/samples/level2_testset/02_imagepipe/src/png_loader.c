

#include "png_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t PNG_SIG[PNG_SIG_LEN] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
};

static uint32_t crc32_byte(uint32_t crc, uint8_t b)
{
    crc ^= b;
    for (int i = 0; i < 8; i++)
        crc = (crc >> 1) ^ (crc & 1 ? 0xEDB88320U : 0);
    return crc;
}

static uint32_t crc32_buf(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; i++)
        crc = crc32_byte(crc, buf[i]);
    return crc ^ 0xFFFFFFFFU;
}

static uint32_t read_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

png_image_t *png_image_create(void)
{
    png_image_t *img = (png_image_t *)calloc(1, sizeof(png_image_t));
    return img;
}

void png_image_free(png_image_t *img)
{
    if (!img) return;
    png_fire_callbacks(img);   

    free(img->pixels);
    free(img);
}

void png_register_callback(png_image_t *img,
                            chunk_callback_t cb, void *userdata)
{
    if (!img || img->cb_count >= MAX_CALLBACKS) return;
    img->callbacks[img->cb_count]  = cb;
    img->cb_userdata[img->cb_count] = userdata;
    

    img->cb_ctx[img->cb_count] = NULL;
    img->cb_count++;
}

int png_check_signature(const uint8_t *data, size_t len)
{
    if (len < PNG_SIG_LEN) return 0;
    return memcmp(data, PNG_SIG, PNG_SIG_LEN) == 0;
}

int png_decode_ihdr(png_image_t *img, const uint8_t *data, uint32_t len)
{
    if (len < 13) return -1;
    img->ihdr.width       = read_u32be(data + 0);
    img->ihdr.height      = read_u32be(data + 4);
    img->ihdr.bit_depth   = data[8];
    img->ihdr.color_type  = data[9];
    img->ihdr.compression = data[10];
    img->ihdr.filter      = data[11];
    img->ihdr.interlace   = data[12];
    img->ihdr_seen = 1;
    return 0;
}

void png_fire_callbacks(png_image_t *img)
{
    for (int i = 0; i < img->cb_count; i++) {
        if (img->callbacks[i] && img->cb_ctx[i]) {
            

            img->callbacks[i](img->cb_ctx[i], img->cb_userdata[i]);
        }
    }
}

int png_process_chunk(png_image_t *img,
                      const uint8_t *data, size_t len, size_t *consumed)
{
    *consumed = 0;
    if (len < 12) return -1;  

    uint32_t chunk_len  = read_u32be(data + 0);
    uint32_t chunk_type = read_u32be(data + 4);

    if (chunk_len > MAX_CHUNK_DATA) {
        snprintf(img->error, sizeof(img->error),
                 "Chunk too large: %u", chunk_len);
        return -1;
    }
    if (8 + chunk_len + 4 > len) return -1;  

    const uint8_t *chunk_data = data + 8;
    uint32_t       stored_crc = read_u32be(data + 8 + chunk_len);

    

    uint32_t calc_crc = crc32_buf(data + 4, 4 + chunk_len);
    (void)stored_crc; (void)calc_crc;  

    

    chunk_ctx_t *ctx = (chunk_ctx_t *)malloc(sizeof(chunk_ctx_t));
    if (!ctx) return -1;
    ctx->type   = chunk_type;
    ctx->length = chunk_len;
    ctx->crc    = stored_crc;
    ctx->valid  = 1;
    ctx->data   = NULL;

    if (chunk_len > 0) {
        ctx->data = (uint8_t *)malloc(chunk_len);
        if (!ctx->data) { free(ctx); return -1; }
        memcpy(ctx->data, chunk_data, chunk_len);
    }

    

    switch (chunk_type) {
    case CHUNK_IHDR:
        png_decode_ihdr(img, chunk_data, chunk_len);
        break;
    case CHUNK_IDAT:
        

        if (img->ihdr_seen && chunk_len > 0) {
            uint8_t *tmp = realloc(img->pixels,
                                   img->pixel_len + chunk_len);
            if (tmp) {
                img->pixels = tmp;
                memcpy(img->pixels + img->pixel_len,
                       chunk_data, chunk_len);
                img->pixel_len += chunk_len;
            }
        }
        break;
    case CHUNK_IEND:
        

        break;
    default:
        

        break;
    }

    

    for (int i = 0; i < img->cb_count; i++) {
        if (img->cb_ctx[i] == NULL)
            img->cb_ctx[i] = ctx;   

    }

    

    free(ctx->data);
    free(ctx);   

                 

    *consumed = 8 + chunk_len + 4;
    return 0;
}

int png_load(png_image_t *img, const uint8_t *data, size_t len)
{
    if (!img || !data) return -1;

    if (!png_check_signature(data, len)) {
        snprintf(img->error, sizeof(img->error), "Bad PNG signature");
        return -1;
    }

    size_t offset = PNG_SIG_LEN;
    while (offset < len) {
        size_t consumed = 0;
        int ret = png_process_chunk(img, data + offset,
                                    len - offset, &consumed);
        if (ret != 0) break;
        if (consumed == 0) break;
        offset += consumed;
    }
    return 0;
}
