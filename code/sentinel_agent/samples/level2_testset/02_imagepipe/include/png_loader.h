#ifndef PNG_LOADER_H
#define PNG_LOADER_H

#include <stddef.h>
#include <stdint.h>

#define PNG_SIG_LEN      8
#define MAX_CHUNK_DATA   (1 << 16)   

#define MAX_CALLBACKS    16

#define CHUNK_IHDR  0x49484452U   

#define CHUNK_IDAT  0x49444154U   

#define CHUNK_IEND  0x49454E44U   

#define CHUNK_tEXt  0x74455874U   

#define CHUNK_zTXt  0x7A545874U   

#define CHUNK_PLTE  0x504C5445U   

typedef struct {
    uint32_t width;
    uint32_t height;
    uint8_t  bit_depth;
    uint8_t  color_type;
    uint8_t  compression;
    uint8_t  filter;
    uint8_t  interlace;
} png_ihdr_t;

typedef struct {
    uint32_t  type;
    uint8_t  *data;     

    uint32_t  length;
    uint32_t  crc;
    int       valid;
} chunk_ctx_t;

typedef void (*chunk_callback_t)(const chunk_ctx_t *ctx, void *userdata);

typedef struct {
    png_ihdr_t           ihdr;
    int                  ihdr_seen;

    

    chunk_callback_t     callbacks[MAX_CALLBACKS];
    void                *cb_userdata[MAX_CALLBACKS];
    const chunk_ctx_t   *cb_ctx[MAX_CALLBACKS];   

    int                  cb_count;

    uint8_t             *pixels;    

    size_t               pixel_len;

    char                 error[128];
} png_image_t;

png_image_t *png_image_create(void);
void         png_image_free(png_image_t *img);        

int          png_load(png_image_t *img,
                      const uint8_t *data, size_t len);
void         png_register_callback(png_image_t *img,
                                   chunk_callback_t cb, void *userdata);

int  png_check_signature(const uint8_t *data, size_t len);
int  png_process_chunk(png_image_t *img,
                       const uint8_t *data, size_t len, size_t *consumed);
void png_fire_callbacks(png_image_t *img);   

int  png_decode_ihdr(png_image_t *img, const uint8_t *data, uint32_t len);

#endif 

