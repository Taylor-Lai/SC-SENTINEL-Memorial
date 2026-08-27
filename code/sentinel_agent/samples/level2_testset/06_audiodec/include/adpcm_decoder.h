#ifndef ADPCM_DECODER_H
#define ADPCM_DECODER_H

#include <stddef.h>
#include <stdint.h>

#define RIFF_ID  0x46464952U  

#define WAVE_ID  0x45564157U  

#define FMT_ID   0x20746D66U  

#define DATA_ID  0x61746164U  

#define WAVE_FORMAT_MS_ADPCM   0x0002

#define ADPCM_NUM_COEF  7

typedef struct {
    int16_t coef1;
    int16_t coef2;
} adpcm_coef_t;

typedef struct {
    uint16_t format_tag;
    uint16_t channels;
    uint32_t sample_rate;
    uint32_t byte_rate;
    uint16_t block_align;        

    uint16_t bits_per_sample;
    uint16_t extra_size;
    uint16_t samples_per_block;  

    uint16_t num_coef;
    adpcm_coef_t coef[ADPCM_NUM_COEF];
} wav_fmt_t;

typedef struct {
    int16_t  prev[2];    

    int16_t  delta;
    uint8_t  coef_idx;
} adpcm_channel_t;

typedef struct {
    wav_fmt_t        fmt;
    int              fmt_seen;

    uint8_t         *data;       

    size_t           data_len;

    int16_t         *pcm_out;    

    size_t           pcm_len;    

    size_t           pcm_cap;    

    char             error[128];
} adpcm_ctx_t;

adpcm_ctx_t *adpcm_ctx_new(void);
void         adpcm_ctx_free(adpcm_ctx_t *ctx);

int  adpcm_parse_wav(adpcm_ctx_t *ctx,
                     const uint8_t *data, size_t len);
int  adpcm_decode_block(adpcm_ctx_t *ctx,
                        const uint8_t *block, size_t block_len); 

int  adpcm_decode_all(adpcm_ctx_t *ctx);

uint32_t wav_read_u32le(const uint8_t *p);
uint16_t wav_read_u16le(const uint8_t *p);
int      adpcm_clamp16(int v);

#endif 

