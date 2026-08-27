#include "ctf_input.h"

static char *create_chunk(const unsigned char *data, size_t len) {
    char *chunk = (char *)malloc(32);
    if (chunk) {
        size_t copy_len = len < 31 ? len : 31;
        memcpy(chunk, data, copy_len);
        chunk[copy_len] = '\0';
    }
    return chunk;
}

static void delete_chunk(char *chunk) {
    free(chunk);
}

static void edit_chunk(char *chunk, const unsigned char *data, size_t len) {
    size_t copy_len = len < 31 ? len : 31;
    memcpy(chunk, data, copy_len);
    chunk[copy_len] = '\0';
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    char *chunk = create_chunk(data, len);
    if (has_byte(data, len, 'X')) {
        delete_chunk(chunk);
        edit_chunk(chunk, data, len);
    }

    free(data);
    return 0;
}
