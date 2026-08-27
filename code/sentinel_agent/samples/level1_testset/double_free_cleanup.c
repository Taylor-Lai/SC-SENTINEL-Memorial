#include "ctf_input.h"

struct Chunk {
    char *data;
    size_t size;
};

static void chunk_create(struct Chunk *chunk, size_t size) {
    chunk->data = (char *)malloc(size);
    chunk->size = size;
}

static void chunk_delete(struct Chunk *chunk) {
    free(chunk->data);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    struct Chunk chunk;
    chunk_create(&chunk, 32);
    if (has_byte(data, len, '1')) {
        chunk_delete(&chunk);
    }
    if (has_byte(data, len, '2')) {
        chunk_delete(&chunk);
    }

    free(data);
    return 0;
}
