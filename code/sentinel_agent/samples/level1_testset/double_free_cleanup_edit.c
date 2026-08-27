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
    if (chunk->data != NULL) {
        free(chunk->data);
        chunk->data = NULL; // 释放后立即置空，杜绝 Double Free
    }
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

    chunk_delete(&chunk); // 统一清理，防止未触发上述条件时发生内存泄漏
    free(data);
    return 0;
}