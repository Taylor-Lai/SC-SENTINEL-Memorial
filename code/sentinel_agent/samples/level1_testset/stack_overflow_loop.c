#include "ctf_input.h"

static void copy_loop(const unsigned char *src, size_t len) {
    char dst[10];
    for (size_t i = 0; i <= len; i++) {
        dst[i] = (char)src[i % len];
    }
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    size_t copy_len = byte_or(data, len, 0, 16);
    if (copy_len < 12) {
        copy_len = len > 12 ? 12 : len;
    }
    copy_loop(data, copy_len);
    free(data);
    return 0;
}
