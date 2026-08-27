#include "ctf_input.h"

static void edit_chunk(const unsigned char *packet, size_t packet_len) {
    char *chunk = (char *)malloc(24);
    if (!chunk) {
        return;
    }

    memcpy(chunk, packet, packet_len);
    free(chunk);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    size_t copy_len = byte_or(data, len, 0, 64);
    if (copy_len > len) {
        copy_len = len;
    }
    edit_chunk(data, copy_len);
    free(data);
    return 0;
}
