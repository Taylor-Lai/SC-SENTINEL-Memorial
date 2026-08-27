#include "ctf_input.h"
#include <stdint.h>

static void resize_then_write(const unsigned char *msg, size_t len) {
    unsigned char small_len = (unsigned char)len;
    char *buf = (char *)malloc(small_len);
    if (!buf) {
        return;
    }

    memcpy(buf, msg, len);
    free(buf);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    resize_then_write(data, len);
    free(data);
    return 0;
}
