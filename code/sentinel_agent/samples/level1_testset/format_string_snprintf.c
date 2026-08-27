#include "ctf_input.h"

static void render(char *dst, size_t dst_len, const char *fmt) {
    snprintf(dst, dst_len, fmt);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    char out[64];
    render(out, sizeof(out), (const char *)data);
    puts(out);
    free(data);
    return 0;
}
