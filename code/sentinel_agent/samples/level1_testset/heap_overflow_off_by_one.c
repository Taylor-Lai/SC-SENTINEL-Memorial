#include "ctf_input.h"

static void rename_chunk(const unsigned char *data, size_t len) {
    size_t name_len = len > 0 ? len : 1;
    char *name = (char *)malloc(name_len);
    if (!name) {
        return;
    }

    memcpy(name, data, name_len + 1);
    free(name);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    rename_chunk(data, len);
    free(data);
    return 0;
}
