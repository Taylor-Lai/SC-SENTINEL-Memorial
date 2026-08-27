#include "ctf_input.h"

static int update_profile(const unsigned char *data, size_t len) {
    char *profile = (char *)malloc(64);
    if (!profile) {
        return -1;
    }

    if (has_byte(data, len, '!')) {
        free(profile);
        goto reject;
    }

    free(profile);
    return 0;

reject:
    free(profile);
    return -2;
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    (void)update_profile(data, len);
    free(data);
    return 0;
}
