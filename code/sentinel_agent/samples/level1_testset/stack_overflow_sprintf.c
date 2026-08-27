#include "ctf_input.h"

static void make_banner(const unsigned char *name) {
    char banner[16];
    sprintf(banner, "player:%s", (const char *)name);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    make_banner(data);
    free(data);
    return 0;
}
