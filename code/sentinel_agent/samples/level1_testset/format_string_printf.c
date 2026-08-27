#include "ctf_input.h"

static void say(const char *msg) {
    printf(msg);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    say((const char *)data);
    free(data);
    return 0;
}
