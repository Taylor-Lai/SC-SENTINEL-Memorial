#include "ctf_input.h"

static void set_checkpoint(int idx) {
    int checkpoints[4] = {0, 1, 2, 3};
    checkpoints[idx] = 31337;
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    int idx = (int)byte_or(data, len, 0, 8);
    set_checkpoint(idx);
    free(data);
    return 0;
}
