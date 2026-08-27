#include "ctf_input.h"

static void set_player_name(const unsigned char *data) {
    char name[16];
    strcpy(name, (const char *)data);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    set_player_name(data);
    free(data);
    return 0;
}
