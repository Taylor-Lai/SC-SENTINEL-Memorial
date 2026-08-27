#include "ctf_input.h"

static void create_and_edit(const unsigned char *data, size_t len) {
    char *name = (char *)malloc(16);
    if (!name) {
        return;
    }

    strcpy(name, (const char *)data);
    free(name);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    create_and_edit(data, len);
    free(data);
    return 0;
}
