#include "ctf_input.h"

static void release_alias(char *alias) {
    free(alias);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    char *owner = (char *)malloc(40);
    if (!owner) {
        free(data);
        return 1;
    }

    char *slot_alias = owner;
    if (has_byte(data, len, 'A')) {
        release_alias(slot_alias);
    }
    if (has_byte(data, len, 'O')) {
        free(owner);
    }

    free(data);
    return 0;
}
