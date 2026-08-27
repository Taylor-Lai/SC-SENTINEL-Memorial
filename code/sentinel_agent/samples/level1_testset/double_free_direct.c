#include "ctf_input.h"

static void delete_note(char *note) {
    free(note);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    char *note = (char *)malloc(48);
    if (!note) {
        free(data);
        return 1;
    }

    delete_note(note);
    if (has_byte(data, len, 'D')) {
        delete_note(note);
    }

    free(data);
    return 0;
}
