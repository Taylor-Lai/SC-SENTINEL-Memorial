#include "ctf_input.h"

struct Note {
    char text[32];
};

static void run_note_machine(const unsigned char *data, size_t len) {
    struct Note *note = NULL;

    if (has_byte(data, len, 'C')) {
        note = (struct Note *)malloc(sizeof(struct Note));
        if (!note) {
            return;
        }
        memcpy(note->text, "created", 8);
    }
    if (has_byte(data, len, 'D')) {
        free(note);
    }
    if (has_byte(data, len, 'S')) {
        puts(note->text);
    }
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }
    run_note_machine(data, len);
    free(data);
    return 0;
}
