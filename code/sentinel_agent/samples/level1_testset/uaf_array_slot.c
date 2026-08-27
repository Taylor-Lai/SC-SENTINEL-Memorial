#include "ctf_input.h"

static void create_slot(char **slots, int idx, const unsigned char *data, size_t len) {
    slots[idx] = (char *)malloc(32);
    if (slots[idx]) {
        size_t copy_len = len < 31 ? len : 31;
        memcpy(slots[idx], data, copy_len);
        slots[idx][copy_len] = '\0';
    }
}

static void delete_slot(char **slots, int idx) {
    free(slots[idx]);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    char *slots[4] = {0};
    int idx = (int)(byte_or(data, len, 0, 1) % 4);
    create_slot(slots, idx, data, len);
    if (has_byte(data, len, 'D')) {
        delete_slot(slots, idx);
    }
    if (has_byte(data, len, 'V') && slots[idx]) {
        puts(slots[idx]);
    }

    free(data);
    return 0;
}
