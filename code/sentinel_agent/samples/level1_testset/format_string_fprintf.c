#include "ctf_input.h"

static void log_event(FILE *out, const char *event) {
    fprintf(out, event);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    log_event(stdout, (const char *)data);
    free(data);
    return 0;
}
