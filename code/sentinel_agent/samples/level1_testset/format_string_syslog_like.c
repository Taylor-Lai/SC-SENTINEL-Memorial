#include "ctf_input.h"

static void tiny_syslog(int level, const char *fmt) {
    (void)level;
    printf(fmt);
}

static void dispatch_log(const char *user_line) {
    tiny_syslog(3, user_line);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    dispatch_log((const char *)data);
    free(data);
    return 0;
}
