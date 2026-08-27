#include "ctf_input.h"

struct Player {
    char *memo;
    int score;
};

static void player_init(struct Player *p, const unsigned char *data, size_t len) {
    p->memo = (char *)malloc(24);
    p->score = 100;
    if (p->memo) {
        size_t copy_len = len < 23 ? len : 23;
        memcpy(p->memo, data, copy_len);
        p->memo[copy_len] = '\0';
    }
}

static void player_reset(struct Player *p) {
    free(p->memo);
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *data = read_challenge_input(argc, argv, &len);
    if (!data) {
        return 1;
    }

    struct Player p;
    player_init(&p, data, len);
    if (has_byte(data, len, 'R')) {
        player_reset(&p);
    }
    if (has_byte(data, len, 'P')) {
        printf("%s:%d\n", p.memo, p.score);
    }

    free(data);
    return 0;
}
