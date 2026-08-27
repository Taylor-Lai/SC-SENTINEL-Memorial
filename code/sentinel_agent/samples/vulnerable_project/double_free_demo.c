#include <stdlib.h>

void double_free_case(int flag) {
    char *buf = (char *)malloc(32);
    if (buf == NULL) {
        return;
    }

    free(buf);

    if (flag) {
        free(buf);  // CWE-415: double free
    }
}

int main() {
    double_free_case(1);
    return 0;
}
