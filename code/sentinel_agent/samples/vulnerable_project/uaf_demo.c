#include <stdio.h>
#include <stdlib.h>

void uaf_case(int flag) {
    int *p = (int *)malloc(sizeof(int));
    if (p == NULL) {
        return;
    }

    *p = 42;
    free(p);

    if (flag) {
        printf("%d\n", *p);  // CWE-416: use after free
    }
}

int main() {
    uaf_case(1);
    return 0;
}
