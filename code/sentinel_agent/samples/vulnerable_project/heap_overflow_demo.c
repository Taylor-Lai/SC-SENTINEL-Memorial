#include <stdlib.h>
#include <string.h>

void heap_overflow_case(const char *input) {
    char *buf = (char *)malloc(8);
    if (buf == NULL) {
        return;
    }

    strcpy(buf, input);  // CWE-122: heap buffer overflow
    free(buf);
}

int main() {
    heap_overflow_case("this string is too long");
    return 0;
}
