#include <string.h>

void stack_overflow_case(const char *input) {
    char buf[8];
    strcpy(buf, input);  // CWE-121: stack buffer overflow
}

int main() {
    stack_overflow_case("this string is too long");
    return 0;
}
