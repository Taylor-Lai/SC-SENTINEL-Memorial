#include <stdio.h>

void format_string_case(const char *user_input) {
    if (user_input == NULL) {
        return;
    }

    printf(user_input);  // CWE-134: attacker-controlled format string
}

int main() {
    format_string_case("%x.%x.%x.%x");
    return 0;
}
