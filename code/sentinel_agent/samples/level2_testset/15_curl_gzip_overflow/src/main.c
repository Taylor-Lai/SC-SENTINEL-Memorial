#include "gziprelay.h"

#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT 32768

int main(int argc, char **argv)
{
    FILE *fp = argc > 1 ? fopen(argv[1], "rb") : stdin;
    if (!fp) return 1;
    uint8_t *input = malloc(MAX_INPUT);
    if (!input) return 1;
    size_t length = fread(input, 1, MAX_INPUT, fp);
    if (argc > 1) fclose(fp);
    int result = gziprelay_decode(input, length);
    free(input);
    return result == 0 ? 0 : 1;
}
