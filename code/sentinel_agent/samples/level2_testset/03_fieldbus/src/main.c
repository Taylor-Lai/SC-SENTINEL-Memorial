

#include "modbus_proto.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT 4096

int main(int argc, char *argv[])
{
    FILE *fp = stdin;
    if (argc >= 2) {
        fp = fopen(argv[1], "rb");
        if (!fp) { perror("fopen"); return 1; }
    }

    uint8_t *buf = (uint8_t *)malloc(MAX_INPUT);
    if (!buf) return 1;
    size_t len = fread(buf, 1, MAX_INPUT - 1, fp);
    if (argc >= 2) fclose(fp);

    modbus_mapping_t *map = modbus_mapping_new();
    if (!map) { free(buf); return 1; }

    

    for (int i = 0; i < 16; i++) map->regs[i] = (uint16_t)(i * 100);

    uint8_t resp[512];
    modbus_reply(map, buf, len, resp, sizeof(resp));

    modbus_mapping_free(map);
    free(buf);
    return 0;
}
