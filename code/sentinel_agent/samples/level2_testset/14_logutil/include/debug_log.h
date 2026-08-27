#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H
#include <stddef.h>
#include <stdint.h>
int debug_parse_record(const uint8_t *data, size_t len);
#endif
