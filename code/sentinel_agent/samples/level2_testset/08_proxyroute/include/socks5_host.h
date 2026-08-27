#ifndef SOCKS5_HOST_H
#define SOCKS5_HOST_H
#include <stddef.h>
#include <stdint.h>
int socks5_parse_request(const uint8_t *data, size_t len);
#endif
