#ifndef DNS_REPLY_H
#define DNS_REPLY_H
#include <stddef.h>
#include <stdint.h>
int dns_parse_reply(const uint8_t *data, size_t len);
#endif
