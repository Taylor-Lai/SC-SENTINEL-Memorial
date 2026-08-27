#ifndef SSH_FINGERPRINT_H
#define SSH_FINGERPRINT_H
#include <stddef.h>
#include <stdint.h>
int ssh_verify_record(const uint8_t *data, size_t len);
#endif
