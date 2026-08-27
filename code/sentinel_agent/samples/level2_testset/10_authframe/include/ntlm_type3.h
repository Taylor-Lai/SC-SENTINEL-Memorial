#ifndef NTLM_TYPE3_H
#define NTLM_TYPE3_H
#include <stddef.h>
#include <stdint.h>
int ntlm_build_type3(const uint8_t *data, size_t len);
#endif
