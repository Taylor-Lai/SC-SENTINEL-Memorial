#ifndef MODBUS_PROTO_H
#define MODBUS_PROTO_H

#include <stdint.h>
#include <stddef.h>

#define MBAP_LEN            6

#define MODBUS_MAX_PDU      253

#define RESP_BUF_SIZE       128   

#define FC_READ_COILS           0x01
#define FC_READ_HOLDING_REGS    0x03
#define FC_WRITE_SINGLE_REG     0x06
#define FC_WRITE_MULTIPLE_REGS  0x10
#define FC_READ_WRITE_REGS      0x17   

#define MODBUS_MAX_REGS     512

typedef struct {
    uint16_t regs[MODBUS_MAX_REGS];
    uint8_t  coils[MODBUS_MAX_REGS];
} modbus_mapping_t;

typedef struct {
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t pdu_length;
    uint8_t  unit_id;
    uint8_t  function_code;
    

    uint16_t read_addr;
    uint16_t nb_read;
    uint16_t write_addr;
    uint16_t nb_write;      

    uint8_t  write_count;   

    uint8_t  write_data[MODBUS_MAX_PDU];
} modbus_request_t;

modbus_mapping_t *modbus_mapping_new(void);
void              modbus_mapping_free(modbus_mapping_t *map);

int  modbus_parse_request(const uint8_t *buf, size_t len,
                          modbus_request_t *req);
int  modbus_build_response(const modbus_request_t *req,
                           const modbus_mapping_t *map,
                           uint8_t *out, size_t out_max);    

int  modbus_reply(modbus_mapping_t *map,
                  const uint8_t *req_buf, size_t req_len,
                  uint8_t *resp_buf, size_t resp_max);

int  modbus_handle_fc17(const modbus_request_t *req,        

                        modbus_mapping_t *map);

#endif 

