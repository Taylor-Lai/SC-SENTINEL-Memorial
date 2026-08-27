

#include "modbus_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t read_u16be(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void write_u16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

modbus_mapping_t *modbus_mapping_new(void)
{
    return (modbus_mapping_t *)calloc(1, sizeof(modbus_mapping_t));
}

void modbus_mapping_free(modbus_mapping_t *map)
{
    free(map);
}

int modbus_parse_request(const uint8_t *buf, size_t len,
                         modbus_request_t *req)
{
    if (!buf || !req || len < (size_t)(MBAP_LEN + 2)) return -1;

    memset(req, 0, sizeof(*req));

    req->transaction_id = read_u16be(buf + 0);
    req->protocol_id    = read_u16be(buf + 2);
    req->pdu_length     = read_u16be(buf + 4);
    req->unit_id        = buf[6];
    req->function_code  = buf[7];

    const uint8_t *pdu  = buf + MBAP_LEN + 1; 

    size_t         plen = len - MBAP_LEN - 1;

    switch (req->function_code) {

    case FC_READ_COILS:
    case FC_READ_HOLDING_REGS:
        if (plen < 5) return -1;
        req->read_addr = read_u16be(pdu + 1);
        req->nb_read   = read_u16be(pdu + 3);
        break;

    case FC_WRITE_SINGLE_REG:
        if (plen < 5) return -1;
        req->write_addr = read_u16be(pdu + 1);
        req->write_data[0] = pdu[3];
        req->write_data[1] = pdu[4];
        req->nb_write = 1;
        break;

    case FC_WRITE_MULTIPLE_REGS:
        if (plen < 6) return -1;
        req->write_addr  = read_u16be(pdu + 1);
        req->nb_write    = read_u16be(pdu + 3);
        req->write_count = pdu[5];
        if (plen < (size_t)(6 + req->write_count)) return -1;
        memcpy(req->write_data, pdu + 6,
               req->write_count < MODBUS_MAX_PDU
               ? req->write_count : MODBUS_MAX_PDU);
        break;

    case FC_READ_WRITE_REGS:
        if (plen < 10) return -1;
        req->read_addr   = read_u16be(pdu + 1);
        req->nb_read     = read_u16be(pdu + 3);  

        req->write_addr  = read_u16be(pdu + 5);
        req->nb_write    = read_u16be(pdu + 7);  

        req->write_count = pdu[9];
        if (plen < (size_t)(10 + req->write_count)) return -1;
        memcpy(req->write_data, pdu + 10,
               req->write_count < MODBUS_MAX_PDU
               ? req->write_count : MODBUS_MAX_PDU);
        break;

    default:
        return -1;
    }
    return 0;
}

int modbus_handle_fc17(const modbus_request_t *req,
                       modbus_mapping_t *map)
{
    

    uint8_t  response[RESP_BUF_SIZE];   

    uint16_t nb_read = req->nb_read;

    

    write_u16be(response + 0, req->transaction_id);
    write_u16be(response + 2, 0x0000);          

    

    response[6] = req->unit_id;
    response[7] = FC_READ_WRITE_REGS;
    response[8] = (uint8_t)(nb_read * 2);       

    

    for (uint16_t i = 0; i < nb_read; i++) {
        uint16_t addr = req->read_addr + i;
        uint16_t val  = (addr < MODBUS_MAX_REGS) ? map->regs[addr] : 0;
        

        write_u16be(response + 9 + i * 2, val);
    }

    uint16_t pdu_len = (uint16_t)(2 + 1 + nb_read * 2);
    write_u16be(response + 4, pdu_len);

    

    for (uint16_t i = 0; i < req->nb_write && i < MODBUS_MAX_REGS; i++) {
        uint16_t addr = req->write_addr + i;
        if (addr < MODBUS_MAX_REGS && i * 2 + 1 < req->write_count) {
            map->regs[addr] = read_u16be(req->write_data + i * 2);
        }
    }

    return (int)(MBAP_LEN + 1 + 1 + 1 + nb_read * 2);
}

int modbus_build_response(const modbus_request_t *req,
                          const modbus_mapping_t *map,
                          uint8_t *out, size_t out_max)
{
    if (!req || !map || !out) return -1;
    size_t needed = MBAP_LEN + 1 + 1 + 1 + req->nb_read * 2;
    if (needed > out_max) return -1;

    write_u16be(out + 0, req->transaction_id);
    write_u16be(out + 2, 0x0000);
    out[6] = req->unit_id;
    out[7] = req->function_code;
    out[8] = (uint8_t)(req->nb_read * 2);

    for (uint16_t i = 0; i < req->nb_read; i++) {
        uint16_t addr = req->read_addr + i;
        uint16_t val  = (addr < MODBUS_MAX_REGS) ? map->regs[addr] : 0;
        write_u16be(out + 9 + i * 2, val);
    }
    uint16_t pdu_len = (uint16_t)(2 + 1 + req->nb_read * 2);
    write_u16be(out + 4, pdu_len);
    return (int)needed;
}

int modbus_reply(modbus_mapping_t *map,
                 const uint8_t *req_buf, size_t req_len,
                 uint8_t *resp_buf, size_t resp_max)
{
    modbus_request_t req;
    if (modbus_parse_request(req_buf, req_len, &req) != 0) return -1;

    if (req.function_code == FC_READ_WRITE_REGS) {
        

        return modbus_handle_fc17(&req, map);
    }
    return modbus_build_response(&req, map, resp_buf, resp_max);
}
