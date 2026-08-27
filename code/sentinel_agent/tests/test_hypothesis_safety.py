from agents.agent_c_hypothesis import (
    copy_appears_bounded,
    detect_pointer_index_loop_overflow,
)


def test_multiline_ternary_memcpy_bound_is_recognized():
    source = """
        memcpy(req->write_data, pdu + 6,
               req->write_count < MODBUS_MAX_PDU
               ? req->write_count : MODBUS_MAX_PDU);
    """

    assert copy_appears_bounded(source, "")


def test_response_capacity_guard_suppresses_fixed_sample_only():
    slice_data = {
        "slice_id": "SLICE-1",
        "target_file": "src/modbus_proto.c",
        "target_function": "modbus_handle_fc17",
    }
    vulnerable = [
        {"source_line": 1, "code": "uint8_t response[RESP_BUF_SIZE];"},
        {"source_line": 2, "code": "for (uint16_t i = 0; i < nb_read; i++) {"},
        {"source_line": 3, "code": "write_u16be(response + 9 + i * 2, val);"},
    ]
    fixed = [
        {"source_line": 1, "code": "uint8_t response[RESP_BUF_SIZE];"},
        {"source_line": 2, "code": "size_t response_size = MBAP_LEN + 3 + (size_t)nb_read * 2;"},
        {"source_line": 3, "code": "if (response_size > RESP_BUF_SIZE) return -1;"},
        {"source_line": 4, "code": "for (uint16_t i = 0; i < nb_read; i++) {"},
        {"source_line": 5, "code": "write_u16be(response + 9 + i * 2, val);"},
    ]

    assert detect_pointer_index_loop_overflow(slice_data, vulnerable)
    assert detect_pointer_index_loop_overflow(slice_data, fixed) == []
