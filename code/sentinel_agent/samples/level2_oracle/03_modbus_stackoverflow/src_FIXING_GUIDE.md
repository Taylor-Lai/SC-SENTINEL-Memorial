# 漏洞修复建议 - modlite Stack Overflow

## 修复优先级

| 优先级 | 漏洞 | 严重性 | 修复难度 | 预计时间 |
|-------|------|--------|---------|---------|
| **P0** | 栈缓冲区溢出 | CRITICAL | 低 | 1-2小时 |
| **P1** | 输入验证缺失 | HIGH | 低 | 1小时 |
| **P2** | 整数溢出风险 | MEDIUM | 中 | 2小时 |

---

## 修复方案

### ✅ 方案 1：最小修改（推荐用于快速修复）

#### 修改文件：`src/modbus_proto.c`

**位置 1**: 在 `modbus_handle_fc17()` 开头添加验证

```c
int modbus_handle_fc17(const modbus_request_t *req, modbus_mapping_t *map)
{
    // ✅ 添加：验证请求参数
    if (!req || !map) return -1;
    
    // ✅ 添加：根据 Modbus 协议，FC 0x17 的 nb_read 最大值是 125
    if (req->nb_read > 125) return -1;
    
    // ✅ 添加：验证响应不会溢出缓冲区
    size_t response_size = MBAP_LEN + 3 + req->nb_read * 2;
    if (response_size > RESP_BUF_SIZE) return -1;

    uint16_t nb_read = req->nb_read;
    uint8_t response[RESP_BUF_SIZE];
    
    // ... 原有代码
}
```

**测试**：
```bash
# 重新编译
make clean && make

# 验证修复
python3 verify_vulnerability.py
```

**优点**：
- ✅ 修改最小，风险低
- ✅ 性能无影响
- ✅ 可快速部署

**缺点**：
- ⚠️ 未解决根本设计问题
- ⚠️ 其他路径可能仍有风险

---

### ✅ 方案 2：增大缓冲区（临时措施）

#### 修改文件：`include/modbus_proto.h`

```c
// 修改前
#define RESP_BUF_SIZE       128

// 修改后
// ✅ 计算：MBAP(6) + Unit(1) + FC(1) + ByteCount(1) + MaxData(125*2) = 259
#define RESP_BUF_SIZE       (MBAP_LEN + 3 + 125 * 2 + 8)  // 267 bytes
```

**测试**：
```bash
make clean && make test
```

**优点**：
- ✅ 一行修改，风险极低
- ✅ 完全解决当前溢出

**缺点**：
- ❌ 增加栈使用（+139字节）
- ❌ 治标不治本
- ❌ 未来功能扩展可能再次溢出

---

### ✅ 方案 3：使用动态内存（推荐用于长期解决）

#### 修改文件：`src/modbus_proto.c`

**完整重写 `modbus_handle_fc17()`**：

```c
int modbus_handle_fc17(const modbus_request_t *req, modbus_mapping_t *map)
{
    if (!req || !map) return -1;
    
    // ✅ 协议级别验证
    if (req->nb_read == 0 || req->nb_read > 125) return -1;
    if (req->nb_write > 121) return -1;
    
    uint16_t nb_read = req->nb_read;
    
    // ✅ 计算所需缓冲区大小
    size_t response_size = MBAP_LEN + 3 + nb_read * 2;
    
    // ✅ 动态分配
    uint8_t *response = (uint8_t *)malloc(response_size);
    if (!response) return -1;
    
    // 构建 MBAP
    write_u16be(response + 0, req->transaction_id);
    write_u16be(response + 2, 0x0000);
    response[6] = req->unit_id;
    response[7] = FC_READ_WRITE_REGS;
    response[8] = (uint8_t)(nb_read * 2);
    
    // ✅ 安全的循环（已验证边界）
    for (uint16_t i = 0; i < nb_read; i++) {
        uint16_t addr = req->read_addr + i;
        uint16_t val  = (addr < MODBUS_MAX_REGS) ? map->regs[addr] : 0;
        write_u16be(response + 9 + i * 2, val);
    }
    
    uint16_t pdu_len = (uint16_t)(2 + 1 + nb_read * 2);
    write_u16be(response + 4, pdu_len);
    
    // 处理写入部分
    for (uint16_t i = 0; i < req->nb_write && i < MODBUS_MAX_REGS; i++) {
        uint16_t addr = req->write_addr + i;
        if (addr < MODBUS_MAX_REGS && i * 2 + 1 < req->write_count) {
            map->regs[addr] = read_u16be(req->write_data + i * 2);
        }
    }
    
    // ✅ 注意：这里需要修改返回机制
    // 当前实现直接返回，但响应数据在栈上
    // 需要修改 API 设计或使用全局缓冲区
    
    int ret = (int)response_size;
    free(response);  // ⚠️ 问题：数据已释放
    return ret;
}
```

**问题**：当前 API 设计不支持动态分配，需要修改函数签名：

```c
// 修改头文件 modbus_proto.h
int modbus_handle_fc17(const modbus_request_t *req,
                       modbus_mapping_t *map,
                       uint8_t *out,           // ✅ 新增：输出缓冲区
                       size_t out_max);        // ✅ 新增：缓冲区大小

// 修改实现
int modbus_handle_fc17(const modbus_request_t *req,
                       modbus_mapping_t *map,
                       uint8_t *out,
                       size_t out_max)
{
    if (!req || !map || !out) return -1;
    
    // 验证
    if (req->nb_read == 0 || req->nb_read > 125) return -1;
    
    size_t needed = MBAP_LEN + 3 + req->nb_read * 2;
    if (needed > out_max) return -1;  // ✅ 边界检查
    
    // 直接写入调用者提供的缓冲区
    write_u16be(out + 0, req->transaction_id);
    // ... 其余逻辑
    
    return (int)needed;
}

// 修改调用点 modbus_reply()
int modbus_reply(modbus_mapping_t *map,
                 const uint8_t *req_buf, size_t req_len,
                 uint8_t *resp_buf, size_t resp_max)
{
    modbus_request_t req;
    if (modbus_parse_request(req_buf, req_len, &req) != 0) return -1;
    
    if (req.function_code == FC_READ_WRITE_REGS) {
        // ✅ 传递输出缓冲区
        return modbus_handle_fc17(&req, map, resp_buf, resp_max);
    }
    return modbus_build_response(&req, map, resp_buf, resp_max);
}
```

**优点**：
- ✅ 完全解决根本问题
- ✅ 统一 API 设计
- ✅ 未来扩展性好

**缺点**：
- ⚠️ 需要修改多个文件
- ⚠️ API 变更可能影响其他代码
- ⚠️ 测试工作量大

---

### ✅ 方案 4：完全重构（推荐用于新版本）

**架构改进**：

1. **统一缓冲区管理**
```c
typedef struct {
    uint8_t *data;
    size_t   size;
    size_t   capacity;
} modbus_buffer_t;

modbus_buffer_t *modbus_buffer_alloc(size_t initial_size);
int modbus_buffer_ensure(modbus_buffer_t *buf, size_t needed);
void modbus_buffer_free(modbus_buffer_t *buf);
```

2. **输入验证中心化**
```c
typedef struct {
    uint16_t min_read;
    uint16_t max_read;
    uint16_t min_write;
    uint16_t max_write;
} modbus_limits_t;

int modbus_validate_request(const modbus_request_t *req,
                            const modbus_limits_t *limits);
```

3. **安全编码模式**
```c
// 所有写操作使用安全包装
static inline int safe_write_u16be(uint8_t *buf, size_t buf_size,
                                   size_t offset, uint16_t value)
{
    if (offset + 2 > buf_size) return -1;
    buf[offset]     = (uint8_t)(value >> 8);
    buf[offset + 1] = (uint8_t)(value & 0xFF);
    return 0;
}
```

---

## 强化输入验证

### 修改 `modbus_parse_request()`

```c
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
    
    // ✅ 验证协议ID
    if (req->protocol_id != 0x0000) return -1;
    
    // ✅ 验证 PDU 长度
    if (req->pdu_length > MODBUS_MAX_PDU) return -1;
    if (req->pdu_length != len - MBAP_LEN) return -1;
    
    const uint8_t *pdu  = buf + MBAP_LEN + 1;
    size_t         plen = len - MBAP_LEN - 1;
    
    switch (req->function_code) {
    
    case FC_READ_COILS:
    case FC_READ_HOLDING_REGS:
        if (plen < 5) return -1;
        req->read_addr = read_u16be(pdu + 1);
        req->nb_read   = read_u16be(pdu + 3);
        
        // ✅ 新增：验证数量范围
        if (req->function_code == FC_READ_COILS && req->nb_read > 2000) return -1;
        if (req->function_code == FC_READ_HOLDING_REGS && req->nb_read > 125) return -1;
        
        // ✅ 新增：验证地址范围
        if (req->read_addr + req->nb_read > MODBUS_MAX_REGS) return -1;
        break;
    
    case FC_WRITE_SINGLE_REG:
        if (plen < 5) return -1;
        req->write_addr = read_u16be(pdu + 1);
        req->nb_write   = 1;
        
        // ✅ 新增：验证地址
        if (req->write_addr >= MODBUS_MAX_REGS) return -1;
        break;
    
    case FC_WRITE_MULTIPLE_REGS:
        if (plen < 6) return -1;
        req->write_addr  = read_u16be(pdu + 1);
        req->nb_write    = read_u16be(pdu + 3);
        req->write_count = pdu[5];
        
        // ✅ 新增：验证一致性
        if (req->nb_write > 123) return -1;
        if (req->write_count != req->nb_write * 2) return -1;
        if (plen < 6 + req->write_count) return -1;
        
        // ✅ 新增：验证地址范围
        if (req->write_addr + req->nb_write > MODBUS_MAX_REGS) return -1;
        
        memcpy(req->write_data, pdu + 6, req->write_count);
        break;
    
    case FC_READ_WRITE_REGS:
        if (plen < 10) return -1;
        req->read_addr   = read_u16be(pdu + 1);
        req->nb_read     = read_u16be(pdu + 3);
        req->write_addr  = read_u16be(pdu + 5);
        req->nb_write    = read_u16be(pdu + 7);
        req->write_count = pdu[9];
        
        // ✅ 新增：严格验证
        if (req->nb_read == 0 || req->nb_read > 125) return -1;
        if (req->nb_write > 121) return -1;
        if (req->write_count != req->nb_write * 2) return -1;
        if (plen < 10 + req->write_count) return -1;
        
        // ✅ 新增：验证地址范围
        if (req->read_addr + req->nb_read > MODBUS_MAX_REGS) return -1;
        if (req->write_addr + req->nb_write > MODBUS_MAX_REGS) return -1;
        
        if (req->write_count > MODBUS_MAX_PDU) return -1;
        memcpy(req->write_data, pdu + 10, req->write_count);
        break;
    
    default:
        // ✅ 新增：拒绝未知功能码
        return -1;
    }
    
    return 0;
}
```

---

## 编译安全选项

### Makefile 强化

```makefile
# 生产环境编译标志
CFLAGS_SECURE = -Wall -Wextra -Werror \
                -Wformat=2 \
                -Wformat-security \
                -Werror=format-security \
                -D_FORTIFY_SOURCE=2 \
                -fstack-protector-strong \
                -fPIE \
                -fno-strict-overflow \
                -fno-delete-null-pointer-checks

LDFLAGS_SECURE = -Wl,-z,relro \
                 -Wl,-z,now \
                 -Wl,-z,noexecstack \
                 -pie

# 调试构建（用于开发）
debug: CFLAGS += -g -O0 -fsanitize=address,undefined
debug: $(TARGET)

# 生产构建
release: CFLAGS += $(CFLAGS_SECURE) -O2
release: LDFLAGS += $(LDFLAGS_SECURE)
release: $(TARGET)

# 静态分析
analyze:
	cppcheck --enable=all --inconclusive --std=c11 src/
	clang-tidy src/*.c -- -I include/
```

---

## 测试计划

### 1. 单元测试

```c
// tests/test_overflow.c
#include <assert.h>
#include "modbus_proto.h"

void test_nb_read_boundary() {
    modbus_request_t req = {0};
    modbus_mapping_t *map = modbus_mapping_new();
    uint8_t resp[512];
    
    // 测试安全值
    req.function_code = FC_READ_WRITE_REGS;
    req.nb_read = 59;
    int ret = modbus_handle_fc17(&req, map, resp, sizeof(resp));
    assert(ret > 0);  // 应该成功
    
    // 测试溢出值
    req.nb_read = 126;
    ret = modbus_handle_fc17(&req, map, resp, sizeof(resp));
    assert(ret == -1);  // 应该拒绝
    
    modbus_mapping_free(map);
}

void test_address_overflow() {
    modbus_request_t req = {0};
    req.read_addr = 500;
    req.nb_read = 50;  // 500 + 50 = 550 > MODBUS_MAX_REGS (512)
    
    int ret = modbus_parse_request(...);
    assert(ret == -1);  // 应该拒绝
}
```

### 2. 模糊测试

```bash
# AFL++ 模糊测试
AFL_USE_ASAN=1 afl-clang-fast -o modbus_parser_afl \
    -fsanitize=address \
    src/main.c src/modbus_proto.c

# 创建种子库
mkdir -p seeds/
python3 poc_exploit.py  # 生成测试用例

# 开始模糊测试
afl-fuzz -i seeds/ -o findings/ -m none -- ./modbus_parser_afl @@

# 分析结果
afl-whatsup findings/
```

### 3. 回归测试

```bash
#!/bin/bash
# regression_test.sh

echo "运行回归测试..."

# 正常功能测试
./modbus_parser seeds/normal_read.bin || exit 1
./modbus_parser seeds/normal_write.bin || exit 1

# 边界测试
./modbus_parser seeds/max_read_125.bin || exit 1

# 异常输入测试（应该优雅失败）
./modbus_parser seeds/invalid_overflow.bin
if [ $? -eq 0 ]; then
    echo "错误: 应该拒绝溢出输入"
    exit 1
fi

echo "所有回归测试通过"
```

---

## 部署检查表

- [ ] 代码审查完成
- [ ] 单元测试通过
- [ ] 集成测试通过
- [ ] 模糊测试运行 24 小时无崩溃
- [ ] 静态分析工具检查通过 (cppcheck, clang-tidy)
- [ ] AddressSanitizer 构建测试通过
- [ ] UndefinedBehaviorSanitizer 测试通过
- [ ] 性能测试（确保修复无性能退化）
- [ ] 文档更新（CHANGELOG, API文档）
- [ ] 安全公告发布（如果是公开项目）
- [ ] CVE 编号申请（如果适用）

---

## 长期建议

1. **安全开发流程**
   - 引入 SAST/DAST 工具到 CI/CD
   - 定期进行渗透测试
   - 建立漏洞赏金计划

2. **代码质量**
   - 采用 MISRA C 或 CERT C 编码标准
   - 增加代码覆盖率要求（>80%）
   - 引入形式化验证（如 Frama-C）

3. **架构改进**
   - 使用内存安全语言重写关键路径（Rust）
   - 实现沙箱隔离机制
   - 添加速率限制和异常检测

4. **监控与响应**
   - 部署入侵检测系统 (IDS)
   - 实时监控异常请求模式
   - 建立安全事件响应流程

---

## 参考资源

- [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [CVE-2022-0367](https://nvd.nist.gov/vuln/detail/CVE-2022-0367)
- [OWASP Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)
- [Modbus Protocol Specification](https://www.modbus.org/specs.php)
