# 贡献指南

本仓库保留 SC-SENTINEL 首次上传的比赛版本，后续不安排常规开发。欢迎反馈文档问题和复现经验，但不承诺合并或响应时限。`code/` 按原始内容保留；如需修改实现，建议 Fork 后在自己的仓库继续开发。

## 提交前

1. 错字、失效链接等小幅文档修正可直接提交 PR；较大调整请先通过 Issue 说明计划修改的内容。
2. 不要提交生成产物、凭据、本地 `.env` 文件和测试输出。
3. 未经相关权利人同意，不要添加个人信息、比赛资料或照片。
4. 保留第三方许可证和署名声明。
5. 仅在隔离且获得授权的环境中使用漏洞样本。

## 开发检查

根据修改范围执行相应检查。仅修改 Markdown 时，检查文字、相对链接和命令说明即可，无需运行与修改无关的代码测试。

归档导航和原始代码完整性可在仓库根目录运行 `python scripts/check_archive.py` 检查。下面的开发命令供 Fork 后继续开发时参考，原始依赖与运行限制见[归档检查记录](ARCHIVE_STATUS.md)。

以下每组命令均从仓库根目录开始。后端与分析引擎建议使用各自的 Python 虚拟环境。

后端：

```powershell
cd code/sentinel_backend
python -m pip install -r requirements.txt
python -m pip install pytest pytest-asyncio
python -m pytest
```

分析引擎：

```powershell
cd code/sentinel_agent
python -m pip install -r requirements.txt
python -m pip install pytest
python -m pytest
```

前端：

```powershell
cd code/sentinel_frontend
npm ci
npm run build
```

## 贡献内容的许可

除非明确另行说明，主动提交到本仓库的贡献按 Apache License 2.0 第 5 条提供。已有其他许可证约束的材料继续遵循其原有条款。
