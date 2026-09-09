# 贡献指南

本仓库保留 SC-SENTINEL 的比赛版本，也欢迎有助于教学和复用的改进。

## 提交前

1. 先通过 Issue 说明遇到的问题或计划修改的内容。
2. 不要提交生成产物、凭据、本地 `.env` 文件和测试输出。
3. 未经相关权利人同意，不要添加个人信息、比赛资料或照片。
4. 保留第三方许可证和署名声明。
5. 仅在隔离且获得授权的环境中使用漏洞样本。

## 开发检查

根据修改范围执行相应检查：

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
