# SC-SENTINEL Frontend

前端基于 Vue 3、TypeScript、Vite、Pinia 与 Vue Router，结合 Element Plus、ECharts 和 Tailwind CSS 展示任务、审计进度与风险报告。

## 页面与交互

| 页面 | 功能 |
| --- | --- |
| 系统首页 | 展示项目能力、审计概况与任务入口 |
| 审计提交 | 上传源码 ZIP、ELF/PE 文件或填写 Git 仓库地址，选择漏洞类型与可用的验证策略 |
| 任务监控 | 通过 WebSocket 查看流水线进度、实时日志与执行状态 |
| 审计报告 | 展示组件风险、漏洞定位、已采集的动态证据、风险裁决及 PDF 导出 |
| 历史任务 | 查询和筛选任务记录，查看已完成报告与管理任务 |

报告展示 `confirmed`（已确认）、`unverified`（未验证、需复核）、`not_reproduced`（当前未复现）与 `false_positive`（已排除）四类裁决状态，并按实际采集情况关联 CWE、位置、触发条件、ASan 错误、AFL++ 样例和 eBPF 事件。独立 ELF/PE 文件只生成静态候选，运行时验证选项不可用。

## 演示登录

默认账号为 `sentinel-demo`，密码为 `sentinel2026`。本地开发或构建前可使用 `VITE_DEMO_LOGIN_USERNAME` 与 `VITE_DEMO_LOGIN_PASSWORD` 覆盖，修改后重新构建前端。该账号用于比赛演示；公开部署通过认证网关保护访问。

## 本地开发

在本目录执行：

```bash
npm ci
npm run dev
```

构建使用 `npm run build`。全栈部署由上一级 Compose 文件完成，Nginx 提供静态页面及 API、WebSocket 代理，访问地址为 <http://localhost:8080>。
