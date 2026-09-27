# SENTINEL 前端

前端提供任务提交、实时进度、历史记录与审计报告界面。

## 演示登录

前端提供本地演示访问控制，默认账号为 `sentinel-demo`，默认密码为 `sentinel2026`。本地开发可在前端目录的 `.env.local` 中设置 `VITE_DEMO_LOGIN_USERNAME` 和 `VITE_DEMO_LOGIN_PASSWORD`，并重启开发服务。Vite 会在构建时写入这些值，已构建的静态页面不能通过修改容器运行时环境变量更新账号；自定义镜像需在前端构建阶段提供配置并重新构建。默认 Docker 构建还会通过 `.dockerignore` 排除 `.env*`，仅在本地增加 `.env.local` 不会改变默认镜像中的账号。该功能用于答辩演示的页面访问控制；生产部署应由后端认证接口签发并校验令牌。

## 技术栈

Vue 3、Vite、TypeScript、Pinia、Vue Router、Element Plus、ECharts 与 Tailwind CSS。

## 页面导航

| 页面 | 文件 | 用途 |
| --- | --- | --- |
| 登录 | `LoginView.vue` | 演示登录 |
| 首页 | `HomeView.vue` | 项目概览与功能入口 |
| 新建审计 | `SubmitView.vue` | 上传 ZIP 或提交仓库地址，选择审计策略 |
| 实时监控 | `MonitorView.vue` | 查看任务进度与 WebSocket 日志 |
| 审计报告 | `ReportView.vue` | 查看风险统计、组件风险、漏洞详情与动态证据 |
| 历史任务 | `HistoryView.vue` | 查看历史任务与状态 |

页面文件位于 [src/views/](src/views/)，路由配置位于 [src/router/index.ts](src/router/index.ts)。

## 本地开发

在 `code/sentinel_frontend/` 目录执行。仓库 CI 使用 Node.js 22，可按该版本准备本地开发环境：

```bash
npm ci
npm run dev
```

开发页面默认位于 `http://localhost:5400`。Vite 将 `/api` 请求和 WebSocket 代理到 `http://127.0.0.1:18000`，因此需同时运行后端。端口与代理配置见 [vite.config.ts](vite.config.ts)。

构建与类型检查：

```bash
npm run build
```

构建产物位于 `dist/`；Compose 使用 Nginx 提供静态页面并代理 API 与 WebSocket。完整平台的启动方式见 [部署指南](../DOCKER.md)。

[返回代码导航](../README.md)
