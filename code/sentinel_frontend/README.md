# SENTINEL 前端

前端提供任务提交、实时进度、历史记录与审计报告界面。

## 演示登录

前端提供本地演示访问控制，默认账号为 `sentinel-demo`，默认密码为 `sentinel2026`。可在启动前使用 `VITE_DEMO_LOGIN_USERNAME` 和 `VITE_DEMO_LOGIN_PASSWORD` 覆盖。该功能用于答辩演示的页面访问控制；生产部署应由后端认证接口签发并校验令牌。

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

在本目录执行：

```bash
npm ci
npm run dev
```

构建与类型检查：

```bash
npm run build
```

完整平台的启动方式见 [运行说明](../README.md)。
