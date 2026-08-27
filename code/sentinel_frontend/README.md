# SENTINEL Frontend

## 演示登录

前端提供本地演示访问控制，默认账号为 `sentinel-demo`，默认密码为
`sentinel2026`。可在启动前使用 `VITE_DEMO_LOGIN_USERNAME` 和
`VITE_DEMO_LOGIN_PASSWORD` 覆盖。该能力用于答辩演示的页面访问控制；生产
部署应由后端认证接口签发并校验令牌。
让ai生成了一个试试的，后面再改

## 选用技术栈
- Vue 3 + Vite
- TypeScript
- Pinia 
- Vue Router 
- Element Plus 
- ECharts 
- Tailwind CSS 


## 1. 页面模块实现

目前已完成以下 4 个核心视图的开发：

### 1.1 首页 (HomeView)
提供审计任务的提交入口。
*   支持 ZIP 文件上传或填写 GitHub 仓库地址。
*   支持“目标漏洞类型”多选与“开启动态验证”开关。

### 1.2 任务列表 (TaskListView)
展示所有历史任务及其当前状态。
*   支持按项目名和任务状态筛选。
*   支持强杀终止运行中的任务。

### 1.3 审计报告 (ReportView)
核心结果展示大屏。
*   **进度视图**: 任务执行期间展示 WebSocket 推送的实时终端日志。
*   **概要视图**: 漏洞与组件的统计分布（ECharts 饼图/柱状图）。
*   **组件风险**: 列表展示 SBOM 扫出的第三方库 CVE 漏洞信息。
*   **漏洞清单**: 漏洞详情展示，并对漏洞代码块进行语法高亮与行号标红。
*   **动态验证**: 显示 AFL++ 产生的崩溃日志及 eBPF 捕获的底层内核事件序列。

### 1.4 关于页 (AboutView)
展示系统架构和技术栈列表。

---
