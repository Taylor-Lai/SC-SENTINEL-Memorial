# ============================================================
# SENTINEL Frontend Dockerfile（多阶段构建）
# 阶段一：Node 构建 Vue 静态产物
# 阶段二：Nginx 提供静态文件 + 反向代理 /api 到后端
# ============================================================

# ── 阶段一：构建 ──────────────────────────────────────────────────────
FROM node:25-alpine AS build

WORKDIR /app

# 先装依赖（利用层缓存）
COPY package.json package-lock.json ./
RUN npm ci

# 构建（vue-tsc 类型检查 + vite build）
COPY . .
RUN npm run build

# ── 阶段二：Nginx 运行 ────────────────────────────────────────────────
FROM nginx:1.27-alpine

# 自定义 Nginx 配置（SPA history 路由 + /api 反代 + WebSocket 升级）
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 拷贝构建产物
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
