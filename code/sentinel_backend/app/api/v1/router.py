"""
API v1 路由聚合器
将 tasks、audit 和 ws 三个子路由统一注册到 /api/v1 前缀下。
"""
from fastapi import APIRouter

from app.api.v1.audit import router as audit_router
from app.api.v1.tasks import router as tasks_router
from app.api.v1.ws import ws_router

v1_router = APIRouter(prefix="/api/v1")

# HTTP 接口：任务 CRUD（7 个）
v1_router.include_router(tasks_router)

# HTTP 接口：审计调度（2 个）
v1_router.include_router(audit_router)

# WebSocket 接口（1 个）
v1_router.include_router(ws_router)
