"""
全局响应包装器
所有 HTTP 接口（除 WebSocket 外）的响应均使用此格式。
"""
from typing import Any

from fastapi.responses import JSONResponse


def ok(data: Any = None, message: str = "成功") -> dict:
    """成功响应"""
    return {"code": 200, "message": message, "data": data}


def fail(code: int, message: str) -> JSONResponse:
    """Return a business envelope with the matching HTTP status code."""
    return JSONResponse(
        status_code=code,
        content={"code": code, "message": message, "data": None},
    )
