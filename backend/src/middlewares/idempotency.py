import time
from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.exc import IntegrityError
from src.config.database import Session
from src.models import IdempotencyRecord

# 登录本身不做幂等缓存；文件上传核验是只读操作，也无需缓存。
SKIP_PATHS = {'/auth/login', '/credibility/seals/verify-upload'}


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """基于 Idempotency-Key 的请求幂等。

    - 同一 key 的首个请求正常执行业务并缓存响应体；
    - 重试在业务未变更的情况下回放缓存，不重复变更、不重复记账；
    - 业务失败（4xx/5xx）不保留记录，允许客户端修正后用同一 key 重试；
    - 并发同 key 请求：唯一约束保证只有一个进入业务，其余收到 409 提示稍后重试。
    """
    async def dispatch(self, request: Request, call_next):
        key = request.headers.get('idempotency-key')
        if request.method != 'POST' or not key or request.url.path in SKIP_PATHS:
            return await call_next(request)
        key = key.strip()[:200]
        with Session() as db:
            existing = db.query(IdempotencyRecord).filter_by(key=key).one_or_none()
            if existing and existing.status_code is not None:
                if existing.path != request.url.path:
                    return JSONResponse(
                        {'detail': '该幂等密钥已用于其他操作，请更换密钥'}, status_code=409)
                return Response(
                    content=existing.response_body,
                    status_code=existing.status_code,
                    media_type='application/json',
                    headers={'Idempotent-Replay': 'true'},
                )
            if existing:
                return JSONResponse({'detail': '相同请求正在处理中，请稍后用同一密钥重试'}, status_code=409)
            record = IdempotencyRecord(key=key, path=request.url.path, created_at=time.time())
            db.add(record)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                return JSONResponse({'detail': '相同请求正在处理中，请稍后用同一密钥重试'}, status_code=409)

        response = await call_next(request)
        try:
            body = b''
            async for chunk in response.body_iterator:
                body += chunk
        except Exception:
            # 业务内部异常：清除占位，允许客户端用同一密钥安全重试。
            with Session() as db:
                rec = db.query(IdempotencyRecord).filter_by(key=key).one_or_none()
                if rec is not None:
                    db.delete(rec)
                    db.commit()
            raise

        with Session() as db:
            record = db.query(IdempotencyRecord).filter_by(key=key).one_or_none()
            if record is None:
                return Response(content=body, status_code=response.status_code,
                                headers=dict(response.headers), media_type=response.media_type)
            if 200 <= response.status_code < 300:
                record.status_code = response.status_code
                record.response_body = body.decode('utf-8')
                record.completed_at = time.time()
                db.commit()
            else:
                # 失败不留痕：回滚业务语义上由路由自身保证，这里删除占位以便安全重试。
                db.delete(record)
                db.commit()

        headers = dict(response.headers)
        headers['Idempotency-Key'] = key
        return Response(content=body, status_code=response.status_code,
                        headers=headers, media_type=response.media_type)
