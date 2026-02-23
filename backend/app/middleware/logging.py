import hashlib
import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("phishguard.api")


class RequestAuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000, 2)
        raw_url = str(request.url)
        hashed = hashlib.sha256(raw_url.encode()).hexdigest()[:12]
        logger.info(
            "request_completed",
            extra={
                "path": request.url.path,
                "method": request.method,
                "url_hash": hashed,
                "status": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response
