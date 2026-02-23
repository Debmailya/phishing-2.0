from fastapi import FastAPI

from app.api.v1 import analytics, auth, scans
from app.db.session import Base, engine
from app.middleware.logging import RequestAuditMiddleware

Base.metadata.create_all(bind=engine)

app = FastAPI(title="PhishGuard AI Enterprise", version="2.0.0")
app.add_middleware(RequestAuditMiddleware)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(analytics.router, prefix="/api/v1")


@app.get("/health")
def health():
    return {"status": "ok", "service": "api-gateway"}
