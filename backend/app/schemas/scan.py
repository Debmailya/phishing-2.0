from datetime import datetime
from pydantic import BaseModel, HttpUrl


class ScanRequest(BaseModel):
    url: HttpUrl


class ScanResponse(BaseModel):
    risk_score: float
    verdict: str
    reasons: list[str]
    detected_brand: str | None = None
    created_at: datetime
