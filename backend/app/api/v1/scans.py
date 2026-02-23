import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import validate_api_key
from app.db.session import get_db
from app.middleware.security import validate_target_url
from app.models.entities import Organization, ThreatScan
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.detection import DetectionService
from app.services.intel import google_safe_browsing_lookup

router = APIRouter(prefix="/scans", tags=["scans"])
detector = DetectionService()


@router.post("", response_model=ScanResponse)
async def run_scan(
    payload: ScanRequest,
    org: Organization = Depends(validate_api_key),
    db: Session = Depends(get_db),
):
    validate_target_url(str(payload.url))
    result = detector.scan(str(payload.url))
    if await google_safe_browsing_lookup(str(payload.url)):
        result["risk_score"] = min(100, result["risk_score"] + 30)
        result["reasons"].append("google_safe_browsing_match")
        result["verdict"] = "malicious"

    record = ThreatScan(
        organization_id=org.id,
        submitted_url_hash=detector.hash_url(str(payload.url)),
        detected_brand=result.get("detected_brand"),
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        evidence=json.dumps(result["reasons"]),
    )
    db.add(record)
    db.commit()
    return ScanResponse(**result)
