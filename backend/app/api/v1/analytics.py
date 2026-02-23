from datetime import date, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.db.session import get_db
from app.models.entities import ThreatScan, User

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/overview")
def threat_overview(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    start = date.today() - timedelta(days=30)
    scans = (
        db.query(ThreatScan)
        .filter(ThreatScan.organization_id == user.organization_id)
        .filter(ThreatScan.created_at >= start)
    )
    total = scans.count()
    malicious = scans.filter(ThreatScan.verdict == "malicious").count()
    suspicious = scans.filter(ThreatScan.verdict == "suspicious").count()
    avg_risk = scans.with_entities(func.avg(ThreatScan.risk_score)).scalar() or 0

    return {
        "organization_id": user.organization_id,
        "period": "30d",
        "total_scans": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "avg_risk": round(float(avg_risk), 2),
    }


@router.post("/retrain")
def trigger_retraining(_: User = Depends(require_role(["admin", "analyst"]))):
    return {"status": "queued", "message": "Model retraining pipeline triggered"}
