import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.security import create_access_token, verify_password
from app.db.session import get_db
from app.models.entities import Organization, User
from app.schemas.auth import LoginRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(
        subject=user.email,
        extra_claims={"role": user.role, "organization_id": user.organization_id},
    )
    return TokenResponse(access_token=token)


@router.post("/organizations/{organization_id}/api-key")
def rotate_api_key(
    organization_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(["admin"])),
):
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    org.api_key = f"pg_{secrets.token_hex(24)}"
    db.commit()
    return {"organization_id": org.id, "api_key": org.api_key}


@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "email": current_user.email,
        "role": current_user.role,
        "organization_id": current_user.organization_id,
    }
