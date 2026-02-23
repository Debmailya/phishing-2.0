import time
from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt
from redis import Redis
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.entities import Organization, User

redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


def get_current_user(
    authorization: str = Header(default=""), db: Session = Depends(get_db)
) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    user = db.query(User).filter(User.email == payload.get("sub")).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive user")
    return user


def require_role(allowed_roles: list[str]) -> Callable:
    def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return role_checker


def validate_api_key(
    x_api_key: str = Header(default=""), db: Session = Depends(get_db)
) -> Organization:
    org = db.query(Organization).filter(Organization.api_key == x_api_key).first()
    if not org:
        raise HTTPException(status_code=401, detail="Invalid API key")

    current_minute = int(time.time() // 60)
    bucket = f"rate:{org.id}:{current_minute}"
    count = redis_client.incr(bucket)
    if count == 1:
        redis_client.expire(bucket, 60)
    if count > org.rate_limit_per_minute:
        raise HTTPException(status_code=429, detail="Organization rate limit exceeded")
    return org
