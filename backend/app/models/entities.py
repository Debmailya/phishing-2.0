from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db.session import Base


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    api_key = Column(String(255), unique=True, nullable=False)
    rate_limit_per_minute = Column(Integer, default=120)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", back_populates="organization")


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user")
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    is_active = Column(Boolean, default=True)

    organization = relationship("Organization", back_populates="users")


class ThreatScan(Base):
    __tablename__ = "threat_scans"
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    submitted_url_hash = Column(String(255), nullable=False)
    detected_brand = Column(String(255), nullable=True)
    risk_score = Column(Float, default=0.0)
    verdict = Column(String(30), default="unknown")
    evidence = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)
