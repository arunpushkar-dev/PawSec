"""SQLAlchemy ORM models for PawSec Server."""

from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Text, DateTime, Boolean, ForeignKey, JSON
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    user_id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False)
    company_id = Column(String(64), nullable=True)
    email = Column(String(256), nullable=False, unique=True)
    api_key = Column(String(64), nullable=False, unique=True)
    is_admin = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

    sessions = relationship("Session", back_populates="user")
    prompts = relationship("PromptRecord", back_populates="user")


class Session(Base):
    __tablename__ = "sessions"

    session_id = Column(String(36), primary_key=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow, nullable=False)
    user_agent = Column(Text, nullable=True)
    extension_version = Column(String(20), nullable=True)
    platform_hint = Column(String(32), nullable=True)

    # FK to user (nullable for backward compat)
    user_id = Column(String(36), ForeignKey("users.user_id"), nullable=True)

    # Aggregated counters (updated on each prompt)
    prompt_count = Column(Integer, default=0)
    blocked_count = Column(Integer, default=0)
    warned_count = Column(Integer, default=0)
    allowed_count = Column(Integer, default=0)

    user = relationship("User", back_populates="sessions")
    prompts = relationship("PromptRecord", back_populates="session",
                           cascade="all, delete-orphan")


class PromptRecord(Base):
    __tablename__ = "prompt_records"

    prompt_id = Column(String(36), primary_key=True)
    session_id = Column(String(36), ForeignKey("sessions.session_id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    # FK to user (nullable for backward compat)
    user_id = Column(String(36), ForeignKey("users.user_id"), nullable=True)

    # Masked text only — plain prompt never stored
    masked_text = Column(Text, nullable=True)

    platform = Column(String(32), nullable=True)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(16), default="SAFE")
    action_taken = Column(String(16), default="ALLOWED")  # BLOCKED | WARNED | ALLOWED

    # Full analysis result as JSON blob
    analysis_result = Column(JSON, nullable=True)

    # Summary counts (denormalised for fast dashboard queries)
    pii_count = Column(Integer, default=0)
    phi_count = Column(Integer, default=0)
    code_threats = Column(Integer, default=0)
    api_secrets_count = Column(Integer, default=0)
    credentials_count = Column(Integer, default=0)
    private_url_count = Column(Integer, default=0)
    business_data_count = Column(Integer, default=0)
    financial_data_count = Column(Integer, default=0)
    llm_intent = Column(String(32), nullable=True)

    # In-browser result snapshot (for comparison/audit)
    in_browser_result = Column(JSON, nullable=True)

    user = relationship("User", back_populates="prompts")
    session = relationship("Session", back_populates="prompts")
