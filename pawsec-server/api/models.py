"""Pydantic request/response models — defines the API contract."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# ── Sub-models: per-skill analysis results ────────────────────────────────────

class PIIAnalysis(BaseModel):
    detected: bool = False
    count: int = 0
    risk_level: str = "SAFE"
    findings_summary: List[str] = []
    masked_text: Optional[str] = None


class PHIAnalysis(BaseModel):
    detected: bool = False
    count: int = 0
    has_critical: bool = False
    has_high: bool = False
    categories_detected: List[str] = []
    summary: Optional[str] = None


class CodeInjectionAnalysis(BaseModel):
    threat_detected: bool = False
    code_types: List[str] = []
    threat_count: int = 0


class APISecretsAnalysis(BaseModel):
    threat_detected: bool = False
    count: int = 0
    risk_level: str = "SAFE"
    secrets_summary: List[Dict[str, str]] = []  # [{service, type, severity}]


class CredentialsAnalysis(BaseModel):
    detected: bool = False
    count: int = 0
    risk_level: str = "SAFE"
    findings_summary: List[Dict[str, str]] = []  # [{type, name, severity}]


class PrivateURLAnalysis(BaseModel):
    detected: bool = False
    count: int = 0
    risk_level: str = "SAFE"
    urls_summary: List[Dict[str, str]] = []  # [{type, name, risk}]


class BusinessDataAnalysis(BaseModel):
    detected: bool = False
    count: int = 0
    risk_level: str = "SAFE"
    findings_summary: List[Dict[str, str]] = []  # [{type, name, jurisdiction}]


class FinancialDataAnalysis(BaseModel):
    detected: bool = False
    count: int = 0
    risk_level: str = "SAFE"
    distinct_financial_figures: int = 0
    findings_summary: List[Dict[str, str]] = []  # [{type, name, amount_hint}]


class UnknownMaliciousIntentAnalysis(BaseModel):
    detected: bool = False
    count: int = 0
    risk_level: str = "SAFE"
    findings: List[Dict[str, str]] = []


class LLMClassification(BaseModel):
    available: bool = False
    Intent_Category: Optional[str] = None
    Generic_Persona_Category: Optional[str] = None
    Pattern: Optional[str] = None
    Intent_Risk_Severity: Optional[str] = None
    Persona_Risk_Severity: Optional[str] = None
    Pattern_Risk_Severity: Optional[str] = None


class RiskBreakdown(BaseModel):
    total_score: int = 0
    effective_score: int = 0
    risk_level: str = "SAFE"
    breakdown: Dict[str, Any] = {}
    recommendations: List[str] = []


class AnalysisResult(BaseModel):
    pii: Optional[PIIAnalysis] = None
    phi: Optional[PHIAnalysis] = None
    code_injection: Optional[CodeInjectionAnalysis] = None
    api_secrets: Optional[APISecretsAnalysis] = None
    credentials: Optional[CredentialsAnalysis] = None
    private_url: Optional[PrivateURLAnalysis] = None
    business_data: Optional[BusinessDataAnalysis] = None
    financial_data: Optional[FinancialDataAnalysis] = None
    unknown_malicious_intent: Optional[UnknownMaliciousIntentAnalysis] = None
    llm_classification: Optional[LLMClassification] = None
    risk: Optional[RiskBreakdown] = None


# ── In-browser result snapshot ────────────────────────────────────────────────

class InBrowserResult(BaseModel):
    pii_detected: bool = False
    code_injection_detected: bool = False
    api_secrets_detected: bool = False
    credentials_detected: bool = False
    private_url_detected: bool = False
    risk_level: str = "SAFE"
    risk_score: int = 0


# ── POST /api/v1/sessions ─────────────────────────────────────────────────────

class SessionCreateRequest(BaseModel):
    user_agent: Optional[str] = None
    extension_version: Optional[str] = None
    platform_hint: Optional[str] = None


class SessionCreateResponse(BaseModel):
    session_id: str
    started_at: datetime


# ── POST /api/v1/analyze ──────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    prompt_text: str = Field(..., min_length=1, max_length=50000,
                             description="Pre-masked prompt text from the extension")
    session_id: Optional[str] = None
    platform: str = "unknown"
    extension_version: Optional[str] = None
    user_agent: Optional[str] = None
    in_browser_result: Optional[InBrowserResult] = None
    analyzers_requested: List[str] = Field(
        default=["pii", "phi", "code_injection", "api_secrets",
                 "credentials", "private_url", "business_data",
                 "financial_data", "unknown_malicious_intent", "llm", "risk"]
    )


class AnalyzeResponse(BaseModel):
    prompt_id: str
    session_id: Optional[str]
    timestamp: datetime
    action_taken: str        # BLOCKED | WARNED | ALLOWED
    risk_score: int
    risk_level: str
    analysis: Dict[str, Any]
    recommendations: List[str] = []


# ── GET /api/v1/sessions ──────────────────────────────────────────────────────

class SessionSummary(BaseModel):
    session_id: str
    started_at: datetime
    last_activity: datetime
    prompt_count: int
    blocked_count: int
    warned_count: int
    allowed_count: int
    platform: Optional[str]


class SessionListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    sessions: List[SessionSummary]


# ── GET /api/v1/sessions/{id} ─────────────────────────────────────────────────

class PromptSummary(BaseModel):
    prompt_id: str
    timestamp: datetime
    masked_text: Optional[str]
    risk_score: int
    risk_level: str
    action_taken: str
    platform: Optional[str]
    pii_count: int
    phi_count: int
    code_threats: int
    api_secrets_count: int
    credentials_count: int
    llm_intent: Optional[str]


class SessionDetailResponse(BaseModel):
    session_id: str
    user_agent: Optional[str]
    extension_version: Optional[str]
    started_at: datetime
    last_activity: datetime
    prompt_count: int
    blocked_count: int
    warned_count: int
    allowed_count: int
    prompts: List[PromptSummary]


# ── GET /api/v1/stats ─────────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    total_prompts: int
    blocked: int
    warned: int
    allowed: int
    platform_breakdown: Dict[str, int]
    risk_distribution: Dict[str, int]


# ── GET /health ───────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    ollama_available: bool
    db_connected: bool
    uptime_seconds: float


# ── User management models ────────────────────────────────────────────────────

class UserResponse(BaseModel):
    user_id: str
    name: str
    company_id: Optional[str]
    email: str
    api_key: str
    is_admin: bool
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime]
    notes: Optional[str]


class UserMeResponse(BaseModel):
    user_id: str
    name: str
    email: str
    company_id: Optional[str]
    is_admin: bool


class UserCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    email: str = Field(..., min_length=1, max_length=256)
    company_id: Optional[str] = Field(None, max_length=64)
    notes: Optional[str] = None


class UserUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    email: Optional[str] = Field(None, min_length=1, max_length=256)
    company_id: Optional[str] = Field(None, max_length=64)
    is_active: Optional[bool] = None
    notes: Optional[str] = None


class UserListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    users: List[UserResponse]


class AdminUserStats(BaseModel):
    user_id: str
    name: str
    company_id: Optional[str]
    email: str
    blocked: int
    warned: int
    allowed: int
    total: int
    last_active: Optional[str]


class AdminStatsResponse(BaseModel):
    total_users: int
    total_prompts: int
    blocked: int
    warned: int
    allowed: int
    per_user: List[AdminUserStats]


class AdminSessionSummary(BaseModel):
    session_id: str
    started_at: datetime
    last_activity: datetime
    prompt_count: int
    blocked_count: int
    warned_count: int
    allowed_count: int
    platform: Optional[str]
    user_id: Optional[str]
    user_name: Optional[str]
    user_email: Optional[str]


class AdminSessionListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    sessions: List[AdminSessionSummary]
