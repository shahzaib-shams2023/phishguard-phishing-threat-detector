from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime


class HeaderForensics(BaseModel):
    from_address: str
    return_path: Optional[str] = None
    sender_domain_mismatch: bool
    spf_status: str     # PASS, FAIL, SOFTFAIL, NONE
    dkim_status: str    # PASS, FAIL, NONE
    dmarc_status: str   # PASS, FAIL, NONE
    suspicious_headers_count: int


class LinguisticSignals(BaseModel):
    urgency_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    detected_tactics: List[str]
    threatens_consequences: bool
    credential_harvesting_intent: bool
    financial_wire_intent: bool


class URLForensics(BaseModel):
    url: str
    domain: str
    is_punycode_homoglyph: bool
    homoglyph_details: Optional[str] = None
    typosquatting_target: Optional[str] = None
    entropy_score: float
    is_ip_address: bool
    suspicious_tld: bool
    risk_score: float   # 0-100


class WarningBanner(BaseModel):
    banner_level: str   # DANGER, WARNING, SAFE
    headline: str
    remediation_advice: str


class PhishReport(BaseModel):
    report_id: str
    verdict: str        # PHISHING_CONFIRMED, SUSPICIOUS, BENIGN
    overall_threat_score: float  # 0-100
    headers: Optional[HeaderForensics] = None
    linguistics: Optional[LinguisticSignals] = None
    analyzed_urls: List[URLForensics]
    warning_banner: WarningBanner
    technical_summary: str
    analyzed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class EmailAnalysisRequest(BaseModel):
    raw_email: str = Field(..., min_length=20, description="Raw RFC 822 email text including headers and body")


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=5, description="Suspicious URL to analyze")

