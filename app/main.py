from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uuid
import os

from app.config import settings
from app.models.schemas import (
    EmailAnalysisRequest, URLAnalysisRequest, PhishReport,
    WarningBanner, URLForensics
)
from app.forensics.header_analyzer import HeaderAnalyzer
from app.forensics.linguistic_analyzer import LinguisticAnalyzer
from app.forensics.url_analyzer import URLAnalyzer
from app.data.scenarios import PRESET_SCENARIOS

app = FastAPI(
    title=settings.app_name,
    description="PhishGuard Phishing Threat & Malicious URL Forensic Engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def root():
    root_index = os.path.join(os.path.dirname(os.path.dirname(__file__)), "index.html")
    if os.path.exists(root_index):
        return FileResponse(root_index)
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "PhishGuard Threat Intelligence API is active."}


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.app_name,
        "environment": settings.environment
    }


@app.get("/api/scenarios")
async def get_scenarios():
    return PRESET_SCENARIOS


@app.post("/api/analyze/email", response_model=PhishReport)
async def analyze_email_stream(request: EmailAnalysisRequest):
    try:
        report_id = f"PHISH-{str(uuid.uuid4())[:8].upper()}"

        # 1. Header Forensics
        headers = HeaderAnalyzer.analyze_headers(request.raw_email)

        # 2. Linguistic Social Engineering Detection
        linguistics = LinguisticAnalyzer.analyze_body(request.raw_email)

        # 3. URL Extraction & Forensic Analysis
        raw_urls = URLAnalyzer.extract_urls_from_text(request.raw_email)
        analyzed_urls = [URLAnalyzer.analyze_url(u) for u in raw_urls]

        # 4. Composite Risk Scoring (0 to 100)
        risk_score = 5.0
        # Header score component
        if headers.sender_domain_mismatch:
            risk_score += 30.0
        if headers.spf_status == "FAIL":
            risk_score += 25.0
        elif headers.spf_status == "SOFTFAIL":
            risk_score += 15.0
        if headers.dkim_status == "FAIL":
            risk_score += 20.0
        if headers.dmarc_status == "FAIL":
            risk_score += 20.0

        # Linguistic component
        if linguistics.urgency_level == "CRITICAL":
            risk_score += 25.0
        elif linguistics.urgency_level == "HIGH":
            risk_score += 15.0
        if linguistics.credential_harvesting_intent:
            risk_score += 25.0
        if linguistics.financial_wire_intent:
            risk_score += 30.0

        # URL component
        if analyzed_urls:
            max_url_risk = max(u.risk_score for u in analyzed_urls)
            risk_score += (max_url_risk * 0.4)

        overall_threat = round(min(risk_score, 100.0), 1)

        # 5. Verdict and Warning Banner
        if overall_threat >= settings.phish_risk_threshold:
            verdict = "PHISHING_CONFIRMED"
            banner = WarningBanner(
                banner_level="DANGER",
                headline="MALICIOUS PHISHING ATTEMPT DETECTED",
                remediation_advice="Do NOT click any links, open attachments, or input passwords. This email demonstrates domain spoofing and psychological urgency cues."
            )
            summary = (
                f"High-confidence phishing campaign detected (Risk Score: {overall_threat}/100). "
                f"Indicators: SPF/DMARC auth failure, deceptive urgency tactics, and suspicious URL structures."
            )
        elif overall_threat >= 35.0:
            verdict = "SUSPICIOUS"
            banner = WarningBanner(
                banner_level="WARNING",
                headline="CAUTION: SUSPICIOUS SENDER OR CONTENT",
                remediation_advice="Exercise extreme caution before responding or opening links. Verify the sender through a secondary channel."
            )
            summary = f"Moderate risk detected (Risk Score: {overall_threat}/100). Review domain and header discrepancies."
        else:
            verdict = "BENIGN"
            banner = WarningBanner(
                banner_level="SAFE",
                headline="VERIFIED BENIGN SENDER",
                remediation_advice="Email passed cryptographic SPF/DKIM authentication and contains no malicious intent patterns."
            )
            summary = f"Email verified safe (Risk Score: {overall_threat}/100). Clean authentication and legitimate links."

        return PhishReport(
            report_id=report_id,
            verdict=verdict,
            overall_threat_score=overall_threat,
            headers=headers,
            linguistics=linguistics,
            analyzed_urls=analyzed_urls,
            warning_banner=banner,
            technical_summary=summary
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Forensic pipeline error: {str(e)}")


@app.post("/api/analyze/url", response_model=URLForensics)
async def analyze_single_url(request: URLAnalysisRequest):
    return URLAnalyzer.analyze_url(request.url)

