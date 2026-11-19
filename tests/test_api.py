from fastapi.testclient import TestClient
from app.main import app
from app.data.scenarios import PRESET_SCENARIOS

client = TestClient(app)


def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"


def test_scenarios():
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    assert "paypal_credential_harvest" in res.json()


def test_analyze_email_phish():
    payload = {
        "raw_email": PRESET_SCENARIOS["paypal_credential_harvest"]
    }
    res = client.post("/api/analyze/email", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "PHISHING_CONFIRMED"
    assert data["overall_threat_score"] >= 65.0
    assert data["warning_banner"]["banner_level"] == "DANGER"


def test_analyze_url_endpoint():
    payload = {
        "url": "https://micros0ft-login.top/account"
    }
    res = client.post("/api/analyze/url", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["typosquatting_target"] == "Microsoft"
    assert data["suspicious_tld"] is True

