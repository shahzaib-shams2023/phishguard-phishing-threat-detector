import pytest
from app.forensics.url_analyzer import URLAnalyzer


def test_url_homoglyph_and_typosquatting():
    url = "https://paypa1-account-verify.top/auth/login"
    forensics = URLAnalyzer.analyze_url(url)
    assert forensics.domain == "paypa1-account-verify.top"
    assert forensics.typosquatting_target == "Paypal"
    assert forensics.suspicious_tld is True
    assert forensics.risk_score >= 60.0


def test_url_punycode_detection():
    url = "https://xn--pypal-4ve.com/secure"
    forensics = URLAnalyzer.analyze_url(url)
    assert forensics.is_punycode_homoglyph is True
    assert forensics.risk_score >= 50.0


def test_url_legitimate_domain():
    url = "https://dashboard.stripe.com/receipts/acct_123"
    forensics = URLAnalyzer.analyze_url(url)
    assert forensics.domain == "dashboard.stripe.com"
    assert forensics.is_punycode_homoglyph is False
    assert forensics.typosquatting_target is None
    assert forensics.risk_score < 30.0

