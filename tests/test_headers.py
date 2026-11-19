import pytest
from app.forensics.header_analyzer import HeaderAnalyzer
from app.data.scenarios import PRESET_SCENARIOS


def test_header_spoofing_detected():
    raw = PRESET_SCENARIOS["paypal_credential_harvest"]
    headers = HeaderAnalyzer.analyze_headers(raw)
    assert headers.sender_domain_mismatch is True
    assert headers.spf_status == "FAIL"
    assert headers.dkim_status == "FAIL"
    assert headers.dmarc_status == "FAIL"
    assert headers.suspicious_headers_count >= 3


def test_header_legitimate_pass():
    raw = PRESET_SCENARIOS["legitimate_stripe_receipt"]
    headers = HeaderAnalyzer.analyze_headers(raw)
    assert headers.sender_domain_mismatch is False
    assert headers.spf_status == "PASS"
    assert headers.dkim_status == "PASS"
    assert headers.dmarc_status == "PASS"
    assert headers.suspicious_headers_count == 0

