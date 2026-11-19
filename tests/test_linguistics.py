import pytest
from app.forensics.linguistic_analyzer import LinguisticAnalyzer
from app.data.scenarios import PRESET_SCENARIOS


def test_linguistics_credential_harvest():
    raw = PRESET_SCENARIOS["paypal_credential_harvest"]
    signals = LinguisticAnalyzer.analyze_body(raw)
    assert signals.urgency_level in ("HIGH", "CRITICAL")
    assert signals.credential_harvesting_intent is True
    assert signals.threatens_consequences is True


def test_linguistics_ceo_wire_fraud():
    raw = PRESET_SCENARIOS["ceo_fraud_wire_transfer"]
    signals = LinguisticAnalyzer.analyze_body(raw)
    assert signals.financial_wire_intent is True


def test_linguistics_benign_email():
    raw = PRESET_SCENARIOS["legitimate_stripe_receipt"]
    signals = LinguisticAnalyzer.analyze_body(raw)
    assert signals.urgency_level == "LOW"
    assert signals.credential_harvesting_intent is False
    assert signals.financial_wire_intent is False

