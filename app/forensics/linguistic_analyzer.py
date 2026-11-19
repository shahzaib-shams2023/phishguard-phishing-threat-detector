import re
from typing import List
from app.models.schemas import LinguisticSignals


class LinguisticAnalyzer:
    URGENCY_KEYWORDS = [
        r"\b(?:within\s+\d+\s+hours|immediate\s+action\s+required|urgent|account\s+suspended|act\s+now)\b",
        r"\b(?:final\s+warning|access\s+terminated|security\s+alert|unauthorized\s+activity)\b"
    ]

    CREDENTIAL_KEYWORDS = [
        r"\b(?:verify|confirm|update|reset|re-enter)\s+(?:your\s+)?(?:password|identity|billing|credentials|account)\b",
        r"\b(?:click\s+(?:the\s+)?(?:secure\s+)?link|login\s+to\s+restore|sign\s+in\s+immediately)\b"
    ]

    FINANCIAL_WIRE_KEYWORDS = [
        r"\b(?:wire\s+transfer|confidential\s+acquisition|executive\s+payment|gift\s+cards|urgent\s+invoice\s+payment)\b"
    ]

    @classmethod
    def analyze_body(cls, text: str) -> LinguisticSignals:
        text_lower = text.lower()
        tactics: List[str] = []

        # Check Urgency
        urgency_matches = 0
        for pattern in cls.URGENCY_KEYWORDS:
            matches = re.findall(pattern, text_lower)
            urgency_matches += len(matches)

        if urgency_matches >= 2:
            urgency_level = "CRITICAL"
            tactics.append("High-pressure temporal artificial deadline")
        elif urgency_matches == 1:
            urgency_level = "HIGH"
            tactics.append("Urgency cues")
        else:
            urgency_level = "LOW"

        # Check Credential Harvesting
        cred_harvest = any(re.search(p, text_lower) for p in cls.CREDENTIAL_KEYWORDS)
        if cred_harvest:
            tactics.append("Credential harvesting language")

        # Check Financial Wire
        fin_wire = any(re.search(p, text_lower) for p in cls.FINANCIAL_WIRE_KEYWORDS)
        if fin_wire:
            tactics.append("Executive impersonation / wire payment coercion")

        # Threat of consequences
        threat_consequences = any(
            w in text_lower for w in ["terminated", "suspended", "legal action", "permanently locked", "restricted"]
        )
        if threat_consequences:
            tactics.append("Threat of punitive account disruption")

        return LinguisticSignals(
            urgency_level=urgency_level,
            detected_tactics=tactics,
            threatens_consequences=threat_consequences,
            credential_harvesting_intent=cred_harvest,
            financial_wire_intent=fin_wire
        )
