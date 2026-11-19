import re
import math
from urllib.parse import urlparse
from typing import List, Optional
from app.models.schemas import URLForensics

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".click", ".buzz", ".club", ".work", ".link", ".cc", ".gq"}

TARGET_BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "wellsfargo", "chase"]


class URLAnalyzer:
    @classmethod
    def calculate_entropy(cls, text: str) -> float:
        """Calculate Shannon entropy to detect algorithmically generated domains."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return round(entropy, 2)

    @classmethod
    def analyze_url(cls, raw_url: str) -> URLForensics:
        cleaned_url = raw_url.strip().strip("'\"<>")
        if not cleaned_url.startswith(("http://", "https://")):
            parsed = urlparse(f"http://{cleaned_url}")
        else:
            parsed = urlparse(cleaned_url)

        domain = parsed.netloc.split(":")[0].lower()
        if not domain and parsed.path:
            domain = parsed.path.split("/")[0].lower()

        # 1. Homoglyph / Punycode Detection
        is_punycode = "xn--" in domain
        has_non_ascii = any(ord(c) > 127 for c in domain)
        homoglyph_details = None
        if is_punycode:
            homoglyph_details = "Punycode (xn--) encoded internationalized domain name."
        elif has_non_ascii:
            homoglyph_details = "Contains non-ASCII Unicode characters masquerading as Latin characters."

        # 2. IP address check
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))

        # 3. Suspicious TLD
        suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

        # 4. Domain Entropy
        entropy = cls.calculate_entropy(domain.split(".")[0] if "." in domain else domain)

        # 5. Typosquatting Brand Matching
        typosquat_target = None
        for brand in TARGET_BRANDS:
            # Check for character substitution: paypa1, micros0ft
            sub_check = domain.replace("0", "o").replace("1", "l").replace("rn", "m")
            if brand in sub_check and brand != domain.split(".")[0]:
                typosquat_target = brand.title()
                break

        # Calculate Threat Risk Score (0-100)
        risk = 10.0
        if is_punycode or has_non_ascii:
            risk += 50.0
        if typosquat_target:
            risk += 45.0
        if is_ip:
            risk += 35.0
        if suspicious_tld:
            risk += 25.0
        if entropy > 3.8:
            risk += 20.0

        final_risk = min(round(risk, 1), 100.0)

        return URLForensics(
            url=cleaned_url,
            domain=domain,
            is_punycode_homoglyph=is_punycode or has_non_ascii,
            homoglyph_details=homoglyph_details,
            typosquatting_target=typosquat_target,
            entropy_score=entropy,
            is_ip_address=is_ip,
            suspicious_tld=suspicious_tld,
            risk_score=final_risk
        )

    @classmethod
    def extract_urls_from_text(cls, text: str) -> List[str]:
        """Extract all hyperlinks from text or HTML body."""
        url_pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
        return list(set(re.findall(url_pattern, text)))

