import re
from typing import Optional
from app.models.schemas import HeaderForensics


class HeaderAnalyzer:
    @classmethod
    def analyze_headers(cls, raw_email: str) -> HeaderForensics:
        # 1. From address
        from_match = re.search(r"^From:\s*(.+)$", raw_email, re.MULTILINE | re.IGNORECASE)
        from_addr = from_match.group(1).strip() if from_match else "unknown@domain.com"

        # 2. Return-Path
        rp_match = re.search(r"^Return-Path:\s*<?([^>\s]+)>?", raw_email, re.MULTILINE | re.IGNORECASE)
        return_path = rp_match.group(1).strip() if rp_match else None

        # 3. Check domain alignment
        from_domain = ""
        rp_domain = ""
        if "@" in from_addr:
            from_domain = from_addr.split("@")[-1].replace(">", "").strip().lower()
        if return_path and "@" in return_path:
            rp_domain = return_path.split("@")[-1].replace(">", "").strip().lower()

        mismatch = bool(from_domain and rp_domain and from_domain != rp_domain)

        # 4. Authentication-Results / Received-SPF
        spf = "NONE"
        if re.search(r"(?:Received-SPF|spf)=pass", raw_email, re.IGNORECASE):
            spf = "PASS"
        elif re.search(r"(?:Received-SPF|spf)=fail", raw_email, re.IGNORECASE):
            spf = "FAIL"
        elif re.search(r"(?:Received-SPF|spf)=softfail", raw_email, re.IGNORECASE):
            spf = "SOFTFAIL"

        dkim = "NONE"
        if re.search(r"dkim=pass", raw_email, re.IGNORECASE):
            dkim = "PASS"
        elif re.search(r"dkim=fail", raw_email, re.IGNORECASE):
            dkim = "FAIL"

        dmarc = "NONE"
        if re.search(r"dmarc=pass", raw_email, re.IGNORECASE):
            dmarc = "PASS"
        elif re.search(r"dmarc=fail", raw_email, re.IGNORECASE):
            dmarc = "FAIL"

        suspicious_count = 0
        if mismatch:
            suspicious_count += 1
        if spf in ("FAIL", "SOFTFAIL"):
            suspicious_count += 1
        if dkim == "FAIL":
            suspicious_count += 1
        if dmarc == "FAIL":
            suspicious_count += 1

        return HeaderForensics(
            from_address=from_addr,
            return_path=return_path,
            sender_domain_mismatch=mismatch,
            spf_status=spf,
            dkim_status=dkim,
            dmarc_status=dmarc,
            suspicious_headers_count=suspicious_count
        )

