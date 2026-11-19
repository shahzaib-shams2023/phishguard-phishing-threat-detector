# PhishGuard: Intelligent Phishing & URL Threat Forensic Engine

PhishGuard is a cybersecurity forensic platform designed to analyze suspicious inbound emails, perform cryptographic header validation (SPF, DKIM, DMARC), detect psychological manipulation tactics, and dissect malicious hyperlinks for Punycode homoglyphs and typosquatting.

---

## 🔍 The Problem
Modern spear-phishing attacks frequently bypass traditional static spam filters:
- **Display Name & Domain Spoofing**: Attackers disguise headers to appear as legitimate executives or vendors while routing traffic through unauthenticated relays.
- **Homoglyph & Punycode Deception**: Attackers register internationalized domain names (IDNs) using Cyrillic or Greek characters visually indistinguishable from Latin characters (e.g. `pаypal.com`).
- **Psychological Social Engineering**: Emails create artificial urgency, threats of account termination, or confidential executive wire requests that manipulate human behavior.

## 💡 The Solution
PhishGuard performs comprehensive multi-vector forensic inspection:
1. **RFC 822 Header Authentication**: Evaluates SPF, DKIM, and DMARC alignment, and flags discrepancies between `From:` and `Return-Path:` domains.
2. **Linguistic Social Engineering Scanner**: Flags artificial time pressure, credential harvesting phrasing, and unauthorized wire transfer requests.
3. **Deep URL Forensics**: Inspects hyperlinks for Punycode (`xn--`), Shannon domain entropy, high-abuse TLDs, and brand typosquatting.
4. **Threat Risk Scoring**: Calculates composite risk (0-100) and categorizes incidents into `PHISHING_CONFIRMED`, `SUSPICIOUS`, or `BENIGN`.
5. **Automated User Warning Banners**: Generates customized user warnings with concrete remediation guidance.

---

## 🏛️ System Architecture

```
Raw Email / Suspicious URL
           │
           ├──────────────────────────────┬──────────────────────────────┐
           ▼                              ▼                              ▼
 [RFC 822 Header Forensics]   [Linguistic Urgency Scanner]     [URL Forensic Analyzer]
  - SPF / DKIM / DMARC         - Artificial deadlines           - Punycode & Homoglyphs
  - Return-Path domain check   - Credential harvesting          - Brand typosquatting
  - Sender spoofing            - Executive impersonation        - Shannon domain entropy
           │                              │                              │
           └──────────────────────────────┼──────────────────────────────┘
                                          │
                                          ▼
                            [Composite Risk Scoring Engine]
                                          │
                                          ▼
                        [Warning Banner & Remediation Guide]
                                          │
                                          ▼
                         Interactive Console & REST API
```

---

## 🛠️ Technology Stack
- **Backend**: Python 3.11, FastAPI, Pydantic v2
- **Forensic Engines**: Email Header Parser, Punycode/IDN Parser, Shannon Entropy
- **Frontend**: Security Operations Dashboard (Tailwind CSS, FontAwesome)
- **Testing**: Pytest, Starlette TestClient
- **Deployment**: Docker, Docker Compose, GitHub Actions CI

---

## 🚀 Getting Started

### Installation
```bash
cd phishguard-phishing-threat-detector

# Create virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### Running the Platform
```bash
python -m uvicorn app.main:app --reload --port 8005
```
Access the Security Console at `http://localhost:8005` or inspect OpenAPI docs at `http://localhost:8005/docs`.

---

## 🧪 Running Automated Tests
```bash
pytest tests/ -v
```

---

## 🐳 Docker Deployment
```bash
docker compose up --build
```
Access the application at `http://localhost:8005`.

---

## 📡 API Reference

### Analyze Email Stream
`POST /api/analyze/email`
```json
{
  "raw_email": "From: \"PayPal Security\" <service@paypal.com>\nReturn-Path: <bounce@attacker.top>\n..."
}
```

Response:
```json
{
  "report_id": "PHISH-89A1B2C3",
  "verdict": "PHISHING_CONFIRMED",
  "overall_threat_score": 92.5,
  "headers": {
    "sender_domain_mismatch": true,
    "spf_status": "FAIL",
    "dkim_status": "FAIL",
    "dmarc_status": "FAIL"
  },
  "linguistics": {
    "urgency_level": "CRITICAL",
    "credential_harvesting_intent": true
  },
  "analyzed_urls": [
    {
      "url": "https://paypa1-account-verify.top/auth/login",
      "typosquatting_target": "Paypal",
      "suspicious_tld": true,
      "risk_score": 85.0
    }
  ],
  "warning_banner": {
    "banner_level": "DANGER",
    "headline": "MALICIOUS PHISHING ATTEMPT DETECTED",
    "remediation_advice": "Do NOT click any links..."
  }
}
```

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

