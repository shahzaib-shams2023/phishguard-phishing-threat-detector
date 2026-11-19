from typing import Dict

PRESET_SCENARIOS: Dict[str, str] = {
    "paypal_credential_harvest": """
From: "PayPal Security Team" <service@paypal.com>
Return-Path: <bounce@attacker-relay.top>
Subject: URGENT: Your PayPal Account Has Been Suspended!
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail

Dear Valued Customer,

We detected unauthorized sign-in attempts on your account. Immediate action required:
Your access will be permanently terminated within 24 hours unless you verify your identity.

Please click the secure link below to confirm your password and billing details:
https://paypa1-account-verify.top/auth/login?token=89412

Thank you,
PayPal Risk Operations
""".strip(),

    "ceo_fraud_wire_transfer": """
From: "Jonathan Vance (CEO)" <ceo@company-enterprise.com>
Return-Path: <jvance.ceo991@freemail-direct.xyz>
Subject: Confidential Acquisition - Urgent Wire Transfer
Authentication-Results: mx.google.com; spf=softfail; dkim=none

Hi Finance Team,

I am currently in an executive board meeting regarding a confidential acquisition.
I urgently need you to execute a wire transfer of $45,000 before 4 PM today.

Please reply immediately once you have verified this email so I can send the overseas routing numbers.
Do not discuss this with anyone on the floor.

Jonathan Vance
Chief Executive Officer
""".strip(),

    "legitimate_stripe_receipt": """
From: "Stripe Billing" <invoices@stripe.com>
Return-Path: <invoices@stripe.com>
Subject: Your receipt from Acme Software ($250.00)
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

Thank you for your payment to Acme Software.
Amount: $250.00 USD
Date: November 15, 2024

View your full receipt and download the PDF at:
https://dashboard.stripe.com/receipts/acct_981294102

Stripe Billing Platform
""".strip()
}

