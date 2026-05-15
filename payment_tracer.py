#!/usr/bin/env python3
"""
payment_tracer.py  –  Payment processor tracing for suspected fraudulent websites.

Identifies the payment gateway(s) used by a fraudulent site so that:

  1. The payment processor can be notified and the merchant account terminated.
  2. Law enforcement can compel disclosure of the merchant identity (KYC data,
     bank account, legal name, address) via a court order or MLAT request.
  3. Card-scheme fraud programs (Visa VAMP, Mastercard MMP) can flag the MID.

Techniques used
───────────────
  A. Static evidence scan  – parse already-downloaded HTML/JS/headers for:
       • Payment script fingerprints  (Stripe.js, PayPal SDK, Klarna, Adyen …)
       • Publishable / client keys    (pk_live_*, client_id, merchantId …)
       • Payment API endpoints        (/checkout, /payment, /pay …)
       • iframe src / form action     pointing at PSP domains
       • Content-Security-Policy      connect-src / frame-src / form-action

  B. Live checkout probing  – optional live requests to discover:
       • Checkout-flow payment form
       • Redirect targets at payment time
       • X-Frame-Options, CSP, Set-Cookie at payment step

  C. Platform identification  – known PSP relationships for common platforms:
       Shoplazza / AllValue / OEMSaaS / ShopExpress / SHOPLINE / Ueeshop …

  D. Merchant identifier extraction  – Stripe account, PayPal clientId, etc.

  E. Report generation  – ready-to-send abuse reports for each identified PSP
       + a consolidated law-enforcement brief with seizure/subpoena guidance.

Standalone usage:
    python payment_tracer.py <url_or_findings.json>
    python payment_tracer.py https://dkoutlet24.com
    python payment_tracer.py dkoutlet24_com_origin_20260515_0926.json

Called from origin_finder.py:
    from payment_tracer import run_payment_trace
    run_payment_trace(hostname, all_findings, out_dir)
"""

import sys
import os
import re
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as e:
    sys.exit(
        f"[!] Missing dependency: {e}\n"
        "    Run: pip install requests beautifulsoup4"
    )

# ── Configuration ─────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "da-DK,da;q=0.9,en;q=0.8",
}
TIMEOUT = 15

# ── Payment gateway signature database ────────────────────────────────────────
#
# Each entry describes one Payment Service Provider (PSP).
# Fields:
#   script_patterns   – regex patterns that appear in <script src="...">
#   js_patterns       – regex patterns found anywhere in JavaScript source
#   domain_patterns   – domains seen in CSP / form action / XHR / redirect
#   key_patterns      – regex that captures a useful identifier (group 1 = value)
#   complaint_url     – where to report a fraudulent merchant
#   abuse_email       – abuse contact e-mail
#   le_guidance       – law-enforcement subpoena / MLAT note
#   description       – human-readable name
#
PAYMENT_SIGNATURES = {
    "stripe": {
        "description": "Stripe",
        "script_patterns": [
            r"js\.stripe\.com/v\d",
            r"stripe\.js",
        ],
        "js_patterns": [
            r"Stripe\s*\(\s*['\"]pk_",
            r"stripe\.elements\(",
            r"stripe\.confirmCardPayment\(",
            r"stripe\.redirectToCheckout\(",
            r"loadStripe\(",
        ],
        "domain_patterns": [
            r"stripe\.com",
            r"api\.stripe\.com",
            r"js\.stripe\.com",
            r"hooks\.stripe\.com",
        ],
        "key_patterns": [
            # Stripe publishable key  →  reveals the CONNECTED ACCOUNT
            (r"Stripe\s*\(\s*['\"](?P<key>pk_(?:live|test)_[A-Za-z0-9]{20,})['\"]",
             "stripe_publishable_key"),
            (r"['\"](?P<key>pk_(?:live|test)_[A-Za-z0-9]{20,})['\"]",
             "stripe_publishable_key"),
        ],
        "complaint_url":  "https://support.stripe.com/contact/email?topic=fraud",
        "abuse_email":    "fraud@stripe.com",
        "le_guidance": (
            "Stripe complies with law-enforcement requests under 18 U.S.C. § 2703 "
            "(ECPA) and the EU-US Data Privacy Framework. A publishable key (pk_live_*) "
            "uniquely identifies the Stripe account. Danish police (NC3) can obtain "
            "account holder name, bank details, and transaction history by sending a "
            "preservation request to stripe.com/government-requests and following up "
            "with a court order or MLAT (US treaty with Denmark)."
        ),
    },
    "paypal": {
        "description": "PayPal",
        "script_patterns": [
            r"paypal\.com/sdk/js",
            r"paypalobjects\.com",
            r"paypal-checkout",
        ],
        "js_patterns": [
            r"paypal\.Buttons\(",
            r"paypal\.FUNDING\.",
            r"paypal_client_id",
            r"PAYPAL_CLIENT_ID",
        ],
        "domain_patterns": [
            r"paypal\.com",
            r"paypalobjects\.com",
            r"api-m\.paypal\.com",
        ],
        "key_patterns": [
            (r"client-id=([A-Za-z0-9_\-]{10,})", "paypal_client_id"),
            (r"['\"]paypal_client_id['\"]\s*:\s*['\"]([A-Za-z0-9_\-]{10,})['\"]",
             "paypal_client_id"),
        ],
        "complaint_url":  "https://www.paypal.com/us/smarthelp/article/how-do-i-report-potential-fraud-unauthorized-transactions-or-other-concerns-faq1422",
        "abuse_email":    "spoof@paypal.com",
        "le_guidance": (
            "PayPal responds to law-enforcement requests via its dedicated portal at "
            "https://www.paypal.com/us/webapps/mpp/security/report-a-concern. The "
            "PayPal client-id uniquely identifies the merchant app. Danish NC3 can "
            "submit requests under MLAT (US–Denmark treaty) to obtain the account "
            "holder's legal name, verified bank account, and transaction history."
        ),
    },
    "klarna": {
        "description": "Klarna",
        "script_patterns": [
            r"klarna\.com/",
            r"x\.klarnacdn\.net",
        ],
        "js_patterns": [
            r"Klarna\.init\(",
            r"klarna\.load\(",
            r"KlarnaCheckout",
        ],
        "domain_patterns": [
            r"klarna\.com",
            r"klarnacdn\.net",
            r"checkout\.klarna\.com",
        ],
        "key_patterns": [
            (r"['\"]client_id['\"]:\s*['\"]([a-f0-9\-]{30,})['\"]",
             "klarna_client_id"),
            (r"Klarna\.init\(\{[^}]*client_id:\s*['\"]([^'\"]+)['\"]",
             "klarna_client_id"),
        ],
        "complaint_url":  "https://www.klarna.com/uk/customer-service/report-fraud/",
        "abuse_email":    "fraud@klarna.com",
        "le_guidance": (
            "Klarna is a licensed Swedish payment institution (FI registration SE556737-0431). "
            "Danish NC3 can obtain merchant KYC data via a Nordic MLA (Mutual Legal Assistance) "
            "request directly between Danish and Swedish police (no MLAT needed) or through "
            "Europol. Include the Klarna client_id and the fraudulent site URL."
        ),
    },
    "adyen": {
        "description": "Adyen",
        "script_patterns": [
            r"adyen\.com/",
            r"checkoutshopper",
        ],
        "js_patterns": [
            r"AdyenCheckout\(",
            r"adyen\.encrypt",
            r"\"environment\":\s*\"live\"",
        ],
        "domain_patterns": [
            r"adyen\.com",
            r"checkoutshopper-live\.adyen\.com",
        ],
        "key_patterns": [
            (r"['\"]clientKey['\"]:\s*['\"]([^'\"]{10,})['\"]",
             "adyen_client_key"),
            (r"['\"]originKey['\"]:\s*['\"]([^'\"]{10,})['\"]",
             "adyen_origin_key"),
            (r"['\"]merchantAccount['\"]:\s*['\"]([^'\"]{5,})['\"]",
             "adyen_merchant_account"),
        ],
        "complaint_url":  "https://www.adyen.com/our-story/contact",
        "abuse_email":    "security@adyen.com",
        "le_guidance": (
            "Adyen NV is regulated by De Nederlandsche Bank (DNB) in the Netherlands. "
            "Danish NC3 can contact Dutch police (Politie, Team High Tech Crime) who have "
            "jurisdiction over Adyen. Include merchantAccount identifier. "
            "Adyen complies with court orders from EU member states."
        ),
    },
    "nets_easy": {
        "description": "Nets Easy (Nexi Group)",
        "script_patterns": [
            r"checkout\.dibspayment\.com",
            r"checkout\.nets\.eu",
            r"test\.checkout\.dibspayment\.com",
        ],
        "js_patterns": [
            r"Dibs\s*\(",
            r"NetsCheckout\(",
            r"easy\.nets\.eu",
            r"nets\.easy",
        ],
        "domain_patterns": [
            r"checkout\.nets\.eu",
            r"dibspayment\.com",
            r"api\.dibspayment\.eu",
        ],
        "key_patterns": [
            (r"checkoutKey\s*[:=]\s*['\"]([^'\"]{20,})['\"]",
             "nets_checkout_key"),
            (r"['\"]checkoutKey['\"]:\s*['\"]([^'\"]{20,})['\"]",
             "nets_checkout_key"),
        ],
        "complaint_url":  "https://www.nets.eu/contact/Pages/default.aspx",
        "abuse_email":    "fraud@nets.eu",
        "le_guidance": (
            "Nets A/S is a Danish payment institution (CVR 20016175) licensed by "
            "Finanstilsynet. NC3 can compel disclosure of the merchant's KYC data "
            "directly under the Danish Payments Act (§ 126) without an MLAT. "
            "Include the checkoutKey value and the fraudulent domain."
        ),
    },
    "mobilepay": {
        "description": "MobilePay (Vipps MobilePay)",
        "script_patterns": [
            r"mobilepay\.dk",
            r"mobilepay\.fi",
            r"vippsmobilepay\.com",
        ],
        "js_patterns": [
            r"MobilePay\.",
            r"mobilepay_merchant",
            r"vippsMobilePay",
        ],
        "domain_patterns": [
            r"mobilepay\.dk",
            r"api\.mobilepay\.dk",
            r"vippsmobilepay\.com",
        ],
        "key_patterns": [
            (r"merchant_id\s*[=:]\s*['\"]([^'\"]{5,})['\"]",
             "mobilepay_merchant_id"),
        ],
        "complaint_url":  "https://developer.mobilepay.dk/docs/report-fraud",
        "abuse_email":    "kontakt@mobilepay.dk",
        "le_guidance": (
            "MobilePay is operated by Vipps MobilePay AS (Norway/Denmark). The Danish "
            "Financial Supervisory Authority (Finanstilsynet) can compel disclosure. "
            "NC3 can contact MobilePay directly via their law-enforcement guide at "
            "https://developer.mobilepay.dk/faq/le"
        ),
    },
    "2checkout_verifone": {
        "description": "2Checkout / Verifone",
        "script_patterns": [
            r"2checkout\.com",
            r"2co\.com",
        ],
        "js_patterns": [
            r"TCO\.requestToken\(",
            r"2checkout",
            r"convertplus",
        ],
        "domain_patterns": [
            r"2checkout\.com",
            r"2co\.com",
            r"secure\.2checkout\.com",
        ],
        "key_patterns": [
            (r"['\"]merchant['\"]:\s*['\"]([^'\"]{3,})['\"]",
             "2co_merchant_code"),
            (r"TCO\.requestToken\([^)]*,\s*['\"]([^'\"]+)['\"]",
             "2co_merchant_code"),
        ],
        "complaint_url":  "https://www.verifone.com/en/us/legal/report-fraud",
        "abuse_email":    "abuse@2checkout.com",
        "le_guidance": (
            "2Checkout (Verifone) is a US company registered in Ohio. NC3 can reach "
            "the merchant KYC data via an MLAT (US–Denmark) request. Include the "
            "2Checkout merchant code (seller ID) found in the page source."
        ),
    },
    "worldpay": {
        "description": "Worldpay / FIS",
        "script_patterns": [
            r"worldpay\.com",
            r"wp3ds\.com",
        ],
        "js_patterns": [
            r"Worldpay\.",
            r"WP3DS",
        ],
        "domain_patterns": [
            r"worldpay\.com",
            r"payments\.worldpay\.com",
            r"access\.worldpay\.com",
        ],
        "key_patterns": [
            (r"['\"]clientKey['\"]:\s*['\"]([^'\"]{10,})['\"]",
             "worldpay_client_key"),
        ],
        "complaint_url":  "https://www.worldpay.com/en/fraudreport",
        "abuse_email":    "fraud@worldpay.com",
        "le_guidance": (
            "Worldpay is a UK-licensed payment institution. NC3 can request merchant "
            "KYC data via a European Investigation Order (EIO) to UK authorities."
        ),
    },
    "checkout_com": {
        "description": "Checkout.com",
        "script_patterns": [
            r"checkout\.com/",
            r"cdn\.checkout\.com",
        ],
        "js_patterns": [
            r"Checkout\.configure\(",
            r"CheckoutWebComponents\(",
            r"frames\.init\(",
        ],
        "domain_patterns": [
            r"checkout\.com",
            r"cdn\.checkout\.com",
            r"api\.checkout\.com",
        ],
        "key_patterns": [
            (r"['\"]publicKey['\"]:\s*['\"]([^'\"]{10,})['\"]",
             "checkout_public_key"),
            (r"pk_[a-z]+_[A-Za-z0-9]{10,}",
             "checkout_public_key"),
        ],
        "complaint_url":  "https://www.checkout.com/docs/risk",
        "abuse_email":    "abuse@checkout.com",
        "le_guidance": (
            "Checkout.com is a UK FCA-licensed payment institution. NC3 can use a "
            "European Investigation Order (EIO) to UK NCA/FCA. Merchant public keys "
            "are unique to each account."
        ),
    },
    "payoneer": {
        "description": "Payoneer",
        "script_patterns": [r"payoneer\.com"],
        "js_patterns":     [r"payoneer"],
        "domain_patterns": [r"payoneer\.com"],
        "key_patterns":    [],
        "complaint_url":   "https://www.payoneer.com/about/contact/",
        "abuse_email":     "abuse@payoneer.com",
        "le_guidance": (
            "Payoneer Inc. is a US company. NC3 can reach merchant identity data via "
            "an MLAT (US–Denmark)."
        ),
    },
    "alipay": {
        "description": "Alipay (Ant Group)",
        "script_patterns": [r"alipay\.com", r"alipayplus\.com"],
        "js_patterns":     [r"AlipayCheckout\(", r"alipay\.trade"],
        "domain_patterns": [r"alipay\.com", r"alipayplus\.com", r"intl\.alipay\.com"],
        "key_patterns": [
            (r"app_id\s*=\s*['\"]([^'\"]{5,})['\"]", "alipay_app_id"),
        ],
        "complaint_url":   "https://intl.alipay.com/channel/report.htm",
        "abuse_email":     "antifraud@support.alipay.com",
        "le_guidance": (
            "Alipay is operated by Ant International (Singapore entity). NC3 can "
            "contact Interpol or Europol to reach Chinese MLPS-registered entities. "
            "Include the app_id found in the page source."
        ),
    },
    "wechat_pay": {
        "description": "WeChat Pay (Tencent)",
        "script_patterns": [r"wechatpay\.com", r"pay\.weixin\.qq\.com"],
        "js_patterns":     [r"WechatPay\(", r"wx\.config\(", r"wx\.chooseWXPay\("],
        "domain_patterns": [r"wechatpay\.com", r"api\.mch\.weixin\.qq\.com"],
        "key_patterns": [
            (r"appId\s*:\s*['\"]([^'\"]{6,})['\"]", "wechat_appid"),
            (r"mch_id\s*[=:]\s*['\"]([^'\"]{5,})['\"]", "wechat_mch_id"),
        ],
        "complaint_url":   "https://www.wechat.com/en/contact.html",
        "abuse_email":     "wechat_fraud@tencent.com",
        "le_guidance": (
            "WeChat Pay is operated by Tencent (China). Law enforcement requests "
            "require coordination through Interpol or Europol China desk. "
            "Include appId and mch_id."
        ),
    },
    "shoplazza_psp": {
        "description": "Shoplazza / AllValue built-in PSP",
        "script_patterns": [
            r"shoplazza\.com",
            r"allvalue\.com",
            r"ueeshop\.com",
            r"shoplineapp\.com",
        ],
        "js_patterns": [
            r"_AIBGBDC_",          # Shoplazza/OEMSaaS platform fingerprint
            r"oemsaas",
            r"C_SETTINGS\[",
            r"_GET_C_SETTING_\(",
            r"omesaasProduct",
            r"omesaasSearch",
            r"\"app-api/",
            r"/app-assets/",
        ],
        "domain_patterns": [
            r"shoplazza\.com",
            r"allvalue\.com",
            r"ueeshop\.com",
            r"shoplineapp\.com",
        ],
        "key_patterns": [
            (r"C_SETTINGS\[['\"]store_id['\"]\]\s*=\s*['\"]?([^'\";\s]+)",
             "platform_store_id"),
            (r"['\"]store_id['\"]\s*:\s*['\"]?([^'\";\s,}]+)",
             "platform_store_id"),
            (r"window\._dkoutlet24com_\s*=\s*['\"]([^'\"]+)['\"]",
             "platform_instance_key"),
        ],
        "complaint_url":  "https://help.shoplazza.com/",
        "abuse_email":    "abuse@shoplazza.com",
        "le_guidance": (
            "Shoplazza (深圳晴景科技) and its white-label variants (AllValue, OEMSaaS, "
            "Ueeshop) are Chinese SaaS e-commerce platforms. The platform manages "
            "payment processing on behalf of merchants. Payment acquirers are typically "
            "Stripe (international cards) or local Chinese processors.\n"
            "\n"
            "Identity disclosure path:\n"
            "  1. Identify the acquirer (Stripe/PayPal) from JS keys (see above).\n"
            "  2. Report to the acquirer with the fraudulent domain and any keys found.\n"
            "  3. NC3 can issue an MLAT request to the US (for Stripe/PayPal) to obtain\n"
            "     the merchant's legal name, bank account, and KYC documents.\n"
            "  4. Additionally, submit to Shoplazza abuse (abuse@shoplazza.com) — they\n"
            "     hold merchant registration data including Chinese national ID or company\n"
            "     registration number.\n"
            "  5. File a complaint with the Chinese CISA (国家互联网应急中心) at\n"
            "     https://www.cert.org.cn/ — effective for Chinese-hosted operators."
        ),
    },
}

# ── Known checkout URL patterns per platform ──────────────────────────────────

CHECKOUT_PATHS = [
    "/checkout",
    "/cart/checkout",
    "/payment",
    "/pay",
    "/order/payment",
    "/order/checkout",
    "/payment_method",
    "/orders/payment",
]

# ── CSP directives that reveal payment origins ─────────────────────────────────

CSP_PAYMENT_DIRECTIVES = [
    "connect-src",
    "frame-src",
    "script-src",
    "form-action",
    "frame-ancestors",
]

# ── Platform fingerprints ──────────────────────────────────────────────────────

PLATFORM_FINGERPRINTS = {
    "Shoplazza / AllValue / OEMSaaS": [
        r"_AIBGBDC_",
        r"oemsaas",
        r"omesaasProduct",
        r"_GET_C_SETTING_\(",
        r"app-api/.*?/\d+",
        r"app-assets/",
    ],
    "Shopify": [
        r"cdn\.shopify\.com",
        r"shopify\.com/s/files",
        r"Shopify\.theme",
        r"window\.Shopify",
    ],
    "WooCommerce / WordPress": [
        r"wp-content/plugins",
        r"wp-includes/",
        r"woocommerce",
    ],
    "Magento": [
        r"cdn\.magento\.com",
        r"Magento_Checkout",
        r"mage/cookies",
    ],
    "SHOPLINE": [
        r"shoplineapp\.com",
        r"cdn\.myshopline\.com",
    ],
    "Ueeshop": [
        r"ueeshop\.com",
    ],
    "Shein / Romwe style": [
        r"shein\.com",
        r"sheincorp",
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
# Core analysis functions
# ══════════════════════════════════════════════════════════════════════════════

def scan_text(text: str) -> dict:
    """
    Scan a block of text for payment gateway signatures.
    Returns dict: { psp_key → { matched_patterns, extracted_keys } }
    """
    results = {}
    for psp_key, psp in PAYMENT_SIGNATURES.items():
        hit = {"matched_patterns": [], "extracted_identifiers": {}}

        all_patterns = (
            [(p, "script")  for p in psp.get("script_patterns", [])] +
            [(p, "js")      for p in psp.get("js_patterns", [])] +
            [(p, "domain")  for p in psp.get("domain_patterns", [])]
        )
        for pattern, kind in all_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                hit["matched_patterns"].append(f"[{kind}] {pattern}")

        for regex, label in psp.get("key_patterns", []):
            m = re.search(regex, text, re.IGNORECASE)
            if m:
                value = m.group(1) if m.lastindex else m.group(0)
                hit["extracted_identifiers"][label] = value

        if hit["matched_patterns"] or hit["extracted_identifiers"]:
            results[psp_key] = hit

    return results


def parse_csp(csp_header: str) -> dict:
    """
    Parse a Content-Security-Policy header, returning directives relevant to payments.
    """
    findings = {}
    if not csp_header:
        return findings
    for directive in csp_header.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        if not parts:
            continue
        name = parts[0].lower()
        if name in CSP_PAYMENT_DIRECTIVES:
            findings[name] = parts[1:]
    return findings


def identify_platform(all_text: str) -> list[str]:
    """Identify which e-commerce platform the site is built on."""
    detected = []
    for name, patterns in PLATFORM_FINGERPRINTS.items():
        hits = [p for p in patterns if re.search(p, all_text, re.IGNORECASE)]
        if hits:
            detected.append({"platform": name, "matched_patterns": hits})
    return detected


def scan_evidence_directory(evidence_dir: Path) -> dict:
    """
    Scan an already-collected evidence directory (from evidence_collector.py).
    Returns aggregated payment findings across all files.
    """
    print(f"[*] Scanning evidence directory: {evidence_dir}")
    aggregated_psp_hits = {}        # psp_key → merged hit
    csp_findings        = {}        # url → parsed CSP
    platform_findings   = []
    all_text_combined   = []

    # Walk all collected files
    for fpath in evidence_dir.rglob("*"):
        if not fpath.is_file():
            continue
        suffix = fpath.suffix.lower()
        if suffix not in {".html", ".htm", ".js", ".txt", ".json", ".css"}:
            continue

        try:
            text = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        all_text_combined.append(text)

        # Scan for PSP signatures
        hits = scan_text(text)
        for psp_key, hit in hits.items():
            if psp_key not in aggregated_psp_hits:
                aggregated_psp_hits[psp_key] = {
                    "description":  PAYMENT_SIGNATURES[psp_key]["description"],
                    "sources":      [],
                    "matched_patterns":      [],
                    "extracted_identifiers": {},
                }
            entry = aggregated_psp_hits[psp_key]
            rel   = str(fpath.relative_to(evidence_dir))
            if rel not in entry["sources"]:
                entry["sources"].append(rel)
            for p in hit["matched_patterns"]:
                if p not in entry["matched_patterns"]:
                    entry["matched_patterns"].append(p)
            entry["extracted_identifiers"].update(hit["extracted_identifiers"])

        # Parse CSP from header files
        if suffix == ".txt" and "headers" in str(fpath):
            for line in text.splitlines():
                if "content-security-policy" in line.lower():
                    url_line = ""
                    for l in text.splitlines():
                        if l.startswith("FINAL URL:") or l.startswith("REQUEST:"):
                            url_line = l.split(":", 1)[-1].strip().split()[-1]
                    csp_val = line.split(":", 1)[-1].strip() if ":" in line else line
                    csp_findings[url_line or str(fpath)] = parse_csp(csp_val)

    # Platform identification
    combined_text = "\n".join(all_text_combined)
    platform_findings = identify_platform(combined_text)

    print(f"    Found {len(aggregated_psp_hits)} PSP signature(s)")
    print(f"    Platform candidates: {[p['platform'] for p in platform_findings]}")

    return {
        "psp_hits":        aggregated_psp_hits,
        "csp_findings":    csp_findings,
        "platform":        platform_findings,
    }


def probe_live_checkout(base_url: str) -> dict:
    """
    Make live HTTP requests to checkout/payment pages and look for
    payment gateway signatures in live responses.
    """
    print(f"[*] Probing live checkout pages at {base_url} …")
    results = {
        "probed_urls":  [],
        "psp_hits":     {},
        "redirects":    [],
        "csp":          {},
        "raw_findings": [],
    }

    session = requests.Session()
    session.headers.update(HEADERS)

    for path in CHECKOUT_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            final_url = resp.url
            results["probed_urls"].append({
                "url":        url,
                "final_url":  final_url,
                "status":     resp.status_code,
            })

            if resp.url != url:
                results["redirects"].append({"from": url, "to": resp.url})

            # CSP
            csp = resp.headers.get("Content-Security-Policy", "")
            if csp:
                results["csp"][final_url] = parse_csp(csp)

            # Payment signatures
            hits = scan_text(resp.text)
            for psp_key, hit in hits.items():
                if psp_key not in results["psp_hits"]:
                    psp = PAYMENT_SIGNATURES[psp_key]
                    results["psp_hits"][psp_key] = {
                        "description":          psp["description"],
                        "sources":              [],
                        "matched_patterns":     [],
                        "extracted_identifiers": {},
                    }
                entry = results["psp_hits"][psp_key]
                if url not in entry["sources"]:
                    entry["sources"].append(url)
                for p in hit["matched_patterns"]:
                    if p not in entry["matched_patterns"]:
                        entry["matched_patterns"].append(p)
                entry["extracted_identifiers"].update(hit["extracted_identifiers"])

        except requests.exceptions.SSLError:
            results["raw_findings"].append(f"SSL error at {url}")
        except requests.exceptions.ConnectionError:
            results["raw_findings"].append(f"Connection refused at {url}")
        except Exception as ex:
            results["raw_findings"].append(f"Error at {url}: {ex}")

    return results


def merge_psp_hits(*hit_dicts) -> dict:
    """Merge PSP hit dicts from multiple sources."""
    merged = {}
    for d in hit_dicts:
        for psp_key, hit in d.items():
            if psp_key not in merged:
                merged[psp_key] = {
                    "description":           hit.get("description", psp_key),
                    "sources":               [],
                    "matched_patterns":      [],
                    "extracted_identifiers": {},
                }
            m = merged[psp_key]
            for s in hit.get("sources", []):
                if s not in m["sources"]:
                    m["sources"].append(s)
            for p in hit.get("matched_patterns", []):
                if p not in m["matched_patterns"]:
                    m["matched_patterns"].append(p)
            m["extracted_identifiers"].update(hit.get("extracted_identifiers", {}))
    return merged


# ══════════════════════════════════════════════════════════════════════════════
# Report generation
# ══════════════════════════════════════════════════════════════════════════════

def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def generate_psp_complaint(hostname: str, psp_key: str, hit: dict) -> str:
    """
    Generate a ready-to-submit abuse complaint for a single PSP.
    """
    psp = PAYMENT_SIGNATURES.get(psp_key, {})
    name = psp.get("description", psp_key)
    email = psp.get("abuse_email", "N/A")
    url   = psp.get("complaint_url", "N/A")
    ids   = hit.get("extracted_identifiers", {})

    id_section = ""
    if ids:
        id_section = "\n".join(
            f"  {label}: {value}" for label, value in ids.items()
        )
    else:
        id_section = "  (No unique identifier extracted – see HTML evidence attached)"

    patterns = "\n".join(f"  • {p}" for p in hit.get("matched_patterns", []))
    sources  = "\n".join(f"  • {s}" for s in hit.get("sources", [])[:5])

    return f"""
{'='*72}
PAYMENT PROCESSOR ABUSE REPORT – {name.upper()}
{'='*72}
Report generated : {_now_str()}
Fraudulent domain : https://{hostname}
Target audience   : Danish consumers / EU market
Payment processor : {name}
Report submitted to : {email}
Online form       : {url}

── NATURE OF THE COMPLAINT ──────────────────────────────────────────────────
The website https://{hostname} is a fraudulent e-commerce store that:
  • Sells counterfeit / non-existent goods to Danish consumers
  • Has no legal company registration (no CVR-number, no physical address)
  • Collects credit card payments via {name} under a fraudulent merchant identity
  • Violates EU DSA (Digital Services Act) and Danish E-handelsloven §§ 7-13

── PAYMENT PROCESSOR EVIDENCE ───────────────────────────────────────────────
{name} scripts / API calls were detected in the site source code.
Technical matches found:
{patterns if patterns else '  (platform fingerprint match – see sources)'}

Evidence files:
{sources}

── MERCHANT IDENTIFIERS (extracted from site source) ────────────────────────
{id_section}

── REQUESTED ACTION ─────────────────────────────────────────────────────────
1. IMMEDIATELY suspend the above merchant account to stop ongoing fraud.
2. Preserve ALL transaction records, KYC documents, bank account details,
   and IP login logs associated with this merchant account.
3. Provide these records to Danish Police (NC3) and/or EU law enforcement
   upon receipt of a valid legal process (court order / MLAT request).

── EVIDENCE ATTACHED ────────────────────────────────────────────────────────
  • Full HTML/header evidence archive (collected {_now_str()})
  • DNS / WHOIS records
  • AI-assisted fraud analysis report
  • Danish legal analysis (E-handelsloven, Markedsføringsloven, GDPR)

── CONTACT FOR LAW ENFORCEMENT FOLLOW-UP ────────────────────────────────────
  Danish Police Cybercrime Center (NC3):  nc3@politi.dk
  MLAT / Mutual Legal Assistance Treaty:  justitsministeriet@jm.dk
{'='*72}
""".strip()


def generate_law_enforcement_brief(
    hostname: str,
    all_psp_hits: dict,
    platform_findings: list,
    existing_findings: dict | None = None,
) -> str:
    """
    Generate a consolidated law-enforcement brief with:
    - Identified payment processors and merchant keys
    - Subpoena / MLAT guidance per PSP
    - Card-scheme fraud program contacts
    - Step-by-step identification strategy
    """
    ts = _now_str()
    platform_names = ", ".join(
        p["platform"] for p in platform_findings
    ) if platform_findings else "Unknown"

    psp_sections = []
    for psp_key, hit in all_psp_hits.items():
        psp    = PAYMENT_SIGNATURES.get(psp_key, {})
        name   = psp.get("description", psp_key)
        ids    = hit.get("extracted_identifiers", {})
        le_note = psp.get("le_guidance", "No specific guidance available.")

        id_lines = "\n    ".join(
            f"{label}: {value}" for label, value in ids.items()
        ) if ids else "(no unique key extracted)"

        psp_sections.append(f"""
  ┌─ {name} ────────────────────────────────────────────────────────────
  │  Abuse email : {psp.get('abuse_email','N/A')}
  │  Report URL  : {psp.get('complaint_url','N/A')}
  │  Identifiers : {id_lines}
  │
  │  Law-enforcement guidance:
  │  {le_note.replace(chr(10), chr(10)+'  │  ')}
  └────────────────────────────────────────────────────────────────────""")

    psp_block = "\n".join(psp_sections) if psp_sections else "  (No payment processors identified yet)"

    # Additional identifiers from existing analysis
    extra_info = ""
    if existing_findings:
        _target = existing_findings.get("target", {})
        # target may be a plain string hostname (older JSON format)
        if isinstance(_target, str):
            _target = {"hostname": _target}
        ip     = existing_findings.get("ip_whois", {})
        if not isinstance(ip, dict):
            ip = {}
        whois  = existing_findings.get("whois", {})
        if not isinstance(whois, dict):
            whois = {}
        extra_info = f"""
── EXISTING RECONNAISSANCE DATA ─────────────────────────────────────────────
  Domain        : {_target.get('hostname', hostname)}
  Registrar     : {whois.get('registrar', 'Unknown')}
  Reg. date     : {whois.get('creation_date', 'Unknown')}
  IP            : {_target.get('ip', 'Unknown')}
  ASN           : {ip.get('asn', 'Unknown')} ({ip.get('asn_description', '')})
  Country       : {ip.get('country', 'Unknown')}
  CDN           : {existing_findings.get('tech', {}).get('detected', ['Unknown'])[0] if existing_findings.get('tech', {}).get('detected') else 'Unknown'}
"""

    return f"""
{'='*72}
LAW-ENFORCEMENT BRIEF: PAYMENT PROCESSOR IDENTIFICATION
Fraudulent website: https://{hostname}
Prepared: {ts}
{'='*72}

── EXECUTIVE SUMMARY ────────────────────────────────────────────────────────
The website https://{hostname} is a fraudulent e-commerce store targeting
Danish consumers. This brief documents the payment processors identified
in the site's source code, the technical identifiers that can be used to
compel disclosure of the operator's true identity, and the legal pathways
available to Danish law enforcement.

── IDENTIFIED PLATFORM ──────────────────────────────────────────────────────
  E-commerce platform: {platform_names}

  Note: Chinese SaaS platforms (Shoplazza, AllValue, OEMSaaS) white-label
  their services and typically use Stripe or PayPal for international card
  processing. The platform itself also holds merchant KYC data (national ID
  or Chinese business registration number).
{extra_info}
── IDENTIFIED PAYMENT PROCESSORS ────────────────────────────────────────────
{psp_block}

── CARD-SCHEME FRAUD PROGRAMS ───────────────────────────────────────────────
  Visa Merchant Monitoring Program (VAMP):
    Contact : risk@visa.com / https://www.visa.com/splisting/searchGrsp.do
    Action  : If the acquirer (e.g. Stripe) is identified, Visa can flag the
              Merchant ID (MID) in their global fraud database and compel the
              acquirer to terminate the account.

  Mastercard Merchant Monitoring Program (MMP):
    Contact : fraudreporting@mastercard.com
    Action  : Same as above for Mastercard transactions.

  Note: Cardholders who have been charged can dispute transactions with their
  issuing bank. The acquirer is then required to disclose the merchant details
  to the card scheme during the chargeback process.

── STEP-BY-STEP IDENTITY TRACING STRATEGY ───────────────────────────────────
  Step 1 – Confirm payment processor (done: see above).
  Step 2 – Send preservation request to the PSP (abuse contact above).
            Request: transaction logs, merchant KYC, IP login history.
  Step 3 – Issue MLAT or EIO (depending on PSP jurisdiction):
            • Stripe / PayPal (US) → MLAT via Justitsministeriet
            • Klarna (Sweden)      → Direct Nordic MLA to Swedish police
            • Adyen (Netherlands)  → EIO to Dutch Politie / DNB
            • Checkout.com (UK)    → EIO to UK NCA
  Step 4 – Platform subpoena (Shoplazza/AllValue if detected):
            Contact: abuse@shoplazza.com + MLAT to China via Interpol.
            The platform holds: merchant email, phone, national ID/passport
            copy, business license, bank account, IP registration history.
  Step 5 – Cloudflare subpoena (if CDN-protected):
            Cloudflare stores the ORIGIN IP of the web server.
            Reference: https://www.cloudflare.com/subpoena-policy/
            Submit via: https://www.cloudflare.com/legal/subpoena-policy/
  Step 6 – Domain registrar subpoena (WHOIS privacy removal):
            ICANN RAA § 3.7.7 requires registrars to disclose registrant
            data to law enforcement. NC3 should contact the registrar's
            abuse department identified in the WHOIS record.
  Step 7 – If Chinese operator confirmed:
            File with Chinese CISA (国家互联网应急中心): https://www.cert.org.cn/
            Europol EC3 has a China liaison channel for cross-border fraud.

── RELEVANT DANISH LAW ──────────────────────────────────────────────────────
  • E-handelsloven § 13             – mandatory business identification
  • Markedsføringsloven § 5         – misleading commercial practices
  • Straffeloven §§ 279-283         – fraud (bedrageri) and theft
  • Betalingsloven § 126            – PSP disclosure to authorities
  • GDPR Art. 6 / Databeskyttelsesloven – data preservation basis

── SUBMITTING EVIDENCE TO NC3 ───────────────────────────────────────────────
  Online report : https://politi.dk/nc3/anmeld-it-kriminalitet
  E-mail        : nc3@politi.dk
  Reference     : Attach this brief + the full evidence archive

{'='*72}
""".strip()


# ══════════════════════════════════════════════════════════════════════════════
# Main orchestrator
# ══════════════════════════════════════════════════════════════════════════════

def run_payment_trace(
    hostname: str,
    existing_findings: dict | None = None,
    out_dir: str | Path | None     = None,
    evidence_dir: str | Path | None = None,
    do_live_probe: bool             = True,
) -> dict:
    """
    Full payment tracing pipeline.

    Parameters
    ----------
    hostname         : e.g. "dkoutlet24.com"
    existing_findings: dict from origin_finder.py (optional)
    out_dir          : where to save reports (default: <hostname>_payment_trace/)
    evidence_dir     : path to already-collected evidence (optional)
    do_live_probe    : whether to probe live checkout pages (default True)

    Returns
    -------
    dict with all findings, suitable for inclusion in the main findings JSON.
    """
    hostname = hostname.replace("https://", "").replace("http://", "").rstrip("/")
    base_url = f"https://{hostname}"

    # ── Output directory ──────────────────────────────────────────────────────
    if out_dir is None:
        safe  = hostname.replace(".", "_")
        ts    = datetime.now().strftime("%Y%m%d_%H%M")
        out_dir = Path(f"{safe}_payment_trace_{ts}")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  PAYMENT TRACE  –  {hostname}")
    print(f"{'='*60}")

    all_psp_hits     = {}
    all_csp          = {}
    platform_findings = []

    # ── A. Static evidence scan ───────────────────────────────────────────────
    if evidence_dir:
        ev_path = Path(evidence_dir)
        if ev_path.exists():
            static = scan_evidence_directory(ev_path)
            all_psp_hits     = merge_psp_hits(all_psp_hits, static["psp_hits"])
            all_csp.update(static["csp_findings"])
            platform_findings = static["platform"]
        else:
            print(f"[!] Evidence directory not found: {ev_path}")

    # Also scan any inline text from existing_findings
    if existing_findings:
        for key in ("html",):
            section = existing_findings.get(key, {})
            raw = section.get("raw", "") or section.get("source", "")
            if raw:
                hits = scan_text(raw)
                all_psp_hits = merge_psp_hits(all_psp_hits, hits)

        # Check headers from existing findings
        hdrs = existing_findings.get("headers", {})
        if isinstance(hdrs, dict):
            header_text = json.dumps(hdrs)
            csp_raw = hdrs.get("content-security-policy", "")
            if csp_raw:
                all_csp[base_url] = parse_csp(csp_raw)
            hits = scan_text(header_text)
            all_psp_hits = merge_psp_hits(all_psp_hits, hits)

    # ── B. Live checkout probe ────────────────────────────────────────────────
    live_results = {}
    if do_live_probe:
        live_results = probe_live_checkout(base_url)
        all_psp_hits = merge_psp_hits(all_psp_hits, live_results.get("psp_hits", {}))
        all_csp.update(live_results.get("csp", {}))
        if not platform_findings:
            # Attempt platform ID from live page content
            for entry in live_results.get("probed_urls", []):
                pass  # text already scanned above during probe

    # ── C. Platform identification from existing findings ─────────────────────
    if not platform_findings and existing_findings:
        combined = json.dumps(existing_findings)
        platform_findings = identify_platform(combined)

    # ── D. Summarise findings ─────────────────────────────────────────────────
    print(f"\n[+] Identified payment processors:")
    if all_psp_hits:
        for psp_key, hit in all_psp_hits.items():
            name = hit.get("description", psp_key)
            ids  = hit.get("extracted_identifiers", {})
            id_str = ", ".join(f"{k}={v}" for k, v in ids.items()) if ids else "no unique key"
            print(f"    • {name:30s}  [{id_str}]")
    else:
        print("    (none identified from collected evidence)")
        print("    → Recommendation: manually complete a test checkout and capture")
        print("      the payment form HTML/network requests.")

    print(f"\n[+] E-commerce platform:")
    for p in platform_findings:
        print(f"    • {p['platform']}")

    # ── E. Generate reports ───────────────────────────────────────────────────
    reports_written = []

    for psp_key, hit in all_psp_hits.items():
        complaint = generate_psp_complaint(hostname, psp_key, hit)
        fname = out_dir / f"complaint_{psp_key}.txt"
        fname.write_text(complaint, encoding="utf-8")
        reports_written.append(str(fname))
        print(f"[+] Written: {fname}")

    # Law-enforcement brief
    le_brief = generate_law_enforcement_brief(
        hostname, all_psp_hits, platform_findings, existing_findings
    )
    le_path = out_dir / "law_enforcement_payment_brief.txt"
    le_path.write_text(le_brief, encoding="utf-8")
    reports_written.append(str(le_path))
    print(f"[+] Written: {le_path}")

    # ── F. Save machine-readable findings ────────────────────────────────────
    findings = {
        "hostname":           hostname,
        "timestamp":          _now_str(),
        "platform":           platform_findings,
        "psp_hits":           all_psp_hits,
        "csp_payment_origins": all_csp,
        "live_probe":         live_results,
        "reports_written":    reports_written,
    }
    json_path = out_dir / "payment_trace.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    print(f"[+] Written: {json_path}")

    print(f"\n{'='*60}")
    print(f"  Payment trace complete. Reports in: {out_dir}/")
    print(f"{'='*60}\n")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ══════════════════════════════════════════════════════════════════════════════

def _find_evidence_dir(hostname: str) -> Path | None:
    """
    Auto-detect an existing evidence directory for the given hostname.
    Looks for patterns like  dkoutlet24_com_analysis_*/
    """
    safe = hostname.replace(".", "_")
    for candidate in sorted(Path(".").glob(f"{safe}_analysis_*"), reverse=True):
        if candidate.is_dir():
            return candidate
    return None


def _find_findings_json(hostname: str) -> Path | None:
    """Auto-detect an existing findings JSON for the given hostname."""
    safe = hostname.replace(".", "_")
    for candidate in sorted(Path(".").glob(f"{safe}_origin_*.json"), reverse=True):
        return candidate
    return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nUsage: python payment_tracer.py <url_or_hostname_or_findings.json>")
        sys.exit(1)

    arg = sys.argv[1]

    # Accept a findings JSON as input
    if arg.endswith(".json") and Path(arg).exists():
        with open(arg, encoding="utf-8") as f:
            loaded = json.load(f)
        _tgt = loaded.get("target", "")
        if isinstance(_tgt, dict):
            hostname = _tgt.get("hostname", "")
        else:
            hostname = str(_tgt)
        if not hostname:
            hostname = arg.replace("_origin_", "").split(".json")[0].replace("_", ".")
        existing_findings = loaded
        print(f"[*] Loaded existing findings for: {hostname}")
    else:
        hostname = arg.replace("https://", "").replace("http://", "").rstrip("/")
        existing_findings = None
        # Try to auto-load findings JSON
        jpath = _find_findings_json(hostname)
        if jpath:
            print(f"[*] Auto-loading findings: {jpath}")
            with open(jpath, encoding="utf-8") as f:
                existing_findings = json.load(f)

    # Auto-detect evidence directory
    ev_dir = _find_evidence_dir(hostname.replace(".", "_").split("_")[0])
    if not ev_dir:
        ev_dir = _find_evidence_dir(hostname)
    if ev_dir:
        print(f"[*] Auto-detected evidence directory: {ev_dir}")

    # Determine output directory
    safe_name = hostname.replace(".", "_")
    ts_str    = datetime.now().strftime("%Y%m%d_%H%M")

    # Place output inside existing analysis dir if available
    if ev_dir:
        out = ev_dir / "payment_trace"
    else:
        out = Path(f"{safe_name}_payment_trace_{ts_str}")

    run_payment_trace(
        hostname         = hostname,
        existing_findings = existing_findings,
        out_dir          = out,
        evidence_dir     = ev_dir / "evidence" if ev_dir else None,
        do_live_probe    = True,
    )
