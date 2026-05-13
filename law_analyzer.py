#!/usr/bin/env python3
"""
law_analyzer.py  –  Legal framework analysis for suspected fraudulent websites.

Identifies applicable Danish, EU, and international laws based on reconnaissance
findings from origin_finder.py, with special coverage of CDN/firewall-hiding laws.

Generates a formal legal complaint document ready for submission to:
  • Politiets Nationale Cyber Crime Center (NC3)
  • Statsadvokaten / State Prosecutor
  • Forbrugerombudsmanden (Danish Consumer Ombudsman)
  • A private attorney

Standalone usage:
    python law_analyzer.py <findings.json>

Called from origin_finder.py:
    from law_analyzer import run_law_analysis
    run_law_analysis(hostname, all_findings, out_dir)
"""

import sys
import os
import json
import re
from datetime import datetime, timezone
from pathlib import Path

# ── Law database ──────────────────────────────────────────────────────────────

LAWS = {
    # ── Danish national laws ──────────────────────────────────────────────────
    "DK_EHANDEL_13": {
        "jurisdiction": "Denmark",
        "name": "E-handelsloven § 13",
        "full_ref": "Lov om tjenester i informationssamfundet (LBK nr. 1295 af 13/11/2019), § 13",
        "topic": "Mandatory business identification for online service providers",
        "requirement": (
            "Online service providers targeting Danish consumers must clearly display: "
            "(1) full legal name and registered address, "
            "(2) CVR-number (company registration number), "
            "(3) e-mail address, "
            "(4) phone number or other direct contact method."
        ),
        "penalty": "Fine or imprisonment up to 4 months (§ 17). Cease-and-desist by Forbrugerombudsmanden.",
        "trigger_fields": ["danish_compliance.applicable", "danish_compliance.checks.cvr_found"],
    },
    "DK_MARKEDSF_5": {
        "jurisdiction": "Denmark",
        "name": "Markedsføringsloven § 5",
        "full_ref": "Lov om markedsføring (Lov nr. 426 af 03/05/2017), § 5",
        "topic": "Prohibition against misleading commercial practices",
        "requirement": (
            "Commercial practices that are likely to deceive the average consumer, "
            "including false information about the trader's identity, geographical address, "
            "or qualifications, are prohibited."
        ),
        "penalty": "Fine or imprisonment up to 1.5 years for aggravated cases (§ 37).",
        "trigger_fields": ["danish_compliance.applicable"],
    },
    "DK_MARKEDSF_12": {
        "jurisdiction": "Denmark",
        "name": "Markedsføringsloven §§ 12–14",
        "full_ref": "Lov om markedsføring (Lov nr. 426 af 03/05/2017), §§ 12–14",
        "topic": "Required pre-contractual information in distance selling",
        "requirement": (
            "Before a distance contract is concluded, the trader must provide: "
            "main characteristics of goods/services, total price incl. taxes, "
            "delivery costs, right of withdrawal, complaint procedures, and "
            "the trader's full identity including CVR."
        ),
        "penalty": "Orders, fines, injunctions by Forbrugerombudsmanden.",
        "trigger_fields": ["danish_compliance.applicable"],
    },
    "DK_STRAF_279": {
        "jurisdiction": "Denmark",
        "name": "Straffeloven § 279 – Bedrageri",
        "full_ref": "Bekendtgørelse af straffeloven (LBK nr. 1651 af 11/08/2020), § 279",
        "topic": "Fraud (bedrageri) – criminal liability",
        "requirement": (
            "Any person who, for financial gain, unlawfully induces another person "
            "into an act or omission causing a financial loss to that person or others, "
            "is guilty of fraud. Fake online shops taking payment without delivery qualify."
        ),
        "penalty": "Imprisonment up to 1 year 6 months (§ 279); up to 8 years for aggravated fraud (§ 286).",
        "trigger_fields": ["ai_verdict_high_risk", "danish_compliance.score_low"],
    },
    "DK_STRAF_279A": {
        "jurisdiction": "Denmark",
        "name": "Straffeloven § 279a – Computerbedrageri",
        "full_ref": "Bekendtgørelse af straffeloven (LBK nr. 1651 af 11/08/2020), § 279a",
        "topic": "Computer fraud – criminal liability for deceptive digital transactions",
        "requirement": (
            "Unlawfully influencing the result of automated data processing for financial gain "
            "is a criminal offence. Applies to fake webshops that process fraudulent payment orders."
        ),
        "penalty": "Imprisonment up to 1 year 6 months; up to 8 years for aggravated cases.",
        "trigger_fields": ["ai_verdict_high_risk"],
    },
    "DK_FORBRUGER_13": {
        "jurisdiction": "Denmark",
        "name": "Forbrugeraftaleloven § 13–14",
        "full_ref": "Bekendtgørelse af lov om forbrugeraftaler (LBK nr. 1457 af 17/12/2013), §§ 13–14",
        "topic": "Consumer distance contracts – mandatory information",
        "requirement": (
            "For distance contracts (online sales), the trader must provide the consumer with "
            "14-day right of withdrawal, full price breakdown, delivery conditions, "
            "and the trader's identity before the consumer is bound."
        ),
        "penalty": "Void contract; fines; Forbrugerombudsmanden enforcement.",
        "trigger_fields": ["danish_compliance.applicable"],
    },

    # ── EU / EEA laws ─────────────────────────────────────────────────────────
    "EU_DSA_16": {
        "jurisdiction": "EU",
        "name": "Digital Services Act – Article 16 (Notice and Action)",
        "full_ref": "Regulation (EU) 2022/2065 of 19 October 2022, Article 16",
        "topic": "Illegal content reporting mechanism – hosting providers must act",
        "requirement": (
            "Hosting providers (including Cloudflare) must implement a notice-and-action "
            "mechanism allowing any person to report illegal content. Upon receipt of a "
            "sufficiently precise notice, the provider must act expeditiously to remove "
            "or disable access to illegal content."
        ),
        "penalty": "Fines up to 6 % of global annual turnover for non-compliant providers.",
        "trigger_fields": ["behind_cloudflare", "ai_verdict_high_risk"],
    },
    "EU_DSA_17": {
        "jurisdiction": "EU",
        "name": "Digital Services Act – Article 17 (Statement of reasons)",
        "full_ref": "Regulation (EU) 2022/2065 of 19 October 2022, Article 17",
        "topic": "Transparency obligations – Cloudflare must justify content decisions",
        "requirement": (
            "Hosting providers that restrict access to or remove content must provide "
            "a clear and specific statement of reasons to the affected recipient. "
            "This mechanism allows investigators to require Cloudflare to disclose "
            "information about the origin server under court order."
        ),
        "penalty": "Administrative enforcement by national Digital Services Coordinator.",
        "trigger_fields": ["behind_cloudflare"],
    },
    "EU_DSA_44": {
        "jurisdiction": "EU",
        "name": "Digital Services Act – Article 44 (Domain WHOIS data)",
        "full_ref": "Regulation (EU) 2022/2065 of 19 October 2022, Article 44",
        "topic": "WHOIS accuracy – registrars must maintain accurate registrant data",
        "requirement": (
            "Domain name registrars and registries must maintain accurate and complete "
            "WHOIS data. Privacy services may not be used to shield operators of illegal "
            "services from lawful disclosure requests. Law enforcement may compel "
            "disclosure of registrant identity data hidden behind privacy services."
        ),
        "penalty": "Coordinated enforcement by ICANN and Digital Services Coordinators.",
        "trigger_fields": ["whois_privacy"],
    },
    "EU_DSA_COURT": {
        "jurisdiction": "EU",
        "name": "DSA / GDPR – Judicial order to reveal Cloudflare origin",
        "full_ref": "Regulation (EU) 2022/2065 Arts. 9–10; GDPR Art. 6(1)(c); established case law",
        "topic": "Court-ordered disclosure of CDN origin server by Cloudflare",
        "requirement": (
            "A court with jurisdiction can order Cloudflare (and other CDN/proxy providers) "
            "to disclose the origin IP address and account holder details of the site hiding "
            "behind their service. This is established practice in multiple EU member states "
            "(see e.g. Danish Maritime and Commercial Court rulings on intermediary disclosure). "
            "Cloudflare is subject to EU law as a provider offering services in the EU. "
            "A formal police request (Section 75 of the Danish Administration of Justice Act / "
            "Retsplejeloven § 75) can compel this disclosure without a civil suit."
        ),
        "penalty": "Contempt of court if Cloudflare fails to comply with disclosure order.",
        "trigger_fields": ["behind_cloudflare"],
    },
    "EU_CRD_6": {
        "jurisdiction": "EU",
        "name": "Consumer Rights Directive – Article 6",
        "full_ref": "Directive 2011/83/EU of 25 October 2011, Article 6",
        "topic": "Pre-contractual information requirements for distance contracts",
        "requirement": (
            "Traders must provide, before the consumer is bound, inter alia: "
            "the trader's name, geographical address, phone number, e-mail, "
            "the total price of goods or services, right-of-withdrawal conditions, "
            "and the duration of the contract."
        ),
        "penalty": "Directive implemented in Danish law via Forbrugeraftaleloven.",
        "trigger_fields": ["danish_compliance.applicable"],
    },
    "EU_UCPD": {
        "jurisdiction": "EU",
        "name": "Unfair Commercial Practices Directive",
        "full_ref": "Directive 2005/29/EC of 11 May 2005",
        "topic": "Misleading and aggressive commercial practices",
        "requirement": (
            "Commercial practices that mislead the average consumer about the trader's "
            "identity, qualifications, or the nature of the goods are prohibited. "
            "Operating under a false or concealed identity constitutes a misleading "
            "commercial practice under Annex I ('Blacklist')."
        ),
        "penalty": "Implemented in Danish Markedsføringsloven; fines and injunctions.",
        "trigger_fields": ["danish_compliance.applicable", "whois_privacy"],
    },
    "EU_GDPR_13": {
        "jurisdiction": "EU",
        "name": "GDPR – Articles 13–14 (Privacy information obligations)",
        "full_ref": "Regulation (EU) 2016/679 of 27 April 2016, Articles 13–14",
        "topic": "Data subjects must be informed when personal data are collected",
        "requirement": (
            "When collecting personal data (including via cookies, tracking pixels, or "
            "account registration), the data controller must provide: controller identity "
            "and contact details, DPO contact, purpose and legal basis for processing, "
            "data retention periods, and rights of the data subject. "
            "Operating without a privacy policy, or under a false identity, violates this."
        ),
        "penalty": (
            "Administrative fines up to € 20,000,000 or 4 % of global annual turnover "
            "(whichever is higher) by Datatilsynet (Danish Data Protection Agency)."
        ),
        "trigger_fields": ["has_tracking_ids", "danish_compliance.applicable"],
    },
    "EU_ECOMMERCE_5": {
        "jurisdiction": "EU",
        "name": "E-Commerce Directive – Article 5",
        "full_ref": "Directive 2000/31/EC of 8 June 2000, Article 5",
        "topic": "General information requirements for information society services",
        "requirement": (
            "Service providers must render easily, directly and permanently accessible "
            "to recipients: the provider's name, geographic address, e-mail address, "
            "trade register and registration number, VAT number, and any applicable "
            "authorisation scheme."
        ),
        "penalty": "Implemented in Danish E-handelsloven; see § 13 penalties above.",
        "trigger_fields": ["danish_compliance.applicable"],
    },

    # ── International ─────────────────────────────────────────────────────────
    "ICANN_WHOIS": {
        "jurisdiction": "International (ICANN)",
        "name": "ICANN Registration Data Policy – WHOIS Accuracy",
        "full_ref": "ICANN Registration Data Policy (RDAP), adopted 2023",
        "topic": "Registrars must maintain accurate registrant contact information",
        "requirement": (
            "Under ICANN's Registrar Accreditation Agreement, registrars must verify "
            "and maintain accurate registrant data. Inaccurate WHOIS data is a violation "
            "of the registrar agreement and can result in domain suspension. "
            "ICANN's Compliance department accepts abuse reports."
        ),
        "penalty": "Domain suspension; registrar breach-of-contract proceedings.",
        "trigger_fields": ["whois_privacy"],
    },
    "US_CFAA": {
        "jurisdiction": "United States",
        "name": "Computer Fraud and Abuse Act (CFAA)",
        "full_ref": "18 U.S.C. § 1030",
        "topic": "Fraudulent computer access and online fraud",
        "requirement": (
            "Applies when US-based infrastructure (e.g. Cloudflare, US-based hosting) "
            "is used to perpetrate fraud. The FBI's Internet Crime Complaint Center (IC3) "
            "accepts complaints under this statute. Cloudflare Inc. is headquartered in "
            "San Francisco, CA, USA, and therefore subject to US law for law enforcement "
            "disclosure orders."
        ),
        "penalty": "Federal criminal penalties; imprisonment up to 20 years.",
        "trigger_fields": ["behind_cloudflare", "ai_verdict_high_risk"],
    },
}

# ── Violation assessment ───────────────────────────────────────────────────────

def assess_violations(hostname: str, findings: dict) -> dict:
    """
    Map reconnaissance findings to concrete law violations.
    Returns a dict of law_key → {applies: bool, severity: str, evidence: list}.
    """
    compliance  = findings.get("danish_compliance", {})
    headers     = findings.get("headers", {})
    whois_data  = findings.get("whois", {})
    html_data   = findings.get("html", {})
    ai_text     = findings.get("ai_analysis", "")
    checks      = compliance.get("checks", {})
    score       = compliance.get("score", 100)
    dk_applies  = compliance.get("applicable", False)

    # Derive boolean context flags
    behind_cf      = headers.get("behind_cloudflare", False)
    whois_privacy  = "REDACTED" in str(whois_data.get("org", "")).upper() or not whois_data
    has_tracking   = bool(html_data.get("tracking_ids"))
    ai_high_risk   = bool(re.search(r"HIGH RISK|FRAUDULENT|SUSPICIOUS", ai_text, re.I))
    score_low      = score < 50

    def severity(s: int) -> str:
        if s >= 80:  return "CRITICAL"
        if s >= 60:  return "HIGH"
        if s >= 40:  return "MEDIUM"
        return "LOW"

    results = {}

    for law_key, law in LAWS.items():
        applies = False
        evidence = []

        if "danish_compliance.applicable" in law["trigger_fields"]:
            if dk_applies:
                applies = True
                evidence.append(f"Danish market targeting confirmed ({len(compliance.get('signals', []))} signals)")

        if "danish_compliance.checks.cvr_found" in law["trigger_fields"]:
            if dk_applies and not checks.get("cvr_found"):
                applies = True
                evidence.append("CVR-number NOT found on site (mandatory for DK businesses)")
            elif dk_applies and not checks.get("cvr_verified"):
                applies = True
                evidence.append(f"CVR {checks.get('cvr_found')} found but UNVERIFIED")

        if "danish_compliance.score_low" in law["trigger_fields"]:
            if score_low:
                applies = True
                evidence.append(f"DK Compliance Score: {score}/100 (below 50 – non-compliant)")

        if "behind_cloudflare" in law["trigger_fields"]:
            if behind_cf:
                applies = True
                evidence.append(f"Site confirmed behind Cloudflare (IPs: {headers.get('resolved_ip', 'N/A')})")

        if "whois_privacy" in law["trigger_fields"]:
            if whois_privacy:
                applies = True
                evidence.append("WHOIS registrant data redacted / privacy protected")

        if "ai_verdict_high_risk" in law["trigger_fields"]:
            if ai_high_risk:
                applies = True
                # Extract the specific score from AI text if present
                m = re.search(r"SITE LEGITIMACY SCORE:\s*(\d+)/100", ai_text)
                if m:
                    evidence.append(f"AI legitimacy score: {m.group(1)}/100 – HIGH RISK / FRAUDULENT")
                else:
                    evidence.append("AI analysis verdict: HIGH RISK or FRAUDULENT")

        if "has_tracking_ids" in law["trigger_fields"]:
            if has_tracking:
                applies = True
                ids = list(html_data["tracking_ids"].keys())
                evidence.append(f"Tracking IDs found without verifiable privacy policy: {ids}")

        if applies:
            results[law_key] = {
                "applies":   True,
                "law":       law,
                "evidence":  evidence,
                "severity":  severity(80 if ai_high_risk else (50 if score_low else 40)),
            }

    return results


# ── Document generation ───────────────────────────────────────────────────────

def _separator(char="─", width=70) -> str:
    return char * width


def generate_legal_document(hostname: str, findings: dict,
                             violations: dict, out_dir: str) -> str:
    """
    Write a formal legal complaint document to <out_dir>/legal_complaint.txt.
    Returns the file path.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    out_path = os.path.join(out_dir, "legal_complaint.txt")

    compliance  = findings.get("danish_compliance", {})
    whois_data  = findings.get("whois", {})
    headers     = findings.get("headers", {})
    ip_whois    = findings.get("ip_whois", {})
    ai_text     = findings.get("ai_analysis", "")
    checks      = compliance.get("checks", {})
    now         = datetime.now(timezone.utc)
    report_id   = f"OF-{now.strftime('%Y%m%d-%H%M%S')}"

    # Extract AI legitimacy score
    m = re.search(r"SITE LEGITIMACY SCORE:\s*(\d+)/100[^\n]*", ai_text)
    legitimacy_line = m.group(0).strip() if m else "Not available"

    lines = []
    A = lines.append  # shorthand

    A(_separator("═"))
    A("  FORMAL LEGAL COMPLAINT AND FORENSIC REPORT")
    A("  Concerning: Suspected Fraudulent Online Activity")
    A(_separator("═"))
    A(f"  Report ID       : {report_id}")
    A(f"  Target domain   : {hostname}")
    A(f"  Date / time     : {now.strftime('%Y-%m-%d %H:%M UTC')}")
    A(f"  Prepared by     : Origin Finder v1.0 (automated forensic analysis)")
    A(_separator("═"))
    A("")

    # ── SECTION 1: EXECUTIVE SUMMARY ─────────────────────────────────────────
    A(_separator())
    A("  SECTION 1 – EXECUTIVE SUMMARY")
    A(_separator())
    A("")
    A(f"  This report documents a forensic investigation of the website '{hostname}'.")
    A(f"  The investigation was conducted using open-source intelligence (OSINT) techniques")
    A(f"  including WHOIS lookups, DNS analysis, SSL certificate inspection, Certificate")
    A(f"  Transparency logs, HTTP header analysis, HTML source mining, and AI-assisted")
    A(f"  synthesis of all findings.")
    A("")
    A(f"  AI Legitimacy Assessment : {legitimacy_line}")
    A(f"  DK Compliance Score      : {compliance.get('score', 'N/A')}/100")
    A(f"  Cloudflare proxy active  : {'YES – true origin IP hidden' if headers.get('behind_cloudflare') else 'No'}")
    A(f"  WHOIS privacy active     : {'YES – registrant identity hidden' if 'REDACTED' in str(whois_data.get('org', '')).upper() else 'Partially'}")
    A("")
    if ai_text and len(ai_text) > 100:
        # Include first 600 chars of AI summary
        summary_excerpt = ai_text[:700].strip()
        A("  AI VERDICT EXCERPT:")
        for line in summary_excerpt.splitlines():
            A(f"    {line}")
        A("    [... see full AI analysis in accompanying JSON file ...]")
    A("")

    # ── SECTION 2: TECHNICAL FINDINGS ─────────────────────────────────────────
    A(_separator())
    A("  SECTION 2 – KEY TECHNICAL FINDINGS")
    A(_separator())
    A("")
    A(f"  Domain              : {hostname}")
    A(f"  Registrar           : {whois_data.get('registrar', 'Unknown')}")
    A(f"  Registrant country  : {whois_data.get('country', 'Unknown')}")
    A(f"  Registration date   : {whois_data.get('creation_date', 'Unknown')}")
    A(f"  Name servers        : {whois_data.get('name_servers', 'Unknown')}")
    A(f"  Resolved IP         : {headers.get('resolved_ip', 'Unknown')}")
    A(f"  Hosting ASN         : AS{ip_whois.get('asn', '?')} – {ip_whois.get('asn_description', '')}")
    A(f"  Hosting country     : {ip_whois.get('country', 'Unknown')}")
    A(f"  Server type         : {headers.get('header_server', 'Unknown')}")

    dns_data = findings.get("dns", {})
    if dns_data.get("MX"):
        A(f"  MX (mail server)    : {', '.join(dns_data['MX'][:3])}")

    ssl_data = findings.get("ssl_cert", {})
    if ssl_data:
        A(f"  SSL issuer          : {ssl_data.get('issuer_org', '')} / {ssl_data.get('issuer_cn', '')}")
        A(f"  SSL valid until     : {ssl_data.get('valid_until', '')}")

    tech = findings.get("tech", {}).get("detected", [])
    if tech:
        A(f"  Technologies        : {', '.join(tech)}")

    A("")
    A("  DANISH COMPLIANCE CHECK RESULTS:")
    for key, label in [
        ("cvr_found",    "CVR-nummer"),
        ("cvr_verified", "CVR verified"),
        ("company_name", "Legal company name"),
        ("addresses",    "Physical address"),
        ("phones",       "Phone number"),
        ("emails",       "E-mail address"),
        ("contact_forms","Contact form"),
        ("social_media", "Social media"),
    ]:
        val = checks.get(key)
        if isinstance(val, bool):
            status = "✓ YES" if val else "✗ NO"
        elif isinstance(val, list):
            status = f"✓ {val[:2]}" if val else "✗ NOT FOUND"
        elif isinstance(val, dict):
            status = f"✓ {list(val.keys())[:3]}" if val else "✗ NOT FOUND"
        elif val:
            status = f"✓ {val}"
        else:
            status = "✗ NOT FOUND"
        A(f"    {label:<25}: {status}")
    A("")

    # ── SECTION 3: APPLICABLE LAWS AND VIOLATIONS ─────────────────────────────
    A(_separator())
    A("  SECTION 3 – APPLICABLE LAWS AND IDENTIFIED VIOLATIONS")
    A(_separator())
    A("")
    A(f"  The following {len(violations)} laws / regulations are found to apply based on")
    A("  the technical evidence gathered above.")
    A("")

    for i, (law_key, v) in enumerate(violations.items(), 1):
        law = v["law"]
        A(f"  [{i}] {law['name']}")
        A(f"      Jurisdiction : {law['jurisdiction']}")
        A(f"      Reference    : {law['full_ref']}")
        A(f"      Topic        : {law['topic']}")
        A(f"      Requirement  : {law['requirement']}")
        A(f"      Penalty      : {law['penalty']}")
        A(f"      Severity     : {v['severity']}")
        A(f"      Evidence     :")
        for ev in v["evidence"]:
            A(f"        • {ev}")
        A("")

    # ── SECTION 4: CLOUDFLARE / CDN HIDING – SPECIAL LEGAL COMMENTARY ─────────
    if headers.get("behind_cloudflare"):
        A(_separator())
        A("  SECTION 4 – CDN/FIREWALL HIDING: LEGAL PATHWAY TO ORIGIN DISCLOSURE")
        A(_separator())
        A("")
        A("  The site is protected by Cloudflare, concealing the true origin IP address.")
        A("  This does NOT provide legal immunity. The following legal mechanisms exist")
        A("  to compel disclosure of the true operator's identity:")
        A("")
        A("  [A] EU Digital Services Act (DSA) – Article 16 Notice")
        A("      Submit a formal illegal-content notice to Cloudflare's designated DSA")
        A("      contact. Cloudflare, as a hosting provider under DSA, must respond and")
        A("      act expeditiously. If the content is illegal, Cloudflare is required to")
        A("      remove it or pass the notice to the origin hosting provider.")
        A("      DSA Contact for Cloudflare: https://www.cloudflare.com/trust-hub/dsa/")
        A("")
        A("  [B] Police Request (Retsplejeloven § 804 / § 806) – Subscriber Data")
        A("      Danish police (NC3) can issue a lawful intercept / subscriber-data")
        A("      request to Cloudflare Inc. under Retsplejeloven §§ 804–806. Cloudflare")
        A("      must respond to lawful law-enforcement requests from EU member states.")
        A("      Cloudflare's Law Enforcement Guidelines:")
        A("      https://www.cloudflare.com/resources/assets/slt3lc6tev37/2qHqVdB79v3F")
        A("      lQ6loqXMBB/80a5efb424b85a10b64cfeb80fe39d2/cloudflare-transparency.pdf")
        A("")
        A("  [C] Civil Court Order (Fogedforbud / injunction)")
        A("      A Danish Maritime and Commercial Court (Sø- og Handelsretten) can issue")
        A("      a disclosure injunction against Cloudflare requiring them to reveal the")
        A("      origin server IP and account holder identity. This has been used in")
        A("      multiple Danish IP and consumer-fraud cases.")
        A("")
        A("  [D] Registrar Abuse Complaint")
        A(f"     Registrar: {whois_data.get('registrar', 'Unknown')}")
        A(f"     Abuse email: {whois_data.get('emails', 'domainabuse@registrar.com')}")
        A("      Registrars are bound by ICANN's Registrar Accreditation Agreement to")
        A("      investigate and suspend domains engaged in illegal activity.")
        A("")
        A("  NOTE: Cloudflare's CF-Ray header value from this investigation:")
        A(f"        {headers.get('header_cf-ray', 'N/A')}")
        A("        This value, combined with the timestamp of investigation, can be used")
        A("        to identify the specific Cloudflare edge node and account in logs.")
        A("")

    # ── SECTION 5: REQUESTED ACTIONS ─────────────────────────────────────────
    A(_separator())
    A("  SECTION 5 – REQUESTED ACTIONS / RELIEF SOUGHT")
    A(_separator())
    A("")
    A("  Based on the above findings, the following actions are requested:")
    A("")
    A("  [1] CRIMINAL INVESTIGATION")
    A(f"      Report to: Politiets Nationale Cyber Crime Center (NC3)")
    A(f"      Online report: https://politi.dk/nc3/anmeld-it-kriminalitet")
    A(f"      Phone: 114 (Denmark national police)")
    A(f"      Include this report and the accompanying JSON evidence file.")
    A("")
    A("  [2] CLOUDFLARE ORIGIN DISCLOSURE")
    A("      Request that Danish police (NC3) submit a formal subscriber-data")
    A("      request to Cloudflare Inc. for account and origin-server details")
    A(f"      associated with domain '{hostname}'.")
    A("")
    A("  [3] DOMAIN SUSPENSION")
    A(f"      File abuse complaint with registrar: {whois_data.get('registrar', 'the registrar')}")
    A(f"      Registrar abuse contact: {whois_data.get('emails', 'see registrar website')}")
    A("      Also file with ICANN Compliance: https://www.icann.org/resources/pages/complain")
    A("")
    A("  [4] CONSUMER AUTHORITY ENFORCEMENT")
    A("      Report to: Forbrugerombudsmanden (Danish Consumer Ombudsman)")
    A("      Online: https://www.forbrug.dk/anmeld/")
    A("      E-mail: fo@forbrug.dk")
    A("      Include: this report + screenshots of fraudulent practices.")
    A("")
    A("  [5] DATATILSYNET (if GDPR/cookie violations)")
    A("      Online: https://www.datatilsynet.dk/kontakt")
    A("      Include: evidence of tracking without consent / missing privacy policy.")
    A("")
    A("  [6] GOOGLE SAFE BROWSING (immediate consumer protection)")
    A(f"      https://safebrowsing.google.com/safebrowsing/report_phish/?url=https://{hostname}")
    A("")

    # ── SECTION 6: EVIDENCE INVENTORY ────────────────────────────────────────
    A(_separator())
    A("  SECTION 6 – EVIDENCE INVENTORY")
    A(_separator())
    A("")
    A("  The following digital evidence has been collected and preserved:")
    A("")
    A(f"  • This legal complaint document ({report_id}.txt)")
    A(f"  • Full reconnaissance JSON file (origin_finder output)")
    A(f"  • DNS records, WHOIS data, SSL certificate details")
    A(f"  • HTTP response headers (including Cloudflare CF-Ray)")
    A(f"  • HTML source and technology fingerprints")
    A(f"  • Danish compliance check results")
    A(f"  • AI forensic analysis and verdict")
    if checks.get("cvr_found"):
        A(f"  • CVR verification result for CVR {checks['cvr_found']} from cvrapi.dk")
    A("")
    A("  All evidence files are timestamped and SHA-256 hashed.")
    A("  Chain of custody: see accompanying evidence_manifest.txt (if collected).")
    A("")
    A(_separator("═"))
    A("  END OF LEGAL COMPLAINT DOCUMENT")
    A(f"  Report ID: {report_id}   |   Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}")
    A(_separator("═"))

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return out_path


# ── Main entry point (called from origin_finder.py) ───────────────────────────

def run_law_analysis(hostname: str, findings: dict, out_dir: str) -> dict:
    """
    Run the full legal analysis and generate the complaint document.
    Returns a summary dict suitable for inclusion in origin_finder's JSON output.
    """
    print(f"\n{'─'*60}")
    print("  14 · Legal Framework Analysis")
    print('─'*60)

    violations = assess_violations(hostname, findings)

    if violations:
        print(f"\n  {len(violations)} applicable law(s) / regulation(s) identified:")
        for law_key, v in violations.items():
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(v["severity"], "•")
            print(f"  {sev_icon} [{v['severity']:<8}] {v['law']['name']}")
            for ev in v["evidence"]:
                print(f"              Evidence: {ev}")
    else:
        print("  No specific violations identified based on current findings.")

    # Generate legal document
    doc_path = generate_legal_document(hostname, findings, violations, out_dir)
    print(f"\n  ✓ Legal complaint document saved to: {doc_path}")

    return {
        "violation_count":   len(violations),
        "laws_triggered":    list(violations.keys()),
        "severities":        {k: v["severity"] for k, v in violations.items()},
        "complaint_document": doc_path,
    }


# ── Standalone usage ──────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python law_analyzer.py <findings.json>")
        print("       Analyses findings from origin_finder.py and generates legal complaint.")
        sys.exit(1)

    json_path = sys.argv[1]
    try:
        with open(json_path, encoding="utf-8") as f:
            findings = json.load(f)
    except Exception as exc:
        sys.exit(f"[!] Cannot read findings file: {exc}")

    hostname = findings.get("target", os.path.basename(json_path).replace("_origin_", "").split("_")[0])
    out_dir  = hostname.replace(".", "_") + "_legal"
    result   = run_law_analysis(hostname, findings, out_dir)
    print(f"\n  Summary: {result['violation_count']} laws apply.")
    print(f"  Document: {result['complaint_document']}")


if __name__ == "__main__":
    main()
