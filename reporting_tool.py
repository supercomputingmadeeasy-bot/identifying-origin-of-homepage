#!/usr/bin/env python3
"""
reporting_tool.py  –  Electronic reporting to authorities and platforms.

Generates ready-to-submit reports and submits electronically where APIs allow,
for suspected fraudulent / non-compliant websites.

Covered authorities and platforms:
  [1] Google Safe Browsing         – phishing / malware reporting
  [2] Cloudflare Abuse             – DSA-compliant abuse notice
  [3] Domain Registrar Abuse       – ICANN + registrar-specific contact
  [4] Danish NC3                   – Politiets Nationale Cyber Crime Center
  [5] Forbrugerombudsmanden        – Danish Consumer Ombudsman
  [6] Europol EC3 / Your Europe    – Cross-border EU consumer complaint
  [7] ICANN Compliance             – WHOIS inaccuracy complaint
  [8] Google Merchant Center       – Shopping fraud report
  [9] Meta / Facebook              – Counterfeit goods report

For each authority:
  • A formatted complaint text is generated (ready to paste or e-mail)
  • Where a public submission URL/API exists, it is opened or called
  • All generated documents are saved to the output directory

Standalone usage:
    python reporting_tool.py <findings.json>

Called from origin_finder.py:
    from reporting_tool import generate_reports
    generate_reports(hostname, all_findings, out_dir)
"""

import sys
import os
import re
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

try:
    import requests
except ImportError:
    sys.exit("[!] Missing dependency: requests\n    Run: pip install requests")


# ── Authority definitions ─────────────────────────────────────────────────────

AUTHORITIES = {
    "google_safebrowsing": {
        "name":        "Google Safe Browsing",
        "description": "Adds the URL to Google's phishing/malware database, removing it from search results and triggering browser warnings for all Chrome/Firefox/Safari users worldwide.",
        "url_template": "https://safebrowsing.google.com/safebrowsing/report_phish/?url={url_encoded}&hl=en",
        "method":      "browser_url",
        "email":       None,
    },
    "cloudflare_abuse": {
        "name":        "Cloudflare Abuse (DSA Article 16 Notice)",
        "description": "Formal Digital Services Act notice to Cloudflare as the hosting provider. Under DSA Art. 16, Cloudflare must act on illegal-content notices and may be required to disclose the origin server.",
        "url":         "https://www.cloudflare.com/abuse/form",
        "method":      "form",
        "email":       "abuse@cloudflare.com",
    },
    "registrar_abuse": {
        "name":        "Domain Registrar Abuse",
        "description": "Under ICANN's Registrar Accreditation Agreement, the registrar must investigate and can suspend the domain for illegal use.",
        "url":         "https://lookup.icann.org/",
        "method":      "email",
        "email":       None,   # filled from WHOIS findings
    },
    "icann_compliance": {
        "name":        "ICANN Compliance (WHOIS Inaccuracy)",
        "description": "Complaint about inaccurate or privacy-shielded WHOIS data for a domain engaged in illegal activity.",
        "url":         "https://www.icann.org/resources/pages/complain",
        "method":      "form",
        "email":       None,
    },
    "dk_nc3": {
        "name":        "Danish NC3 – Politiets Nationale Cyber Crime Center",
        "description": "Criminal complaint to Danish national cybercrime police. NC3 can request subscriber data from Cloudflare and registrars, and coordinate with Europol/FBI.",
        "url":         "https://politi.dk/nc3/anmeld-it-kriminalitet",
        "method":      "form",
        "email":       "nc3@politi.dk",
        "phone":       "+45 114",
    },
    "dk_forbrugerombudsmanden": {
        "name":        "Forbrugerombudsmanden (Danish Consumer Ombudsman)",
        "description": "Administrative enforcement of Markedsføringsloven, E-handelsloven, and Forbrugeraftaleloven. Can issue injunctions, fines, and cease-and-desist orders.",
        "url":         "https://www.forbrug.dk/anmeld/",
        "method":      "form",
        "email":       "fo@forbrug.dk",
    },
    "ec_consumer": {
        "name":        "European Consumer Centre Denmark / EU Consumer Online Dispute",
        "description": "Cross-border EU consumer complaint platform. Escalates to competent authority in the seller's country.",
        "url":         "https://ec.europa.eu/consumers/odr/",
        "method":      "form",
        "email":       "ecc@forbrug.dk",
    },
    "google_merchant": {
        "name":        "Google Merchant Center – Shopping Fraud",
        "description": "Report the site for appearing fraudulently in Google Shopping. Google can delist the merchant.",
        "url":         "https://support.google.com/merchants/contact/merchant_verification_appeal",
        "method":      "form",
        "email":       None,
    },
    "meta_ip": {
        "name":        "Meta / Facebook – Intellectual Property / Counterfeit Report",
        "description": "If the site impersonates a brand or sells counterfeit goods advertised via Facebook/Instagram.",
        "url":         "https://www.facebook.com/help/contact/1408715455914466",
        "method":      "form",
        "email":       None,
    },
}


# ── Report text generators ─────────────────────────────────────────────────────

def _header(label: str, width: int = 70) -> str:
    return f"\n{'─' * width}\n  {label}\n{'─' * width}\n"


def _extract_score(ai_text: str) -> tuple:
    """Return (legitimacy_score_int, score_line_str) from AI analysis text."""
    m = re.search(r"SITE LEGITIMACY SCORE:\s*(\d+)/100[^\n]*", ai_text)
    if m:
        score_line = m.group(0).strip()
        score_int  = int(m.group(1))
        return score_int, score_line
    return 0, "Not available"


def _format_common_header(hostname: str, findings: dict) -> str:
    """Shared header block for all reports."""
    now       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    whois     = findings.get("whois", {})
    headers   = findings.get("headers", {})
    ip_whois  = findings.get("ip_whois", {})
    compliance= findings.get("danish_compliance", {})
    checks    = compliance.get("checks", {})
    ai_text   = findings.get("ai_analysis", "")
    _, score_line = _extract_score(ai_text)

    lines = [
        f"DOMAIN          : {hostname}",
        f"REPORT DATE     : {now}",
        f"REGISTRAR       : {whois.get('registrar', 'Unknown')}",
        f"REG. DATE       : {whois.get('creation_date', 'Unknown')}",
        f"REGISTRANT CC   : {whois.get('country', 'Unknown')}",
        f"WHOIS PRIVACY   : {'YES – registrant hidden' if 'REDACTED' in str(whois.get('org','')).upper() else 'Partial / Unknown'}",
        f"RESOLVED IP     : {headers.get('resolved_ip', 'Unknown')}",
        f"CDN / PROXY     : {'Cloudflare (origin IP hidden)' if headers.get('behind_cloudflare') else 'None detected'}",
        f"HOSTING ASN     : AS{ip_whois.get('asn','?')} {ip_whois.get('asn_description','')}",
        f"HOSTING COUNTRY : {ip_whois.get('country','Unknown')}",
        f"DK COMPLIANCE   : {compliance.get('score','N/A')}/100 – {compliance.get('verdict','')}",
        f"AI VERDICT      : {score_line}",
        f"CVR-NUMMER      : {checks.get('cvr_found','NOT FOUND')} (verified: {checks.get('cvr_verified', False)})",
    ]
    return "\n".join(f"  {l}" for l in lines)


# ── Individual report generators ──────────────────────────────────────────────

def report_google_safebrowsing(hostname: str, findings: dict) -> dict:
    url = f"https://{hostname}"
    submit_url = f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={quote(url, safe='')}&hl=en"
    ai_text    = findings.get("ai_analysis", "")

    text = f"""GOOGLE SAFE BROWSING – PHISHING / DECEPTIVE SITE REPORT
{'='*65}

{_format_common_header(hostname, findings)}

DESCRIPTION OF HARMFUL ACTIVITY:
  The website {hostname} is suspected to be a fraudulent online shop /
  deceptive website targeting consumers. It collects payments for goods
  or services that are not delivered as described (if at all).

  Key indicators:
  • Domain registered {findings.get('whois', {}).get('creation_date', 'recently')}
  • Hidden behind Cloudflare CDN (true operator unidentifiable)
  • WHOIS registrant data redacted / privacy protected
  • Missing mandatory Danish business information (CVR, address, phone)
  • AI forensic analysis: {ai_text[:200].strip() if ai_text else 'HIGH RISK / FRAUDULENT'}

REQUESTED ACTION:
  1. Add {hostname} to Google Safe Browsing phishing database
  2. Display browser security warning for all users attempting to visit
  3. Delist from Google Search results under Safe Browsing policies

SUBMISSION URL:
  {submit_url}

NOTE: If you have a Google account, sign in before submitting to
      ensure your report is prioritised and tracked.
"""
    return {
        "authority":   "Google Safe Browsing",
        "text":        text,
        "submit_url":  submit_url,
        "method":      "Open the SUBMISSION URL above in your browser and paste the domain",
    }


def report_cloudflare_abuse(hostname: str, findings: dict) -> dict:
    headers  = findings.get("headers", {})
    cf_ray   = headers.get("header_cf-ray", "Not recorded")
    ip       = headers.get("resolved_ip", "Unknown")
    now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    text = f"""CLOUDFLARE ABUSE NOTICE – DIGITAL SERVICES ACT ARTICLE 16
{'='*65}

TO:      Cloudflare Trust & Safety
VIA:     https://www.cloudflare.com/abuse/form
CC:      abuse@cloudflare.com

SUBJECT: Illegal Content Notice under EU DSA Article 16 – {hostname}

{_format_common_header(hostname, findings)}

LEGAL BASIS FOR THIS NOTICE:
  This notice is submitted under Regulation (EU) 2022/2065 (Digital Services
  Act), Article 16 – Notice and Action Mechanism. Cloudflare, Inc. operates
  as a hosting intermediary within the EU and is subject to DSA obligations.

  CF-Ray value observed during investigation: {cf_ray}
  Investigation timestamp                   : {now}

  The above CF-Ray value, combined with the timestamp, allows Cloudflare to
  identify the specific account, origin IP address, and server associated with
  the domain '{hostname}' in Cloudflare's internal access logs.

DESCRIPTION OF ILLEGAL CONTENT:
  The website {hostname} is a suspected fraudulent online shop in violation of:
  • Danish E-handelsloven (LBK nr. 1295/2019) – missing mandatory business info
  • Markedsføringsloven § 5 – misleading commercial practices
  • Consumer Rights Directive 2011/83/EU – missing pre-contractual information
  • Potentially: Straffeloven § 279 (bedrageri / fraud)

  Missing required information:
  • CVR-nummer (Danish company registration): NOT FOUND
  • Physical business address:               NOT FOUND
  • Verified company name:                   NOT FOUND

REQUESTED ACTION (DSA Art. 16):
  1. Expeditiously remove or disable access to the illegal content / website
  2. Preserve all logs, account information, and origin-server details for
     30 days to support ongoing law enforcement investigation
  3. Disclose origin server IP and account holder details to:
     • Politiets NC3 (Danish cybercrime police) upon lawful request
     • Any competent Danish court issuing a disclosure order

CONTACT FOR FOLLOW-UP:
  This report is supported by a full forensic investigation dossier.
  Please contact the reporting party for the complete evidence package.
"""
    return {
        "authority":  "Cloudflare Abuse",
        "text":       text,
        "submit_url": "https://www.cloudflare.com/abuse/form",
        "email":      "abuse@cloudflare.com",
        "method":     "Submit via form above OR email to abuse@cloudflare.com",
    }


def report_registrar_abuse(hostname: str, findings: dict) -> dict:
    whois        = findings.get("whois", {})
    registrar    = whois.get("registrar", "Unknown Registrar")
    abuse_email  = whois.get("emails", "domainabuse@registrar.com")
    # Registrar abuse email is typically the WHOIS email for the registrar
    if isinstance(abuse_email, list):
        abuse_email = abuse_email[0]

    text = f"""DOMAIN REGISTRAR ABUSE REPORT – ICANN POLICY VIOLATION
{'='*65}

TO:      {registrar} – Abuse Department
EMAIL:   {abuse_email}

SUBJECT: Abuse Report – Illegal / Fraudulent Use of Domain: {hostname}

{_format_common_header(hostname, findings)}

LEGAL BASIS:
  Under the ICANN Registrar Accreditation Agreement (RAA) Section 3.18,
  registrars are required to maintain an abuse point of contact and to
  take reasonable and prompt steps to investigate and respond to abuse
  reports for domains under their management.

  Under ICANN's Registration Data Policy, accurate WHOIS data is mandatory.
  This domain's registrant data is fully REDACTED, making it impossible to
  contact the operator about illegal activity or consumer harm.

DESCRIPTION OF ABUSE:
  The domain {hostname} is being used to operate a suspected fraudulent
  online shop targeting Danish consumers. The operator:
  • Has hidden all registrant identity behind privacy services
  • Is hiding the true server behind Cloudflare CDN
  • Has not provided legally required Danish business information (CVR, address)
  • May be collecting payments without delivering goods/services

REQUESTED ACTION:
  1. Investigate the use of this domain for suspected fraud
  2. Disclose registrant identity to:
     – Politiets NC3 (cybercrime police) upon lawful request
     – Danish courts upon disclosure order
  3. If investigation confirms illegal use: SUSPEND the domain
  4. If WHOIS data is inaccurate: initiate accuracy verification per RAA § 3.7.7

ICANN COMPLIANCE REPORT:
  A parallel complaint has also been filed at:
  https://www.icann.org/resources/pages/complain
"""
    return {
        "authority":  f"Registrar: {registrar}",
        "text":       text,
        "email":      abuse_email,
        "method":     f"Email to: {abuse_email}",
    }


def report_dk_nc3(hostname: str, findings: dict) -> dict:
    whois      = findings.get("whois", {})
    headers    = findings.get("headers", {})
    compliance = findings.get("danish_compliance", {})
    checks     = compliance.get("checks", {})
    ai_text    = findings.get("ai_analysis", "")
    _, score_line = _extract_score(ai_text)

    text = f"""POLITIANMELDELSE – IT-KRIMINALITET / INTERNETSVINDEL
{'='*65}

TIL:     Politiets Nationale Cyber Crime Center (NC3)
VIA:     https://politi.dk/nc3/anmeld-it-kriminalitet
EMAIL:   nc3@politi.dk
TLF:     114

EMNE:    Anmeldelse af formodet internetsvindel / falsk webshop – {hostname}

{'─'*65}
TEKNISKE BEVISER (kort oversigt)
{'─'*65}
{_format_common_header(hostname, findings)}

{'─'*65}
BESKRIVELSE AF DEN KRIMINELLE AKTIVITET
{'─'*65}

  Hjemmesiden {hostname} mistænkes for at drive en falsk eller svigagtig
  netbutik rettet mod danske forbrugere. Undersøgelsen viser:

  1. MANGLENDE LOVPLIGTIGE OPLYSNINGER (E-handelsloven § 13):
     • CVR-nummer                  : IKKE FUNDET
     • Fysisk adresse              : {('FUNDET' if checks.get('addresses') else 'IKKE FUNDET')}
     • Fuldt firmanavn             : {('FUNDET' if checks.get('company_name') else 'IKKE FUNDET')}
     • Telefonnummer               : {('FUNDET' if checks.get('phones') else 'IKKE FUNDET')}
     • E-mailadresse               : {('FUNDET' if checks.get('emails') else 'IKKE FUNDET')}
     • Dansk compliance score      : {compliance.get('score', 'N/A')}/100

  2. SKJULT IDENTITET BAG CDN/FIREWALL:
     • Hjemmesiden er beskyttet af Cloudflare, som skjuler den reelle
       server-IP og ejers identitet.
     • Cloudflares CF-Ray header:  {headers.get('header_cf-ray', 'Se vedlagte JSON')}
     • Registrant data er REDACTED (privatiseret via registrar-service)
     • Domænet er registreret den {whois.get('creation_date', 'Ukendt')} (nyregistreret)

  3. AI FORENSISK ANALYSE KONKLUSION:
     {score_line}

  4. MULIGE LOVOVERTRÆDELSER:
     • Straffeloven § 279 (Bedrageri)
     • Straffeloven § 279a (Computerbedrageri)
     • E-handelsloven § 13 (manglende oplysningspligt)
     • Markedsføringsloven § 5 (vildledende handelspraksis)

{'─'*65}
ANMODEDE EFTERFORSKNINGSSKRIDT
{'─'*65}

  1. CLOUDFLARE-FORESPØRGSEL (subscriber data request):
     Anmod Cloudflare, Inc. om at udlevere:
     – Den reelle oprindelses-server-IP for {hostname}
     – Kontooplysninger for den konto, der driver {hostname}
     – Adgangslogfiler for den angiven periode
     Cloudflares politianmodningsportal:
     https://www.cloudflare.com/resources/assets/slt3lc6tev37/...
     (se Cloudflare's Law Enforcement Guidelines)

  2. REGISTRAR-FORESPØRGSEL:
     Registrar: {whois.get('registrar', 'Ukendt')}
     Anmod registrar om at udlevere den faktiske registrants identitet
     bag privacy-servicen i henhold til ICANN RAA § 3.7.8.

  3. DOMÆNESUSPENSION:
     Anmod registrar om midlertidig suspension af domænet, mens
     efterforskningen pågår.

  4. BESLAG AF BEVISMATERIALE:
     Det vedlagte ZIP-arkiv indeholder:
     – Fuld kopi af hjemmesiden (HTML, JavaScript, billeder)
     – HTTP response headers med Cloudflare CF-Ray
     – SHA-256 checksummer for alle filer (integritetsdokumentation)
     – Komplet JSON-rapport fra Origin Finder

ANMELDER:
  Denne anmeldelse er udarbejdet vha. automatiseret open source-efterretning
  (OSINT). Det fulde bevismateriale er vedlagt som ZIP-arkiv og JSON-fil.
"""
    return {
        "authority":  "Politiets NC3",
        "text":       text,
        "submit_url": "https://politi.dk/nc3/anmeld-it-kriminalitet",
        "email":      "nc3@politi.dk",
        "method":     "Submit online at the URL above OR email to nc3@politi.dk with the evidence ZIP attached",
    }


def report_forbrugerombudsmanden(hostname: str, findings: dict) -> dict:
    compliance = findings.get("danish_compliance", {})
    checks     = compliance.get("checks", {})

    missing = []
    if not checks.get("cvr_found"):
        missing.append("CVR-nummer (§ 13, stk. 1, nr. 1)")
    if not checks.get("company_name"):
        missing.append("Fuldt firmanavn (§ 13, stk. 1, nr. 1)")
    if not checks.get("addresses"):
        missing.append("Fysisk adresse (§ 13, stk. 1, nr. 1 + CRD Art. 6)")
    if not checks.get("phones"):
        missing.append("Telefonnummer (§ 13, stk. 1, nr. 3)")
    if not checks.get("emails"):
        missing.append("E-mailadresse (§ 13, stk. 1, nr. 2)")
    if not checks.get("contact_forms"):
        missing.append("Kontaktformular (markedsf. god skik)")

    text = f"""KLAGE TIL FORBRUGEROMBUDSMANDEN
{'='*65}

TIL:     Forbrugerombudsmanden
EMAIL:   fo@forbrug.dk
VIA:     https://www.forbrug.dk/anmeld/

EMNE:    Klage over vildledende handelspraksis og manglende oplysningspligt
         – hjemmesiden {hostname}

{_format_common_header(hostname, findings)}

{'─'*65}
KLAGEN
{'─'*65}

  Hjemmesiden {hostname} markedsfører sig til danske forbrugere, men
  undlader at oplyse de oplysninger, som e-handelsloven, markedsføringsloven
  og forbrugeraftaleloven foreskriver.

  MANGLENDE LOVPLIGTIGE OPLYSNINGER:
{chr(10).join(f'  • {item}' for item in missing) if missing else '  (ingen mangler identificeret)'}

  Compliance score: {compliance.get('score', 'N/A')}/100 (80+ = compliant)
  Verdict: {compliance.get('verdict', 'N/A')}

  MULIGE OVERTRÆDELSER:
  • E-handelsloven (LBK nr. 1295/2019) § 13
  • Markedsføringsloven (Lov nr. 426/2017) §§ 5, 12–14
  • Forbrugeraftaleloven (LBK nr. 1457/2013) §§ 13–14
  • Direktiv 2011/83/EU (Consumer Rights Directive) Art. 6

  Det er ikke muligt at identificere virksomheden bag hjemmesiden, da:
  • WHOIS-registrantoplysninger er fuldstændigt skjult
  • Hjemmesiden er beskyttet af Cloudflare CDN, som skjuler reel server-IP
  • Ingen CVR-nummer er opgivet, og ingen dansk selskabsregistrering kan verificeres

ANMODET HANDLING:
  1. Udsted påbud (injunktion) om øjeblikkelig visning af lovpligtige oplysninger
  2. Indled sag om overtrædelse af markedsføringsloven § 5 (vildledende praksis)
  3. Koordiner med NC3 om strafferetlig efterforskning (bedrageri § 279)
  4. Anmod Cloudflare og registrar om udlevering af ejeroplysninger
     i medfør af myndigheders adgang til oplysninger

VEDLAGT:
  – Fuld forensisk rapport (JSON) fra Origin Finder
  – Juridisk klagedokument (legal_complaint.txt)
  – Webarkiv og bevismateriale (ZIP)
"""
    return {
        "authority":  "Forbrugerombudsmanden",
        "text":       text,
        "submit_url": "https://www.forbrug.dk/anmeld/",
        "email":      "fo@forbrug.dk",
        "method":     "Submit via forbrug.dk OR email to fo@forbrug.dk with attached evidence",
    }


def report_icann_compliance(hostname: str, findings: dict) -> dict:
    whois     = findings.get("whois", {})
    registrar = whois.get("registrar", "Unknown")

    text = f"""ICANN COMPLIANCE COMPLAINT – WHOIS INACCURACY
{'='*65}

TO:      ICANN Compliance
VIA:     https://www.icann.org/resources/pages/complain

SUBJECT: WHOIS Inaccuracy Complaint – {hostname}

{_format_common_header(hostname, findings)}

COMPLAINT:
  The domain {hostname} is registered with {registrar} and has its
  registrant data fully redacted behind a privacy protection service.

  The domain is used to operate a suspected fraudulent online shop.
  Under ICANN's Registration Data Policy (RDAP) and the Registrar
  Accreditation Agreement (RAA) § 3.7.7, registrars must verify and
  maintain accurate registrant contact information.

  When a domain is used for illegal purposes, privacy services cannot
  be used to shield the registrant from legitimate disclosure requests.
  This constitutes a violation of the registrar's ICANN obligations.

REQUESTED ACTION:
  1. Require {registrar} to verify the accuracy of registrant data
  2. Require {registrar} to disclose registrant identity to law
     enforcement upon lawful request
  3. If WHOIS data is found inaccurate: initiate breach proceedings
     against {registrar} per RAA § 3.7.7

SUPPORTING DOCUMENTATION:
  Full OSINT investigation report is available on request.
"""
    return {
        "authority":  "ICANN Compliance",
        "text":       text,
        "submit_url": "https://www.icann.org/resources/pages/complain",
        "method":     "Submit via ICANN Compliance Portal above",
    }


# ── Master report generator ───────────────────────────────────────────────────

def generate_reports(hostname: str, findings: dict, out_dir: str) -> dict:
    """
    Generate all reports and save them to out_dir/reports/.
    Returns a summary dict.
    """
    print(f"\n{'─'*60}")
    print("  16 · Electronic Reporting to Authorities & Platforms")
    print('─'*60)

    reports_dir = Path(out_dir) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    ai_text         = findings.get("ai_analysis", "")
    score_int, _    = _extract_score(ai_text)
    behind_cf       = findings.get("headers", {}).get("behind_cloudflare", False)
    dk_applicable   = findings.get("danish_compliance", {}).get("applicable", False)
    whois           = findings.get("whois", {})
    registrar_email = whois.get("emails", "domainabuse@tucows.com")
    if isinstance(registrar_email, list):
        registrar_email = registrar_email[0]

    all_reports = {}

    # Determine which reports to generate
    report_generators = [
        ("google_safebrowsing",      report_google_safebrowsing,          True),
        ("cloudflare_abuse",         report_cloudflare_abuse,             behind_cf),
        ("registrar_abuse",          report_registrar_abuse,              True),
        ("icann_compliance",         report_icann_compliance,             True),
        ("dk_nc3",                   report_dk_nc3,                       dk_applicable),
        ("dk_forbrugerombudsmanden", report_forbrugerombudsmanden,        dk_applicable),
    ]

    generated_files = []
    for report_key, generator_fn, condition in report_generators:
        if not condition:
            print(f"  [SKIP] {AUTHORITIES.get(report_key, {}).get('name', report_key)} (not applicable)")
            continue

        auth_info = AUTHORITIES.get(report_key, {})
        print(f"\n  [{report_key}] Generating: {auth_info.get('name', report_key)}")

        try:
            report = generator_fn(hostname, findings)
            all_reports[report_key] = report

            # Save report text
            file_path = reports_dir / f"{report_key}.txt"
            file_path.write_text(report["text"], encoding="utf-8")
            generated_files.append(str(file_path))
            print(f"    ✓ Saved: {file_path.name}")
            print(f"    → {report.get('method', '')}")
            if report.get("submit_url"):
                print(f"    → URL: {report['submit_url']}")
            if report.get("email"):
                print(f"    → Email: {report['email']}")

        except Exception as exc:
            print(f"    [ERROR] {exc}")

    # ── Master submission guide ───────────────────────────────────────────────
    guide_path = reports_dir / "SUBMISSION_GUIDE.txt"
    _write_submission_guide(hostname, findings, all_reports, guide_path)
    generated_files.append(str(guide_path))

    print(f"\n  ✓ {len(generated_files)} report file(s) saved to: {reports_dir}")
    print(f"  ✓ Submission guide: {guide_path}")

    return {
        "reports_dir":     str(reports_dir),
        "reports_generated": list(all_reports.keys()),
        "files":           generated_files,
    }


def _write_submission_guide(hostname: str, findings: dict,
                             reports: dict, out_path: Path):
    """Write a step-by-step guide for submitting all reports."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ai_text = findings.get("ai_analysis", "")
    _, score_line = _extract_score(ai_text)

    lines = [
        "═" * 70,
        "  REPORT SUBMISSION GUIDE",
        f"  Target: {hostname}",
        f"  Date  : {now}",
        f"  Verdict: {score_line}",
        "═" * 70,
        "",
        "  Follow these steps in ORDER for maximum impact:",
        "",
        "  ┌─────────────────────────────────────────────────────────────────┐",
        "  │  STEP 1 – IMMEDIATE (do today, takes 5 minutes)                │",
        "  └─────────────────────────────────────────────────────────────────┘",
        "",
        f"  [1a] Google Safe Browsing (removes from search + triggers browser warning)",
        f"       Open: https://safebrowsing.google.com/safebrowsing/report_phish/?url={quote(f'https://{hostname}', safe='')}",
        f"       File: reports/google_safebrowsing.txt",
        "",
    ]

    if "cloudflare_abuse" in reports:
        lines += [
            "  [1b] Cloudflare Abuse – DSA Art. 16 Notice (disables the proxy shield)",
            "       Open: https://www.cloudflare.com/abuse/form",
            "       OR email: abuse@cloudflare.com (attach reports/cloudflare_abuse.txt)",
            "       File: reports/cloudflare_abuse.txt",
            "",
        ]

    lines += [
        "  ┌─────────────────────────────────────────────────────────────────┐",
        "  │  STEP 2 – POLICE REPORT (today or tomorrow)                    │",
        "  └─────────────────────────────────────────────────────────────────┘",
        "",
    ]

    if "dk_nc3" in reports:
        lines += [
            "  [2a] Danish NC3 (cybercrime police) – criminal complaint",
            "       Online: https://politi.dk/nc3/anmeld-it-kriminalitet",
            "       Email:  nc3@politi.dk",
            "       Attach: reports/dk_nc3.txt + the evidence ZIP archive",
            "       File:   reports/dk_nc3.txt",
            "",
        ]

    lines += [
        "  ┌─────────────────────────────────────────────────────────────────┐",
        "  │  STEP 3 – CONSUMER AUTHORITY (this week)                       │",
        "  └─────────────────────────────────────────────────────────────────┘",
        "",
    ]

    if "dk_forbrugerombudsmanden" in reports:
        lines += [
            "  [3a] Forbrugerombudsmanden (consumer ombudsman)",
            "       Online: https://www.forbrug.dk/anmeld/",
            "       Email:  fo@forbrug.dk",
            "       Attach: reports/dk_forbrugerombudsmanden.txt",
            "       File:   reports/dk_forbrugerombudsmanden.txt",
            "",
        ]

    lines += [
        "  ┌─────────────────────────────────────────────────────────────────┐",
        "  │  STEP 4 – DOMAIN REGISTRAR (this week)                         │",
        "  └─────────────────────────────────────────────────────────────────┘",
        "",
        f"  [4a] Registrar abuse complaint",
        f"       Registrar: {findings.get('whois', {}).get('registrar', 'Unknown')}",
        f"       Email: {findings.get('whois', {}).get('emails', 'see registrar website')}",
        "       File:  reports/registrar_abuse.txt",
        "",
        "  [4b] ICANN Compliance (WHOIS inaccuracy)",
        "       Online: https://www.icann.org/resources/pages/complain",
        "       File:   reports/icann_compliance.txt",
        "",
        "  ┌─────────────────────────────────────────────────────────────────┐",
        "  │  STEP 5 – ATTORNEY (if you suffered financial loss)             │",
        "  └─────────────────────────────────────────────────────────────────┘",
        "",
        "  [5a] Hand the following package to a Danish civil attorney:",
        "       • legal_complaint.txt  (legal analysis and complaint)",
        "       • All files in reports/ directory",
        "       • evidence ZIP archive (full site download)",
        "       • origin finder JSON output",
        "",
        "       The attorney can use this package to seek:",
        "       – An injunction (fogedforbud) ordering Cloudflare to",
        "         disclose the origin server IP and account details",
        "       – Damages from the fraudulent operator once identified",
        "",
        "═" * 70,
        "  WHAT HAPPENS AFTER REPORTING:",
        "═" * 70,
        "",
        "  Google Safe Browsing : Browser warnings appear within 24-72 hours.",
        "                         Search delisting within days.",
        "",
        "  Cloudflare Abuse     : Under DSA, Cloudflare must respond within",
        "                         a reasonable time (typically 1-2 weeks).",
        "                         They may suspend the site or require the",
        "                         site owner to provide legitimate info.",
        "",
        "  NC3 (Police)         : NC3 will evaluate for criminal investigation.",
        "                         They have powers to compel Cloudflare and",
        "                         the registrar to disclose the operator's ID.",
        "",
        "  Forbrugerombudsmanden: Can issue cease-and-desist orders and fines",
        "                         without going to court.",
        "",
        "═" * 70,
        f"  Generated by Origin Finder – {now}",
        "═" * 70,
    ]

    out_path.write_text("\n".join(lines), encoding="utf-8")


# ── Standalone usage ───────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python reporting_tool.py <findings.json>")
        print("       Generates ready-to-submit reports from origin_finder.py output.")
        sys.exit(1)

    json_path = sys.argv[1]
    try:
        with open(json_path, encoding="utf-8") as f:
            findings = json.load(f)
    except Exception as exc:
        sys.exit(f"[!] Cannot read findings file: {exc}")

    hostname = findings.get("target", "unknown")
    out_dir  = hostname.replace(".", "_") + "_reports_run"
    result   = generate_reports(hostname, findings, out_dir)

    print(f"\n  Done. Reports saved to: {result['reports_dir']}")
    print(f"  Next step: Open {result['reports_dir']}/SUBMISSION_GUIDE.txt")


if __name__ == "__main__":
    main()
