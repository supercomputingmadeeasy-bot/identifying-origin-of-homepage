# Origin Finder

**Uncover the true identity and origin of any website** — even when it hides behind WHOIS privacy, Cloudflare, CDN proxies, or fake business details.

Origin Finder is a Python reconnaissance toolkit that chains **17 investigation and action modules**, culminating in a GPT-4o AI verdict with two independently scored outputs: a **Site Legitimacy Score** (how trustworthy the site is) and a **Forensic Confidence** percentage (how certain the analyst is of the verdict).

The toolkit is **jurisdiction-agnostic** — it works against any website worldwide. Country-specific compliance modules (currently: Danish market) activate automatically when the relevant signals are detected in the target site.

When a site is identified as suspicious or fraudulent, four companion scripts automatically activate:
- **`law_analyzer.py`** — identifies every applicable law and generates a formal legal complaint
- **`evidence_collector.py`** — downloads the entire website as forensic evidence
- **`reporting_tool.py`** — produces ready-to-submit reports for police, consumer authorities, Cloudflare, and Google
- **`payment_tracer.py`** — identifies the payment processor(s), extracts merchant identifiers, and generates PSP abuse reports and a law-enforcement brief for tracing the perpetrator through the payment channel

---

## Table of Contents

- [Use Cases](#use-cases)
- [How It Works — All 17 Modules](#how-it-works--all-17-modules)
- [Installation](#installation)
- [Usage](#usage)
- [Output](#output)
- [Browse Viewer — Navigating Captured Evidence](#browse-viewer--navigating-captured-evidence)
- [Danish Market Compliance (Section 12)](#danish-market-compliance-section-12)
- [AI Verdict Scoring (Section 13)](#ai-verdict-scoring-section-13)
- [Legal Framework Analysis (Section 14)](#legal-framework-analysis-section-14)
- [Evidence Collection (Section 15)](#evidence-collection-section-15)
- [Electronic Reporting (Section 16)](#electronic-reporting-section-16)
- [Payment Processor Tracing (Section 17)](#payment-processor-tracing-section-17)
- [Digital Fingerprinting — The "Black Site / White Site" Principle](#digital-fingerprinting--the-black-site--white-site-principle)
- [Danish Legislation Reference](#danish-legislation-reference)
- [Requirements](#requirements)
- [Legal & Ethical Use](#legal--ethical-use)

---

## Use Cases

| Scenario | What Origin Finder reveals |
|---|---|
| **Suspected fake shop** targeting any consumer market | Missing business registration, no physical address, IP shared with dozens of grey-market sites |
| **Fake shop** targeting Danish consumers specifically | Missing CVR, failing DK compliance score, verified against virk.dk / cvrapi.dk |
| **Brand impersonation** site | Shared Google Analytics ID links it to the operator's 12 other clones |
| **"Drop-shipping" fraud site** hidden behind Cloudflare | Pre-Cloudflare SSL cert in CT logs reveals the real origin server hostname |
| **Unknown vendor** you want to verify before purchasing | Full compliance score, legitimacy score, AI verdict, live business registry check |
| **OSINT / competitive intelligence** | Technology stack, hosting ASN, all subdomains ever issued a certificate |
| **Building a police complaint** | Violation report + pre-written complaints in relevant language, ready to submit |
| **Preserving digital evidence** | Full site archive (HTML + JS + assets), SHA-256 chain of custody, screenshots |
| **Tracing the perpetrator via payment channel** | Identifies PSP, extracts merchant ID / publishable keys, generates subpoena guidance |

---

## How It Works — All 17 Modules

### 1 · WHOIS Lookup
Queries registrar, registrant name, organisation, country, creation/expiry dates, name servers, email, and DNSSEC status. Detects when WHOIS privacy is active (common on fraudulent sites).

### 2 · DNS Records
Resolves `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, and `SOA` records. MX records often reveal the true email provider (e.g. a Chinese mail server behind a site claiming to be Danish).

### 3 · SSL/TLS Certificate Inspection
Connects directly on port 443 and extracts:
- Subject CN and SAN list (can reveal subdomains or the real operator)
- Issuer organisation (generic Let's Encrypt vs. a named company certificate)
- Validity window

### 4 · Certificate Transparency via crt.sh *(key bypass trick)*
CT logs index **every certificate ever issued** for a domain. Sites that later moved behind Cloudflare often have old certificates that reveal the pre-CDN origin server IP or hostname. Returns up to 80 entries with issuer and log date.

### 5 · HTTP Response Headers
Fetches live headers and extracts:
- `Server`, `X-Powered-By`, `X-Generator` (stack leaks)
- `CF-Ray` (Cloudflare confirmation)
- `X-Forwarded-For`, `X-Real-IP`, `X-Backend-Server` (origin IP leaks)
- `Via`, `X-Cache`, `X-Varnish`, `X-Amz-CF-Id`
- Resolves the actual IP and checks it against known Cloudflare CIDR ranges

### 6 · HTML Source Mining
Parses the full page source for:
- Page title and meta description
- Generator tag (CMS version)
- **Analytics & tracking IDs**: Google Analytics UA/G4, Google Tag Manager, Facebook Pixel, Yandex Metrika, Hotjar
- Email addresses (filtered to remove asset false positives)
- Social media profile handles: Facebook, Instagram, Twitter/X, YouTube, LinkedIn
- Phone numbers
- Copyright strings

### 7 · Technology Fingerprinting
Pattern-matches page source and headers against 24 signatures:

> WordPress, WooCommerce, Shopify, Magento, PrestaShop, OpenCart, Joomla, Drupal, TYPO3, Laravel, Django, Ruby on Rails, Next.js, React, Vue.js, Cloudflare, AWS CloudFront, Akamai, Varnish, Nginx, Apache, PHP, Google Fonts, Bootstrap

### 8 · robots.txt / sitemap.xml
Retrieves and displays `/robots.txt`, `/sitemap.xml`, and `/sitemap_index.xml`. Disallow entries and sitemap structure reveal internal architecture and sometimes the real backend domain.

### 9 · IP WHOIS / ASN / Geolocation
Uses RDAP to resolve the hosting IP's:
- ASN number and organisation name
- Country of registration
- CIDR block

A site claiming to be in Denmark but hosted on a Chinese ASN is a significant red flag.

### 10 · Reverse-IP Lookup
Queries the free [HackerTarget API](https://hackertarget.com/reverse-ip-lookup/) to list all domains sharing the same IP. A cluster of similarly-named grey-market shops on one IP is a strong fraud indicator.

### 11 · Digital Fingerprinting & Cross-Site Identity
See [dedicated section below](#digital-fingerprinting--the-black-site--white-site-principle).

### 12 · Danish Market Compliance
See [dedicated section below](#danish-market-compliance-section-12).

### 13 · AI Synthesis (GPT-4o via GitHub Models)
See [dedicated section below](#ai-verdict-scoring-section-13).

### 14 · Legal Framework Analysis (`law_analyzer.py`)
See [dedicated section below](#legal-framework-analysis-section-14).

### 15 · Evidence Collection (`evidence_collector.py`)
See [dedicated section below](#evidence-collection-section-15).

### 16 · Electronic Reporting (`reporting_tool.py`)
See [dedicated section below](#electronic-reporting-section-16).

### 17 · Payment Processor Tracing (`payment_tracer.py`)
See [dedicated section below](#payment-processor-tracing-section-17).

---

## Installation

### 1. Clone / download

```bash
git clone <repo-url>
cd "Identifying origin of homepage"
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` contains:
```
requests
beautifulsoup4
dnspython
python-whois
ipwhois
openai
```

**Optional** — Shodan favicon hash support:
```bash
pip install mmh3
```

**Optional** — full-page screenshots in `evidence_collector.py`:
```bash
pip install playwright && playwright install chromium
```

### 3. Set your GitHub Token

The AI analysis section requires a GitHub Personal Access Token with **`models:read`** scope (free via GitHub Copilot Pro/Free).

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

Get one at: **GitHub → Settings → Developer settings → Personal access tokens**

---

## Usage

### Full pipeline (recommended)

```bash
# All 17 modules — OSINT + legal analysis + evidence + reports + payment trace
GITHUB_TOKEN=ghp_... python origin_finder.py suspicious-shop.com
```

When the site scores below 60/100 legitimacy or the AI returns HIGH RISK / FRAUDULENT, sections 15, 16, and 17 activate automatically.

### Standalone scripts (run on any existing findings JSON)

```bash
# Re-run legal analysis against a saved findings file
python law_analyzer.py hostname_origin_YYYYMMDD_HHMM.json

# Download the entire site as forensic evidence
python evidence_collector.py https://suspicious-shop.com

# Generate all authority reports
python reporting_tool.py hostname_origin_YYYYMMDD_HHMM.json

# Trace payment processors and generate PSP abuse reports
python payment_tracer.py hostname_origin_YYYYMMDD_HHMM.json
# or directly from a URL (no prior analysis required):
python payment_tracer.py https://suspicious-shop.com
```

### Other options

```bash
# With HTTPS prefix (also accepted)
python origin_finder.py https://example.com

# Without AI analysis (token not set — all other modules still run)
python origin_finder.py suspicious-shop.dk

# Payment tracer standalone — accepts URL or findings JSON
python payment_tracer.py https://suspicious-shop.com
python payment_tracer.py hostname_origin_YYYYMMDD_HHMM.json
```

The tool accepts bare domains, domains with paths, or full URLs. It normalises the input automatically.

---

## Output

All 17 modules print to **stdout** in real time with clear section headers.

After each run, a timestamped output directory is created:

```
hostname_analysis_YYYYMMDD_HHMM/
├── _BROWSE.html                 ← ★ navigable site viewer (open in browser)
├── legal_complaint.txt          ← formal legal complaint (Section 14)
├── reports/
│   ├── SUBMISSION_GUIDE.txt     ← step-by-step filing instructions
│   ├── dk_nc3.txt               ← Danish police complaint (NC3)  [if DK-targeted]
│   ├── dk_forbrugerombudsmanden.txt                              [if DK-targeted]
│   ├── cloudflare_abuse.txt     ← DSA Article 16 notice
│   ├── registrar_abuse.txt
│   ├── google_safebrowsing.txt
│   └── icann_compliance.txt
├── payment_trace/               ← Section 17 output
│   ├── complaint_<psp>.txt      ← ready-to-send abuse complaint per PSP found
│   ├── law_enforcement_payment_brief.txt  ← LE brief with subpoena / MLAT guidance
│   └── payment_trace.json       ← machine-readable findings
└── evidence/                    ← unmodified originals — do not edit
    ├── pages/                   ← all crawled HTML pages
    ├── assets/                  ← all JS, CSS, images
    ├── headers/                 ← HTTP response headers per file
    ├── screenshots/             ← full-page PNGs (if Playwright installed)
    ├── evidence_manifest.txt    ← chain of custody document
    └── manifest.json            ← machine-readable manifest (SHA-256 hashes)
```

> **Evidence integrity:** everything inside `evidence/` is written once and never modified.
> `_BROWSE.html` is a read-only viewer generated *outside* `evidence/` so it cannot contaminate the forensic record.

The raw JSON file is written alongside the directory:
```
hostname_origin_YYYYMMDD_HHMM.json
```

All evidence files are SHA-256 hashed. The manifest and ZIP archive are suitable for direct submission to police, a prosecutor, or an attorney.

### Example stdout structure

```
════════════════════════════════════════════════════════════
  ORIGIN FINDER  –  suspicious-shop.dk
  2026-05-13 09:41 UTC
════════════════════════════════════════════════════════════

────────────────────────────────────────────────────────────
  1 · WHOIS
────────────────────────────────────────────────────────────
  registrar            : NameSilo, LLC
  ...

────────────────────────────────────────────────────────────
  12 · Danish Market Compliance (oplysningspligt)
────────────────────────────────────────────────────────────
  Danish targeting confirmed (4 signals):
    • .dk TLD
    • keyword: mobilepay
    • keyword: inkl. moms
    • Danish characters (æ/ø/å)

  [1] CVR-nummer
    Found: 12345678
    ✓ VERIFIED via cvrapi.dk
      Navn     : Eksempel ApS
      Adresse  : Hovedgade 1, 2100 København Ø
      Status   : NORMAL
  ...

  DK Compliance Score : 45/100  [█████████░░░░░░░░░░░]
  Verdict             : SUSPICIOUS – significant information missing (high risk)

────────────────────────────────────────────────────────────
  13 · AI Analysis (GitHub Copilot Pro / GPT-4o)
────────────────────────────────────────────────────────────
  ...
  SITE LEGITIMACY SCORE: 22/100 – HIGH RISK
  Forensic Confidence: 88%
```

---

## Browse Viewer — Navigating Captured Evidence

Every analysis directory contains `_BROWSE.html` — a self-contained, offline HTML file that lets you navigate the captured site snapshot as if you were browsing it live.

### What it provides

| Panel | Contents |
|---|---|
| **Top header** | Domain, AI legitimacy score (colour-coded), quick links to all reports and evidence |
| **Left sidebar — Captured pages** | Clickable list of every HTML page collected; click to display in the main viewer |
| **Left sidebar — Evidence & reports** | Direct links to `legal_complaint.txt`, chain-of-custody manifest, `manifest.json`, and all authority reports |
| **Left sidebar — Dansk lovgivning** | Direct links to the applicable Danish laws on [retsinformation.dk](https://www.retsinformation.dk/) |
| **Main frame** | Inline iframe showing the selected captured page |

### Opening the viewer

```bash
# Linux / macOS
xdg-open  "hostname_analysis_YYYYMMDD_HHMM/_BROWSE.html"
open      "hostname_analysis_YYYYMMDD_HHMM/_BROWSE.html"

# Or simply double-click _BROWSE.html in your file manager
```

### Regenerating for an existing analysis directory

If you have an older analysis directory without a `_BROWSE.html`, regenerate it without touching the evidence:

```bash
python evidence_collector.py --browse hostname_analysis_YYYYMMDD_HHMM
```

This reads `evidence/manifest.json` (read-only) and writes only `_BROWSE.html` to the analysis directory.

### Evidence integrity guarantee

`_BROWSE.html` is written to the **analysis directory root** — never inside `evidence/`. The files under `evidence/` (pages, assets, headers, manifests) are never modified after collection. SHA-256 hashes in `manifest.json` can be independently verified at any time to confirm the evidence archive is unaltered.

---

## Danish Market Compliance (Section 12)

Section 12 auto-activates when the site shows **any** of the following signals:

| Signal type | Examples |
|---|---|
| TLD | `.dk` domain |
| HTML language | `<html lang="da">`, `hreflang="da"` |
| Danish-only characters | æ, ø, å in page text |
| Currency | `DKK`, `kr.` in prices |
| DK payment methods | MobilePay, Dankort |
| Danish commerce keywords | `fragt`, `levering`, `kurv`, `køb`, `tilbud`, `reklamation`, `kundeservice` |

If none are detected, the section is skipped silently.

### The 7 legal disclosure requirements

Under the Danish E-Commerce Act (*e-handelsloven*), the Marketing Practices Act (*markedsføringsloven*), and the EU Consumer Rights Directive, all businesses marketing to Danish consumers must display:

| # | Requirement | Points | Notes |
|---|---|---|---|
| 1 | **CVR-nummer** | 20 (verified) / 10 (found, unverified) | Looked up live via **cvrapi.dk → virk.dk** |
| 2 | **Fuldt firmanavn** | 15 | Legal suffix required: A/S, ApS, I/S, K/S, P/S, etc. |
| 3 | **Fysisk adresse** | 15 | Danish postal code (1000–9999) required |
| 4 | **Telefonnummer** | 15 | +45 or 8-digit DK format |
| 5 | **E-mailadresse** | 15 | Filtered to remove asset false positives |
| 6 | **Kontaktformular** | 10 | Must have text/email input + submit button |
| 7 | **Sociale medier** | 10 | Facebook, Instagram, X, LinkedIn, YouTube, TikTok |

**Maximum score: 100 points**

### Score thresholds

| Score | Label |
|---|---|
| 80–100 | COMPLIANT — site displays required Danish business information |
| 50–79 | PARTIAL — some required information missing (suspicious) |
| 20–49 | NON-COMPLIANT — significant information missing (high risk) |
| 0–19 | FRAUDULENT INDICATOR — almost none of the required DK business info present |

### CVR Live Verification

When a CVR number is found on the page, it is verified in real time against **cvrapi.dk** (free, no API key required). The returned data includes:

- Registered company name
- Registered address, postcode, city
- Company status (NORMAL / OPLØST / etc.)
- Industry code description
- Number of employees
- Company start date
- Phone and email on file

A mismatch between the CVR-registered name and the site's claimed identity is a major red flag and is surfaced explicitly.

Direct virk.dk link is always printed: `https://virk.dk/virksomhed/cvr/<number>`

---

## AI Verdict Scoring (Section 13)

The AI analysis (GPT-4o via GitHub Models) produces **two separate scores** that answer different questions:

### Site Legitimacy Score (0–100)

> *"How trustworthy is this site to a real consumer?"*

Built from an explicit rubric — the AI cannot pick an arbitrary number:

**Additions:**
- +20 Verified legal entity (CVR / company register confirmed, name matches site)
- +15 Physical address present and matches registered company
- +15 Phone number present and matches country/company
- +10 Email address present and on matching domain
- +10 Working contact form present
- +10 Active, matching social media presence
- +10 Domain age > 2 years with consistent WHOIS history
- +5 SSL certificate issued to the company (not generic)
- +5 No shared-IP neighbours that are known fraud/grey-market sites

**Deductions:**
- −20 CVR missing or unverifiable / does not match site name
- −15 No physical address for a country-targeted site
- −15 WHOIS privacy + no other identifying information
- −10 Site is a near-clone of other known grey-market domains
- −10 Analytics ID shared with known suspicious/fraudulent sites
- −10 IP shared with many unrelated commercial sites (fraud cluster)
- −5 SSL cert issued generically (Cloudflare / Let's Encrypt, no company name)
- −5 No social media presence for a consumer-facing retail site

**Labels:**

| Score | Label |
|---|---|
| 80–100 | LIKELY LEGITIMATE |
| 60–79 | QUESTIONABLE — verify before purchasing |
| 40–59 | SUSPICIOUS — significant trust signals missing |
| 20–39 | HIGH RISK — strong indicators of fraud or impersonation |
| 0–19 | FRAUDULENT — do not engage |

### Forensic Confidence (0–100%)

> *"How certain is the analyst of the verdict, given the available evidence?"*

| % | Meaning |
|---|---|
| 90–100% | Multiple independent signals all point the same way |
| 70–89% | Strong evidence but one or two gaps |
| 50–69% | Moderate evidence; conflicting signals exist |
| < 50% | Thin evidence; assessment is speculative |

These two numbers are intentionally separate. A site can score **15/100 legitimacy** with **92% forensic confidence** — meaning: *"I am 92% sure this site is essentially fraudulent."* This eliminates the ambiguity of a single "confidence" figure.

---

## Legal Framework Analysis (Section 14)

`law_analyzer.py` maps reconnaissance findings to concrete law violations across three jurisdictions.

### Laws covered

| Jurisdiction | Law | Topic |
|---|---|---|
| Denmark | E-handelsloven § 13 | Mandatory online business identification (CVR, address, phone, email) |
| Denmark | Markedsføringsloven §§ 5, 12–14 | Misleading commercial practices; pre-contractual information |
| Denmark | Forbrugeraftaleloven §§ 13–14 | Distance-selling consumer rights |
| Denmark | Straffeloven § 279 | Fraud (bedrageri) — criminal liability |
| Denmark | Straffeloven § 279a | Computer fraud — fraudulent digital transactions |
| EU | Digital Services Act Art. 16 | Illegal-content notice-and-action mechanism (Cloudflare must act) |
| EU | Digital Services Act Art. 17 | Transparency — Cloudflare disclosure under court order |
| EU | Digital Services Act Art. 44 | WHOIS accuracy; privacy services cannot shield illegal operators |
| EU | DSA + Retsplejeloven § 804–806 | Judicial / police order compelling Cloudflare to reveal origin IP |
| EU | Consumer Rights Directive Art. 6 | Pre-contractual information for distance contracts |
| EU | Unfair Commercial Practices Directive | False identity; misleading commercial practices |
| EU | GDPR Arts. 13–14 | Data subject information obligations; tracking without privacy policy |
| EU | E-Commerce Directive Art. 5 | General information requirements for online service providers |
| International | ICANN Registration Data Policy | WHOIS accuracy; registrars must verify and maintain registrant data |
| USA | 18 U.S.C. § 1030 (CFAA) | Cloudflare (US-based) subject to FBI/IC3 requests |

### The Cloudflare origin-disclosure pathway

Section 4 of the generated legal complaint documents the exact legal route to unmask a site hiding behind Cloudflare:

1. **DSA Art. 16 abuse notice** — Cloudflare must act on illegal-content notices
2. **Police request** (Retsplejeloven §§ 804–806) — NC3 can compel subscriber-data disclosure
3. **Civil court injunction** — Danish Maritime & Commercial Court can order origin-IP disclosure
4. **Registrar abuse** — domain suspension via ICANN RAA §§ 3.7.7–3.7.8

The CF-Ray header captured during investigation is recorded in all documents — it ties the investigation timestamp to a specific Cloudflare account in their internal logs.

---

## Evidence Collection (Section 15)

`evidence_collector.py` performs a **read-only forensic crawl** of the target site and preserves everything needed for a criminal or civil case.

### What is collected

| Type | Details |
|---|---|
| HTML pages | Up to 40 pages, BFS crawl following internal links |
| JavaScript files | All `.js`/`.mjs` files — critical for detecting malicious code |
| Stylesheets | All CSS files including imported fonts and images |
| Images & assets | PNG, JPG, SVG, ICO, WOFF, etc. |
| HTTP headers | Full response headers saved per URL (Server, CF-Ray, cookies, etc.) |
| Screenshots | Full-page PNG screenshots via Playwright (optional) |

### Chain of custody

Every file is SHA-256 hashed. The manifest records:
- Original URL
- Save path
- File type
- File size
- SHA-256 hash
- Download timestamp

The entire collection is packaged into a timestamped ZIP archive suitable for submission as digital evidence.

### Automatic trigger threshold

Evidence collection activates automatically when **any** of these conditions are met:
- Site Legitimacy Score **< 60 / 100**
- DK Compliance Score **< 40 / 100**
- AI verdict contains `HIGH RISK` or `FRAUDULENT`

It can also be run standalone against any URL:
```bash
python evidence_collector.py https://suspicious-shop.com
```

---

## Electronic Reporting (Section 16)

`reporting_tool.py` generates formatted complaint documents and a prioritised submission guide.

### Authorities covered

| Authority | Format | Trigger condition |
|---|---|---|
| **Google Safe Browsing** | Pre-filled submission URL | Always |
| **Cloudflare Abuse** (DSA Art. 16) | Email / web form text | Site behind Cloudflare |
| **Domain Registrar Abuse** | Email to registrar abuse contact | Always |
| **ICANN Compliance** | Web form text | WHOIS privacy active |
| **Danish NC3** (police) | Full Danish-language complaint | Danish market targeting |
| **Forbrugerombudsmanden** | Full Danish-language complaint | Danish market targeting |

### SUBMISSION_GUIDE.txt

A master guide is generated with 5 prioritised steps:
1. **Immediate (today)** — Google Safe Browsing + Cloudflare abuse notice
2. **Police report** — NC3 complaint with evidence ZIP
3. **Consumer authority** — Forbrugerombudsmanden complaint
4. **Domain registrar** — abuse email + ICANN compliance
5. **Attorney** — full package handover for injunction / damages

Each step includes the exact URL, email address, and which file to attach.

---

## Payment Processor Tracing (Section 17)

`payment_tracer.py` identifies the payment gateway(s) used by a suspected fraudulent site and produces actionable intelligence for two parallel tracks: **PSP takedown** and **law-enforcement identity disclosure**.

### Why the payment channel matters

Every payment processor that onboards a merchant collects KYC (Know Your Customer) data — legal name, national ID or business registration, bank account, and contact details. This data is retained even after the merchant account is closed. It is therefore the **most reliable path to the real identity of an anonymous fraud site operator**, often succeeding where WHOIS privacy, CDN masking, and offshore hosting make other channels impractical.

### Five tracing techniques

| Technique | What it uncovers |
|---|---|
| **A · Static evidence scan** | Parses all downloaded HTML/JS/headers for payment script fingerprints, publishable keys (`pk_live_*`), merchant IDs, iframe `src`, `form action` URLs |
| **B · Live checkout probe** | Makes live HTTP requests to `/checkout`, `/cart/checkout`, `/payment`, etc. and scans responses + CSP headers for PSP signatures |
| **C · Platform identification** | Matches e-commerce platform fingerprints (Shoplazza, Shopify, WooCommerce, SHOPLINE, Ueeshop, Magento, etc.) which have known built-in PSP relationships |
| **D · Merchant identifier extraction** | Extracts Stripe publishable keys, PayPal `client-id`, Klarna `client_id`, Adyen `merchantAccount`, Nets `checkoutKey`, platform `store_id` |
| **E · Report generation** | Writes a ready-to-send complaint per discovered PSP + a consolidated law-enforcement brief |

### Payment processors in the signature database

| PSP | Key identifier extracted | Complaint destination |
|---|---|---|
| **Stripe** | `pk_live_*` publishable key → reveals connected account | fraud@stripe.com + stripe.com/government-requests |
| **PayPal** | `client-id` → merchant PayPal account | reportfraud@paypal.com |
| **Klarna** | `client_id` | merchant.feedback@klarna.com |
| **Adyen** | `merchantAccount` name | security@adyen.com |
| **Nets Easy** (DK) | `checkoutKey` | fraud@nets.eu |
| **MobilePay** (DK) | merchant ID | support@mobilepay.dk |
| **2Checkout / Verifone** | merchant code | abuse@2checkout.com |
| **Worldpay** | merchant code | fraud.team@worldpay.com |
| **Checkout.com** | public key | fraud@checkout.com |
| **Payoneer** | partner ID | compliance@payoneer.com |
| **Alipay** | app ID | intl-merchant-support@alibaba-inc.com |
| **WeChat Pay** | app ID | wechatpay-support@tencent.com |
| **Shoplazza / AllValue built-in** | `store_id` on platform | abuse@shoplazza.com |

### Law-enforcement brief

`law_enforcement_payment_brief.txt` is a structured document that gives investigators:

1. **All discovered PSP accounts** with the exact identifier (key / merchant ID) that identifies the account
2. **Per-PSP subpoena guidance** — applicable law (ECPA, EU DPF, MLAT treaty), exact legal basis, recommended wording for a court order or police request
3. **Card-scheme escalation contacts** — Visa VAMP, Mastercard MMP (flagging the MID terminates card acceptance across all processors, not just one)
4. **Platform KYC route** — for Chinese SaaS platforms (Shoplazza, SHOPLINE, Ueeshop) where the Chinese operator has national-ID-level KYC on merchants, with guidance on China MLAT / Mutual Legal Assistance procedure
5. **Full OSINT context** injected from the main `origin_finder.py` findings (WHOIS registrar, DNS, SSL, IP ASN, etc.)

### Standalone usage

```bash
# From a URL (performs live checkout probe)
python payment_tracer.py https://suspicious-shop.com

# From a prior analysis JSON (also scans downloaded evidence directory)
python payment_tracer.py hostname_origin_YYYYMMDD_HHMM.json
```

Output is written to `hostname_analysis_YYYYMMDD_HHMM/payment_trace/` (when called via `origin_finder.py`) or to `payment_trace/` in the current directory (standalone).

### Automatic trigger condition

When called from `origin_finder.py`, Section 17 activates automatically whenever the site is flagged as suspicious or fraudulent (same threshold as Sections 15–16). It can always be re-run standalone against any existing findings JSON.

---

## Digital Fingerprinting — The "Black Site / White Site" Principle

> *"What appears on the white site appears on the black site."*

Every identifier embedded in a public page is **identical across every site the same operator runs** — including sites hidden behind fake names, privacy services, or separate domains. Section 11 extracts and cross-references these identifiers.

### 11a — Favicon Hash Fingerprint

The favicon is downloaded and hashed:
- **MD5** → search [BuiltWith Favicon](https://builtwith.com/favicon/)
- **SHA-256** → archive and diff across time
- **Shodan MurmurHash3** (requires `pip install mmh3`) → search all internet-facing servers serving the identical icon: `https://www.shodan.io/search?query=http.favicon.hash:<hash>`

Sites built from the same template or managed by the same operator often share an identical favicon even across completely different brand names.

### 11b — External Resource Domain Map

Every `<script src>`, `<link href>`, `<img src>`, `<iframe src>` pointing to a third-party domain is collected. The unique *combination* of CDN providers, font services, analytics platforms, and payment widgets fingerprints the developer, agency, or template behind the site.

### 11c — Analytics ID Cross-Reference

Each Google Analytics, GTM, Facebook Pixel, Yandex Metrika, or Hotjar ID is **shared across every site the same account holder controls**. The tool:
1. Prints direct links to [SpyOnWeb](https://spyonweb.com/) and [BuiltWith Relationships](https://builtwith.com/relationships/) for each ID
2. Attempts to scrape SpyOnWeb for the list of related domains (no API key required)

### 11d — Content Fingerprint

Visible page text (scripts and styles stripped) is hashed with SHA-256 and MD5. Identical hashes across different domains reveal clones, mirrors, or copy-pasted fraudulent storefronts.

### 11e — Inline JavaScript Hashes

Each inline `<script>` block (no `src` attribute, > 80 chars) is MD5-hashed. Developers copy-paste the same boilerplate across every site they build. These hashes can be searched in Shodan and Censys to find the full deployment footprint.

---

## Danish Legislation Reference

Full text of every applicable law is available free of charge on **[retsinformation.dk](https://www.retsinformation.dk/)** — the official Danish legal information system.

| Law | retsinformation.dk link | Topic |
|---|---|---|
| E-handelsloven | [LBK nr. 1295 af 13/11/2019](https://www.retsinformation.dk/eli/lta/2019/1295) | Mandatory online business identification (§ 13) |
| Markedsføringsloven | [Lov nr. 426 af 03/05/2017](https://www.retsinformation.dk/eli/lta/2017/426) | Prohibition against misleading commercial practices |
| Forbrugeraftaleloven | [LBK nr. 2052 af 24/11/2022](https://www.retsinformation.dk/eli/lta/2022/2052) | Distance-selling consumer rights |
| Straffeloven | [LBK nr. 1360 af 13/10/2023](https://www.retsinformation.dk/eli/lta/2023/1360) | §§ 279–279a: fraud and computer fraud |
| Databeskyttelsesloven | [LOV nr. 502 af 23/05/2018](https://www.retsinformation.dk/eli/lta/2018/1182) | GDPR implementation — data subject rights |
| Retsplejeloven | [LBK nr. 1160 af 19/09/2023](https://www.retsinformation.dk/eli/lta/2023/1160) | §§ 804–806: police orders compelling data disclosure |

Links are also available directly in the sidebar of every generated `_BROWSE.html` viewer.

---

## Requirements

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| requests | any |
| beautifulsoup4 | any |
| dnspython | any |
| python-whois | any |
| ipwhois | any |
| openai | ≥ 1.0 |
| mmh3 *(optional)* | Shodan favicon hash |
| playwright *(optional)* | Screenshots in evidence_collector.py |

**External APIs used (all free, no key required except GitHub Models):**

| Service | Purpose | Key? |
|---|---|---|
| [crt.sh](https://crt.sh) | Certificate Transparency log search | No |
| [HackerTarget](https://hackertarget.com) | Reverse-IP lookup | No |
| [cvrapi.dk](https://cvrapi.dk) | Danish CVR number verification | No |
| [SpyOnWeb](https://spyonweb.com) | Analytics ID cross-reference | No |
| [GitHub Models](https://github.com/marketplace/models) | GPT-4o AI analysis | **Yes** — GitHub PAT |
| [virk.dk](https://virk.dk) | CVR deep-link (browser) | No |
| [Shodan](https://shodan.io) | Favicon hash search (browser link) | No |
| [BuiltWith](https://builtwith.com) | Favicon + analytics cross-ref (browser link) | No |
| [Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/) | Phishing report (browser link, reporting_tool.py) | No |
| [NC3 / Politi.dk](https://politi.dk/nc3/anmeld-it-kriminalitet) | Criminal complaint submission (browser) | No |
| [Forbrug.dk](https://www.forbrug.dk/anmeld/) | Consumer complaint submission (browser) | No |

---

## Legal & Ethical Use

This tool performs **passive, read-only reconnaissance** using only publicly available information:
- Public DNS records
- Public CT logs
- Public WHOIS data
- Publicly accessible HTTP responses (same as any browser)
- Public business registries (virk.dk / cvrapi.dk)

No exploitation, scanning, brute-forcing, or credential testing is performed.

**Use this tool to:**
- Verify a vendor before making a purchase
- Investigate sites reported as fraudulent or impersonating legitimate brands
- Compliance auditing of your own or clients' sites
- OSINT research and journalism
- Build a police complaint or evidence dossier for a suspected fraud site

**Do not use this tool to:**
- Harass or stalk individuals
- Facilitate competitive intelligence that violates terms of service
- Any activity that is unlawful in your jurisdiction

**On legal complaint accuracy:**
The generated legal documents (`legal_complaint.txt`, reports in `reports/`) are produced by automated analysis. Always have a qualified attorney review them before formal submission in a legal proceeding. Law references are correct as of May 2026 but may be superseded by subsequent legislation.
