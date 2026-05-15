#!/usr/bin/env python3
"""
origin_finder.py  –  Uncover the true origin of a website
even when protected by WHOIS privacy or Cloudflare/CDN proxies.

Techniques used
───────────────
1. WHOIS lookup
2. DNS records (A / MX / NS / TXT)
3. SSL/TLS certificate inspection (SANs, issuer, CN)
4. Certificate Transparency log search via crt.sh  ← powerful bypass trick
5. HTTP response headers (Server, X-Powered-By, CF-Ray, origin leaks …)
6. HTML source mining (analytics IDs, generator tags, emails, social links)
7. Technology fingerprinting (CMS, framework, CDN)
8. robots.txt / sitemap.xml scanning
9. IP WHOIS / ASN / geolocation
10. Reverse-IP lookup (free HackerTarget API)
11. Digital fingerprinting & cross-site identity (favicon hash, analytics ID cross-ref,
    external resource map, content hash, inline-JS hashes – reveals the hidden network
    of sites run by the same operator: "what appears on the white site appears on the black site")
12. Danish market compliance check (auto-triggered when Danish targeting is detected):
    CVR-nummer verification (cvrapi.dk), fuldt firmanavn, fysisk adresse,
    telefonnummer, e-mailadresse, kontaktformular, sociale medier
    → scored 0-100 and included in the final verdict
13. GitHub Copilot Pro (GPT-4o via GitHub Models) synthesises all findings into a verdict

Usage
─────
    python origin_finder.py <url>

    GITHUB_TOKEN environment variable must be set to a GitHub personal access token
    with Copilot / Models access, or edit API_KEY below.

Example
───────
    GITHUB_TOKEN=ghp_... python origin_finder.py outletsport24.com
"""

import sys
import os
import re
import ssl
import json
import base64
import hashlib
import socket
import textwrap
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin

# ── third-party (install with: pip install requests beautifulsoup4 dnspython python-whois ipwhois openai)
try:
    import requests
    import whois
    import dns.resolver
    import dns.rdatatype
    from bs4 import BeautifulSoup
    from ipwhois import IPWhois
    from openai import OpenAI
except ImportError as e:
    sys.exit(
        f"[!] Missing dependency: {e}\n"
        "    Run:  pip install requests beautifulsoup4 dnspython python-whois ipwhois openai"
    )

# ── Configuration ────────────────────────────────────────────────────────────
API_KEY   = os.getenv("GITHUB_TOKEN", "")   # GitHub PAT with Copilot/Models access
MODEL     = "gpt-4o"
COPILOT_BASE_URL = "https://models.inference.ai.azure.com"
TIMEOUT   = 10   # seconds for HTTP/DNS calls

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}

# Cloudflare IP ranges (abridged – enough to detect CF origin masking)
CF_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13",   "104.24.0.0/14",   "108.162.192.0/18",
    "131.0.72.0/22",   "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13",   "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22","198.41.128.0/17",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def normalise(url: str) -> tuple[str, str]:
    """Return (full_url, bare_hostname)."""
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    hostname = urlparse(url).hostname or url
    return url, hostname


def section(title: str) -> None:
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print('─'*60)


def is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(r) for r in CF_RANGES)
    except ValueError:
        return False


# ── 1. WHOIS ──────────────────────────────────────────────────────────────────

def do_whois(hostname: str) -> dict:
    section("1 · WHOIS")
    findings = {}
    try:
        w = whois.whois(hostname)
        for field in ("registrar", "registrant_name", "org", "country",
                      "creation_date", "expiration_date", "name_servers",
                      "emails", "dnssec"):
            val = getattr(w, field, None)
            if val:
                findings[field] = str(val)
                print(f"  {field:<20}: {val}")
        if not findings:
            print("  [!] WHOIS privacy active – no registrant data returned.")
    except Exception as exc:
        print(f"  [!] WHOIS error: {exc}")
    return findings


# ── 2. DNS records ────────────────────────────────────────────────────────────

def do_dns(hostname: str) -> dict:
    section("2 · DNS Records")
    findings: dict[str, list] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = dns.resolver.resolve(hostname, rtype, raise_on_no_answer=False)
            vals = [r.to_text() for r in answers]
            if vals:
                findings[rtype] = vals
                for v in vals:
                    print(f"  {rtype:<6} {v}")
        except Exception:
            pass
    return findings


# ── 3. SSL certificate ────────────────────────────────────────────────────────

def do_ssl_cert(hostname: str) -> dict:
    section("3 · SSL/TLS Certificate")
    findings = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=TIMEOUT),
            server_hostname=hostname
        ) as s:
            cert = s.getpeercert()

        subject  = dict(x[0] for x in cert.get("subject", []))
        issuer   = dict(x[0] for x in cert.get("issuer", []))
        sans     = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]
        not_after = cert.get("notAfter", "")

        findings["subject_cn"]  = subject.get("commonName", "")
        findings["issuer_org"]  = issuer.get("organizationName", "")
        findings["issuer_cn"]   = issuer.get("commonName", "")
        findings["sans"]        = sans
        findings["valid_until"] = not_after

        print(f"  Subject CN  : {findings['subject_cn']}")
        print(f"  Issuer      : {findings['issuer_org']} / {findings['issuer_cn']}")
        print(f"  Valid until : {not_after}")
        if sans:
            print(f"  SANs ({len(sans)})   : {', '.join(sans[:20])}")
        else:
            print("  No SANs found.")
    except Exception as exc:
        print(f"  [!] SSL error: {exc}")
    return findings


# ── 4. Certificate Transparency via crt.sh  (KEY BYPASS TRICK) ───────────────

def do_crt_sh(hostname: str) -> dict:
    """
    crt.sh indexes every certificate ever issued for a domain via CT logs.
    Even behind Cloudflare, the origin cert – or an *old* cert issued before
    the CDN was added – is often still there and reveals the real hostname,
    hosting IP, or shared-hosting neighbours.
    """
    section("4 · Certificate Transparency (crt.sh) – bypass trick")
    findings = {"certs": []}
    try:
        url = f"https://crt.sh/?q=%25.{hostname}&output=json"
        r = requests.get(url, timeout=TIMEOUT)
        data = r.json()
        seen = set()
        for entry in data[:80]:
            names = entry.get("name_value", "")
            issuer = entry.get("issuer_name", "")
            logged = entry.get("entry_timestamp", "")[:10]
            for name in names.split("\n"):
                name = name.strip().lstrip("*.")
                if name and name not in seen:
                    seen.add(name)
                    findings["certs"].append(
                        {"domain": name, "issuer": issuer, "logged": logged}
                    )
                    print(f"  [{logged}] {name:<45}  via  {issuer[:60]}")
        print(f"\n  → {len(seen)} unique domain/subdomain names found in CT logs")
    except Exception as exc:
        print(f"  [!] crt.sh error: {exc}")
    return findings


# ── 5. HTTP headers ───────────────────────────────────────────────────────────

def do_headers(url: str, hostname: str) -> dict:
    section("5 · HTTP Response Headers")
    findings = {}
    interesting = [
        "server", "x-powered-by", "x-generator", "cf-ray", "x-cache",
        "via", "x-host", "x-real-ip", "x-forwarded-for", "x-origin",
        "x-backend-server", "x-amz-cf-id", "x-varnish", "x-drupal-cache",
        "x-wp-total", "set-cookie", "location",
    ]
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                         allow_redirects=True)
        findings["status_code"]   = r.status_code
        findings["final_url"]     = r.url
        findings["response_time"] = round(r.elapsed.total_seconds(), 2)

        print(f"  Status        : {r.status_code}")
        print(f"  Final URL     : {r.url}")
        for h in interesting:
            val = r.headers.get(h)
            if val:
                findings[f"header_{h}"] = val
                print(f"  {h:<25}: {val}")

        # IP of the server we actually reached
        try:
            ip = socket.gethostbyname(urlparse(r.url).hostname or hostname)
            findings["resolved_ip"] = ip
            cf = is_cloudflare_ip(ip)
            findings["behind_cloudflare"] = cf
            print(f"  Resolved IP   : {ip}  {'← CLOUDFLARE proxy!' if cf else ''}")
        except Exception:
            pass

        return r, findings          # also return response for HTML parsing
    except Exception as exc:
        print(f"  [!] HTTP error: {exc}")
        return None, findings


# ── 6. HTML source mining ─────────────────────────────────────────────────────

def do_html(response) -> dict:
    section("6 · HTML Source Mining")
    findings = {}
    if response is None:
        print("  [!] No response to parse.")
        return findings

    soup = BeautifulSoup(response.text, "html.parser")

    # Title & description
    title = soup.title.string.strip() if soup.title else ""
    desc  = ""
    m = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
    if m:
        desc = m.get("content", "")
    findings["title"] = title
    findings["description"] = desc
    print(f"  Title       : {title}")
    print(f"  Description : {desc[:120]}")

    # Generator tag
    gen = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
    if gen:
        findings["generator"] = gen.get("content", "")
        print(f"  Generator   : {findings['generator']}")

    # Analytics & tracking IDs
    src = response.text
    patterns = {
        "Google Analytics (UA)": r"UA-\d{6,9}-\d{1,3}",
        "Google Analytics (G4)": r"G-[A-Z0-9]{8,}",
        "Google Tag Manager":    r"GTM-[A-Z0-9]{4,8}",
        "Facebook Pixel":        r"fbq\s*\(\s*['\"]init['\"],\s*['\"](\d+)['\"]",
        "Yandex Metrika":        r"ym\(\s*(\d{7,8}),",
        "Hotjar":                r"hjid[:=]\s*(\d+)",
    }
    tracking = {}
    for name, pat in patterns.items():
        hits = re.findall(pat, src)
        if hits:
            tracking[name] = list(set(hits))
            print(f"  {name:<26}: {tracking[name]}")
    findings["tracking_ids"] = tracking

    # Emails in source
    emails = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", src)))
    emails = [e for e in emails if not e.endswith((".png", ".jpg", ".svg", ".css", ".js"))]
    if emails:
        findings["emails"] = emails
        print(f"  Emails      : {emails[:10]}")

    # Social links
    social = {}
    social_patterns = {
        "Facebook":  r"facebook\.com/([A-Za-z0-9_.]+)",
        "Instagram": r"instagram\.com/([A-Za-z0-9_.]+)",
        "Twitter/X": r"(?:twitter|x)\.com/([A-Za-z0-9_]+)",
        "YouTube":   r"youtube\.com/(?:channel|user|c)/([A-Za-z0-9_\-]+)",
        "LinkedIn":  r"linkedin\.com/(?:company|in)/([A-Za-z0-9_\-]+)",
    }
    for platform, pat in social_patterns.items():
        hits = list(set(re.findall(pat, src)))
        if hits:
            social[platform] = hits
            print(f"  {platform:<26}: {hits[:5]}")
    findings["social"] = social

    # Phone numbers
    phones = re.findall(r"(?:\+\d{1,3}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}", src)
    phones = list(set(p.strip() for p in phones if len(p.strip()) >= 8))[:10]
    if phones:
        findings["phones"] = phones
        print(f"  Phones      : {phones}")

    # Copyright text
    copy_hits = re.findall(r"©.*?(?:<|\\n|\n|$)", src)[:5]
    copy_hits = [re.sub(r"<[^>]+>", "", c).strip() for c in copy_hits]
    if copy_hits:
        findings["copyright"] = copy_hits
        print(f"  Copyright   : {copy_hits}")

    return findings


# ── 7. Technology fingerprinting ──────────────────────────────────────────────

def do_tech(response, header_findings: dict) -> dict:
    section("7 · Technology Fingerprinting")
    findings = {"detected": []}
    if response is None:
        return findings

    src = response.text
    headers = {k.lower(): v for k, v in response.headers.items()}

    checks = [
        ("WordPress",      r"wp-content|wp-includes|wp-json"),
        ("WooCommerce",    r"woocommerce|wc-api"),
        ("Shopify",        r"cdn\.shopify\.com|Shopify\.theme"),
        ("Magento",        r"Mage\.Cookies|magento|mage/"),
        ("PrestaShop",     r"prestashop|/modules/"),
        ("OpenCart",       r"catalog/view/theme"),
        ("Joomla",         r"/components/com_"),
        ("Drupal",         r"Drupal\.settings|drupal\.js"),
        ("TYPO3",          r"typo3temp|typo3conf"),
        ("Laravel",        r"laravel_session|Laravel"),
        ("Django",         r"csrfmiddlewaretoken"),
        ("Ruby on Rails",  r"data-turbo|rails-ujs"),
        ("Next.js",        r"__NEXT_DATA__|/_next/static"),
        ("React",          r"__reactFiber|react-dom"),
        ("Vue.js",         r"__vue__|v-bind"),
        ("Cloudflare",     r"cf-ray|cloudflare"),
        ("AWS CloudFront", r"X-Amz-Cf-Id|cloudfront\.net"),
        ("Akamai CDN",     r"akamaized\.net|akamai"),
        ("Varnish Cache",  r"x-varnish"),
        ("Nginx",          r"nginx"),
        ("Apache",         r"apache"),
        ("PHP",            r"\.php|X-Powered-By.*PHP"),
        ("Google Fonts",   r"fonts\.googleapis\.com"),
        ("Bootstrap",      r"bootstrap\.min\.css|bootstrap\.min\.js"),
    ]

    for tech, pat in checks:
        if re.search(pat, src, re.I) or re.search(pat, str(headers), re.I):
            findings["detected"].append(tech)
            print(f"  ✓ {tech}")

    return findings


# ── 8. robots.txt / sitemap ───────────────────────────────────────────────────

def do_robots(url: str) -> dict:
    section("8 · robots.txt / sitemap.xml")
    findings = {}
    base = url.rstrip("/")
    for path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
        try:
            r = requests.get(base + path, headers=HEADERS, timeout=TIMEOUT)
            if r.status_code == 200:
                snippet = r.text[:800]
                findings[path] = snippet
                print(f"\n  [{path}]")
                for line in snippet.splitlines()[:20]:
                    print(f"    {line}")
        except Exception:
            pass
    return findings


# ── 9. IP WHOIS / ASN / geo ───────────────────────────────────────────────────

def do_ip_whois(ip: str) -> dict:
    section("9 · IP WHOIS / ASN / Geolocation")
    findings = {}
    if not ip:
        print("  [!] No IP to look up.")
        return findings
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        asn  = res.get("asn", "")
        desc = res.get("asn_description", "")
        cc   = res.get("asn_country_code", "")
        cidr = res.get("asn_cidr", "")
        findings.update({"asn": asn, "asn_description": desc,
                         "country": cc, "cidr": cidr})
        print(f"  IP          : {ip}")
        print(f"  ASN         : AS{asn}  {desc}")
        print(f"  Country     : {cc}")
        print(f"  CIDR        : {cidr}")
    except Exception as exc:
        print(f"  [!] IP WHOIS error: {exc}")
    return findings


# ── 10. Reverse-IP lookup ─────────────────────────────────────────────────────

def do_reverse_ip(ip: str) -> dict:
    section("10 · Reverse-IP Lookup (HackerTarget)")
    findings = {}
    if not ip:
        return findings
    try:
        r = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=TIMEOUT
        )
        domains = [d.strip() for d in r.text.splitlines() if d.strip() and "error" not in d.lower()]
        findings["co_hosted"] = domains
        print(f"  {len(domains)} domain(s) sharing this IP:")
        for d in domains[:30]:
            print(f"    {d}")
    except Exception as exc:
        print(f"  [!] Reverse-IP error: {exc}")
    return findings


# ── 12. Digital Fingerprinting & Cross-Site Identity ─────────────────────────

def do_fingerprint(url: str, hostname: str, html_findings: dict) -> dict:
    """
    Cross-site identity fingerprinting.

    Core concept  – "what appears on the white site appears on the black site":
    Every unique identifier embedded in a public page (analytics IDs, favicon
    hash, inline JS snippets, CDN patterns) is *identical* on every other site
    the same person or company operates – even sites behind fake identities or
    privacy screens.  Correlating those identifiers across the open web reveals
    the hidden operator network.

    Techniques
    ──────────
    12a. Favicon hash       – MD5 + Shodan MurmurHash3 → find all servers
                              serving the identical icon (same template/operator)
    12b. External resources – map every third-party domain loaded by the page;
                              the unique combo fingerprints the dev/agency
    12c. Analytics cross-ref– every GA / GTM / Pixel / Yandex ID is shared
                              across ALL sites by the same owner; SpyOnWeb &
                              BuiltWith index this publicly
    12d. Content fingerprint– SHA-256 of normalised visible text detects clones
                              and mirrors of the same site
    12e. Inline JS hashes   – inline <script> blocks are often copy-pasted across
                              every site from the same developer; MD5 hashes
                              reveal template authorship
    """
    section("12 · Digital Fingerprinting & Cross-Site Identity")
    findings: dict = {}

    # ── 12a. Favicon fingerprint ──────────────────────────────────────────────
    print("\n  [12a] Favicon hash fingerprint")
    favicon_found = False
    for fav_path in ("/favicon.ico", "/favicon.png", "/apple-touch-icon.png",
                     "/apple-touch-icon-precomposed.png"):
        try:
            r = requests.get(
                url.rstrip("/") + fav_path, headers=HEADERS, timeout=TIMEOUT
            )
            if r.status_code == 200 and len(r.content) > 64:
                md5_hash   = hashlib.md5(r.content).hexdigest()
                sha256_hash = hashlib.sha256(r.content).hexdigest()
                b64_favicon = base64.encodebytes(r.content)
                # Shodan indexes http.favicon.hash using MurmurHash3 of base64
                try:
                    import mmh3  # type: ignore  # pip install mmh3  (optional)
                    shodan_hash = str(mmh3.hash(b64_favicon))
                except ImportError:
                    shodan_hash = None

                findings["favicon"] = {
                    "path":        fav_path,
                    "size_bytes":  len(r.content),
                    "md5":         md5_hash,
                    "sha256":      sha256_hash,
                    "shodan_hash": shodan_hash,
                }
                print(f"  Path         : {fav_path}  ({len(r.content)} bytes)")
                print(f"  MD5          : {md5_hash}")
                print(f"  SHA-256      : {sha256_hash}")
                if shodan_hash:
                    print(f"  Shodan hash  : {shodan_hash}")
                    print(f"  → Shodan     : https://www.shodan.io/search?query=http.favicon.hash%3A{shodan_hash}")
                print(f"  → BuiltWith  : https://builtwith.com/favicon/{md5_hash}")
                print(f"  → FaviconDB  : https://www.faviconanalyzer.com/?url={url.rstrip('/')}{fav_path}")
                favicon_found = True
                break
        except Exception:
            pass
    if not favicon_found:
        print("  (no favicon found)")

    # ── 12b. External resource domain map ────────────────────────────────────
    print("\n  [12b] External resource domains (third-party fingerprint)")
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        soup_ext = BeautifulSoup(r.text, "html.parser")
        ext_domains: set[str] = set()
        tag_attrs = [("script", "src"), ("link", "href"), ("img", "src"),
                     ("img", "data-src"), ("iframe", "src"), ("source", "src")]
        for tag_name, attr in tag_attrs:
            for tag in soup_ext.find_all(tag_name):
                val = tag.get(attr, "")
                if val and (val.startswith("http") or val.startswith("//")):
                    if val.startswith("//"):
                        val = "https:" + val
                    d = urlparse(val).netloc.lower()
                    if d and d != hostname and not d.endswith("." + hostname):
                        ext_domains.add(d)
        findings["external_resource_domains"] = sorted(ext_domains)
        print(f"  {len(ext_domains)} unique third-party domain(s):")
        for d in sorted(ext_domains)[:40]:
            print(f"    {d}")
    except Exception as exc:
        print(f"  [!] Resource domain scan error: {exc}")

    # ── 12c. Analytics ID cross-reference ────────────────────────────────────
    # Each analytics / tracking ID is shared across the entire site portfolio
    # of the same operator.  SpyOnWeb publicly exposes these relationships.
    print("\n  [12c] Analytics ID cross-reference (shared-owner detection)")
    tracking = html_findings.get("tracking_ids", {})
    all_ids: list[tuple[str, str]] = []
    for id_type, ids in tracking.items():
        if isinstance(ids, list):
            all_ids.extend((id_type, i) for i in ids)
        elif ids:
            all_ids.append((id_type, ids))

    if all_ids:
        findings["analytics_crossref"] = {}
        for id_type, tid in all_ids[:6]:
            print(f"\n  [{id_type}]  ID: {tid}")
            spy_url = f"https://spyonweb.com/{tid}"
            bw_url  = f"https://builtwith.com/relationships/tag/{tid}"
            print(f"    → SpyOnWeb : {spy_url}")
            print(f"    → BuiltWith: {bw_url}")
            # Attempt to parse SpyOnWeb results (no API key required)
            try:
                rs = requests.get(spy_url, headers=HEADERS, timeout=TIMEOUT)
                if rs.status_code == 200:
                    spy_soup = BeautifulSoup(rs.text, "html.parser")
                    related: list[str] = []
                    # SpyOnWeb lists domains in various link/list containers
                    for a in spy_soup.select("a[href]"):
                        text = a.get_text(strip=True)
                        href = a.get("href", "")
                        # Keep entries that look like bare domain names
                        if (text and "." in text and len(text) < 80
                                and " " not in text
                                and not text.startswith("http")
                                and tid not in text):
                            related.append(text)
                    related = list(dict.fromkeys(related))[:25]
                    if related:
                        findings["analytics_crossref"][tid] = related
                        print(f"    Related sites via this ID:")
                        for site in related:
                            print(f"      {site}")
                    else:
                        print("    (SpyOnWeb returned no public matches – check manually)")
            except Exception as exc:
                print(f"    (SpyOnWeb lookup failed: {exc})")
    else:
        print("  No analytics/tracking IDs found to cross-reference.")
        print("  Tip: check Google Analytics, GTM, Fb Pixel, Yandex Metrika in page source.")

    # ── 12d. Content fingerprint (clone/mirror detection) ────────────────────
    print("\n  [12d] Page content fingerprint (clone / mirror detection)")
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        clone_soup = BeautifulSoup(r.text, "html.parser")
        for dead in clone_soup(["script", "style", "noscript", "head"]):
            dead.decompose()
        clean_text  = re.sub(r"\s+", " ", clone_soup.get_text()).strip()
        sha256_text = hashlib.sha256(clean_text.encode("utf-8", errors="replace")).hexdigest()
        md5_text    = hashlib.md5(clean_text.encode("utf-8", errors="replace")).hexdigest()
        findings["content_fingerprint"] = {
            "sha256": sha256_text,
            "md5":    md5_text,
            "chars":  len(clean_text),
        }
        print(f"  Visible-text SHA-256 : {sha256_text}")
        print(f"  Visible-text MD5     : {md5_text}")
        print(f"  Char count           : {len(clean_text)}")
        print("  → Use these hashes to find identical/cloned sites via search or Shodan")
    except Exception as exc:
        print(f"  [!] Content fingerprint error: {exc}")

    # ── 12e. Inline JS snippet hashes (developer / agency fingerprint) ────────
    print("\n  [12e] Inline <script> hashes (developer / template fingerprint)")
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        js_soup = BeautifulSoup(r.text, "html.parser")
        inline_blocks = [
            t.get_text(strip=True)
            for t in js_soup.find_all("script")
            if not t.get("src") and len(t.get_text(strip=True)) > 80
        ]
        if inline_blocks:
            js_hashes = [
                {"md5": hashlib.md5(s.encode()).hexdigest(),
                 "length": len(s)}
                for s in inline_blocks[:10]
            ]
            findings["inline_js_hashes"] = js_hashes
            print(f"  {len(inline_blocks)} inline script(s) found:")
            for entry in js_hashes:
                print(f"    MD5: {entry['md5']}  ({entry['length']} chars)")
            print("  → Search these MD5s in Shodan/Censys to find identical deployments")
        else:
            print("  No significant inline scripts found.")
    except Exception as exc:
        print(f"  [!] JS hash error: {exc}")

    return findings


# ── 12. Danish Market Compliance ─────────────────────────────────────────────

# Danish stop-words / market signals
_DA_SIGNALS = [
    r"\binkl\.?\s*moms\b",          # incl. VAT (DK)
    r"\bdkk\b",                      # currency code
    r"(?:kr|dkk)\.?\s*\d",          # price in kr/DKK
    r"\bmobilepay\b",                # DK payment app
    r"\bdankort\b",                  # DK debit card
    r"\bfragt\b",                    # shipping (DA)
    r"\blevering\b",                 # delivery (DA)
    r"\btilbud\b",                   # offer (DA)
    r"\bkurv\b",                     # shopping cart (DA)
    r"\bkøb\b",                      # buy (DA)
    r"\bprisgaranti\b",              # price guarantee (DA)
    r"\bkundeservice\b",             # customer service (DA)
    r"\breklamation\b",              # complaint (DA)
    r"\bforside\b",                  # front page (DA)
    r"\bvirksomhed\b",               # company (DA)
    r"[æøå]",                        # Danish-only characters
]

# Danish phone: +45 XXXXXXXX  or  bare 8-digit starting 2-9
_DK_PHONE_RE = re.compile(
    r"(?:\+45[\s\-]?)?([2-9]\d{7})(?![\d])"
)
# CVR: exactly 8 digits, often preceded by CVR / CVR-nr
_CVR_RE = re.compile(
    r"(?:cvr[\s\-nr.]*|virksomhed[^\d]{0,10})(\d{8})",
    re.I
)
# Danish postal code (1000-9999) optionally followed by city
_DK_POSTAL_RE = re.compile(
    r"\b([1-9]\d{3})\s+([A-ZÆØÅ][a-zæøåA-ZÆØÅ\s]{2,25})"
)
# Legal entity suffixes used in Denmark
_DK_ENTITY_RE = re.compile(
    r"([A-ZÆØÅ][\w\s&æøåÆØÅ.,\-]{2,60}\s(?:A/S|ApS|I/S|K/S|P/S|IVS|SMBA|FMBA|AMBA|Fond|Fonden))",
    re.I
)


def _detect_danish_targeting(hostname: str, text: str, headers: dict) -> list[str]:
    """Return list of signals that indicate the site targets Danish consumers."""
    signals = []
    if hostname.endswith(".dk"):
        signals.append(".dk TLD")
    lang = headers.get("content-language", "")
    if re.search(r"\bda\b", lang, re.I):
        signals.append(f"Content-Language: {lang}")
    if re.search(r'hreflang=["\']?da', text, re.I):
        signals.append("hreflang=da tag")
    if re.search(r'<html[^>]+lang=["\']?da', text, re.I):
        signals.append("HTML lang=da")
    for pat in _DA_SIGNALS:
        if re.search(pat, text, re.I):
            signals.append(f"keyword: {pat.strip(r'\b\?').strip()}")
    return signals


def _lookup_cvr(cvr: str) -> dict:
    """Free cvrapi.dk lookup – no key required for basic queries."""
    try:
        r = requests.get(
            f"https://cvrapi.dk/api?search={cvr}&country=dk",
            headers={**HEADERS, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def do_danish_compliance(url: str, hostname: str, html_findings: dict) -> dict:
    """
    Section 12 – Danish Market Compliance (oplysningspligt / e-handelsloven).

    Businesses that market to Danish consumers are legally required under the
    Danish E-Commerce Act (e-handelsloven), the Marketing Practices Act
    (markedsføringsloven) and the EU Consumer Rights Directive to display:

        1. CVR-nummer          – official Danish company registration number
        2. Fuldt firmanavn     – full legal company name
        3. Fysisk adresse      – physical street address
        4. Telefonnummer       – phone number
        5. E-mailadresse       – email address
        6. Kontaktformular     – working contact form
        7. Sociale medier      – social media links

    A hidden, fraudulent, or impersonating site will often fail most of these.
    Each item is scored; the total forms the *DK Compliance Score* (0-100).

    Score weights
    ─────────────
        CVR (verified)    20 pts   CVR (found, unverified)  10 pts
        Firmanavn         15 pts
        Adresse           15 pts
        Telefon           15 pts
        E-mail            15 pts
        Kontaktformular   10 pts
        Sociale medier    10 pts
    """
    section("12 · Danish Market Compliance (oplysningspligt)")

    findings: dict = {"applicable": False, "signals": [], "checks": {},
                      "score": 0, "score_max": 100, "verdict": ""}

    # ── Fetch main page ───────────────────────────────────────────────────────
    try:
        r_main = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        main_text  = r_main.text
        main_plain = BeautifulSoup(main_text, "html.parser").get_text(" ", strip=True)
        resp_headers = {k.lower(): v for k, v in r_main.headers.items()}
    except Exception as exc:
        print(f"  [!] Could not fetch page: {exc}")
        print("  Skipping Danish compliance check.")
        return findings

    # ── Detect targeting ──────────────────────────────────────────────────────
    signals = _detect_danish_targeting(hostname, main_text, resp_headers)
    findings["signals"] = signals

    # Also try /kontakt page for extra data
    kontakt_text = ""
    for kontakt_path in ("/kontakt", "/contact", "/kontaktformular",
                         "/om-os", "/about", "/impressum"):
        try:
            rk = requests.get(
                url.rstrip("/") + kontakt_path,
                headers=HEADERS, timeout=TIMEOUT, allow_redirects=True
            )
            if rk.status_code == 200 and len(rk.text) > 500:
                kontakt_text += " " + rk.text
        except Exception:
            pass

    full_text = main_text + " " + kontakt_text
    full_plain = BeautifulSoup(full_text, "html.parser").get_text(" ", strip=True)

    if not signals:
        print("  No Danish market targeting detected – check skipped.")
        print("  (Signals looked for: .dk TLD, hreflang=da, Danish keywords, DKK currency)")
        return findings

    findings["applicable"] = True
    print(f"  Danish targeting confirmed ({len(signals)} signal(s)):")
    for s in signals[:8]:
        print(f"    • {s}")

    score = 0
    checks: dict = {}

    # ── 1. CVR-nummer ─────────────────────────────────────────────────────────
    print("\n  [1] CVR-nummer")
    cvr_hits = list(dict.fromkeys(_CVR_RE.findall(full_text)))
    if cvr_hits:
        cvr = cvr_hits[0]
        checks["cvr_found"] = cvr
        print(f"    Found: {cvr}")
        # Verify via cvrapi.dk
        cvr_data = _lookup_cvr(cvr)
        if cvr_data and cvr_data.get("name"):
            checks["cvr_verified"]    = True
            checks["cvr_company"]     = cvr_data.get("name", "")
            checks["cvr_address"]     = cvr_data.get("address", "")
            checks["cvr_zipcode"]     = cvr_data.get("zipcode", "")
            checks["cvr_city"]        = cvr_data.get("city", "")
            checks["cvr_phone"]       = cvr_data.get("phone", "")
            checks["cvr_email"]       = cvr_data.get("email", "")
            checks["cvr_industry"]    = cvr_data.get("industrycode_text", "")
            checks["cvr_employees"]   = cvr_data.get("employees", "")
            checks["cvr_startdate"]   = cvr_data.get("startdate", "")
            checks["cvr_status"]      = cvr_data.get("companystatus", "")
            print(f"    ✓ VERIFIED via cvrapi.dk")
            print(f"      Navn     : {cvr_data.get('name')}")
            print(f"      Adresse  : {cvr_data.get('address')}, "
                  f"{cvr_data.get('zipcode')} {cvr_data.get('city')}")
            print(f"      Status   : {cvr_data.get('companystatus')}")
            print(f"      Branche  : {cvr_data.get('industrycode_text', '')}")
            print(f"    → Virk.dk  : https://virk.dk/virksomhed/cvr/{cvr}")
            score += 20
        else:
            checks["cvr_verified"] = False
            print("    ⚠ Found but could NOT verify via cvrapi.dk")
            print(f"    → Manual check: https://virk.dk/virksomhed/cvr/{cvr}")
            score += 10
    else:
        checks["cvr_found"] = None
        checks["cvr_verified"] = False
        print("    ✗ NOT FOUND – legal requirement for DK businesses")
    checks["cvr_score"] = score  # running total

    # ── 2. Fuldt firmanavn ────────────────────────────────────────────────────
    print("\n  [2] Fuldt firmanavn (legal entity name)")
    # Use CVR-verified name first; fall back to regex on page
    company_name = checks.get("cvr_company", "")
    if not company_name:
        hits = _DK_ENTITY_RE.findall(full_plain)
        if hits:
            company_name = hits[0].strip()
    if company_name:
        checks["company_name"] = company_name
        print(f"    ✓ {company_name}")
        score += 15
    else:
        checks["company_name"] = None
        print("    ✗ No legal entity name (A/S, ApS, I/S …) found in page text")

    # ── 3. Fysisk adresse ─────────────────────────────────────────────────────
    print("\n  [3] Fysisk adresse (physical address)")
    # Try CVR data first
    cvr_addr = ""
    if checks.get("cvr_address"):
        cvr_addr = (f"{checks['cvr_address']}, "
                    f"{checks.get('cvr_zipcode','')} "
                    f"{checks.get('cvr_city','')}")
    postal_hits = _DK_POSTAL_RE.findall(full_plain)
    page_addrs = [f"{z} {c.strip()}" for z, c in postal_hits[:5]]
    if cvr_addr or page_addrs:
        checks["addresses"] = ([cvr_addr] if cvr_addr else []) + page_addrs
        for a in checks["addresses"][:3]:
            print(f"    ✓ {a}")
        score += 15
    else:
        checks["addresses"] = []
        print("    ✗ No Danish postal address detected")

    # ── 4. Telefonnummer ──────────────────────────────────────────────────────
    print("\n  [4] Telefonnummer")
    # Prefer CVR phone, then page
    cvr_phone = checks.get("cvr_phone", "")
    dk_phones  = list(dict.fromkeys(_DK_PHONE_RE.findall(full_plain)))[:5]
    # Also reuse any phones found by do_html
    html_phones = html_findings.get("phones", [])
    all_phones = list(dict.fromkeys(
        ([cvr_phone] if cvr_phone else []) + dk_phones +
        [p for p in html_phones if len(re.sub(r"\D", "", p)) >= 8]
    ))
    if all_phones:
        checks["phones"] = all_phones[:5]
        print(f"    ✓ {all_phones[:3]}")
        score += 15
    else:
        checks["phones"] = []
        print("    ✗ No Danish phone number found")

    # ── 5. E-mailadresse ──────────────────────────────────────────────────────
    print("\n  [5] E-mailadresse")
    emails = html_findings.get("emails", [])
    if not emails:
        emails = list(set(re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            full_plain
        )))[:10]
    # Exclude image / asset false positives
    emails = [e for e in emails
               if not e.lower().endswith((".png",".jpg",".svg",".css",".js"))]
    if emails:
        checks["emails"] = emails[:5]
        print(f"    ✓ {emails[:3]}")
        score += 15
    else:
        checks["emails"] = []
        print("    ✗ No email address found")

    # ── 6. Kontaktformular der virker ────────────────────────────────────────
    print("\n  [6] Kontaktformular (working contact form)")
    form_soup = BeautifulSoup(full_text, "html.parser")
    forms = form_soup.find_all("form")
    # Filter for forms that look like contact forms
    contact_forms = []
    for f in forms:
        form_html = str(f).lower()
        # Has at least a text/email input and a submit
        has_input  = bool(re.search(r'<input[^>]+type=["\']?(text|email)', form_html))
        has_submit = bool(re.search(r'type=["\']?submit|<button', form_html))
        if has_input and has_submit:
            action = f.get("action", "")
            contact_forms.append(action or "(inline form)")
    if contact_forms:
        checks["contact_forms"] = contact_forms[:3]
        print(f"    ✓ {len(contact_forms)} contact form(s) found: {contact_forms[:2]}")
        score += 10
    else:
        checks["contact_forms"] = []
        print("    ✗ No contact form detected")
        # Partial credit: link to /kontakt page
        if re.search(r'href=["\'][^"\']*(kontakt|contact)[^"\']', full_text, re.I):
            checks["contact_page_link"] = True
            print("      (contact page link found – but no form confirmed)")
            score += 5

    # ── 7. Sociale medier ────────────────────────────────────────────────────
    print("\n  [7] Sociale medier (social media links)")
    social = html_findings.get("social", {})
    if not social:
        # Re-check in full text
        soc_patterns = {
            "Facebook":  r"facebook\.com/([A-Za-z0-9_.]+)",
            "Instagram": r"instagram\.com/([A-Za-z0-9_.]+)",
            "Twitter/X": r"(?:twitter|x)\.com/([A-Za-z0-9_]+)",
            "LinkedIn":  r"linkedin\.com/(?:company|in)/([A-Za-z0-9_\-]+)",
            "YouTube":   r"youtube\.com/(?:channel|user|c)/([A-Za-z0-9_\-]+)",
            "TikTok":    r"tiktok\.com/@([A-Za-z0-9_.]+)",
        }
        for platform, pat in soc_patterns.items():
            hits = list(set(re.findall(pat, full_text)))
            if hits:
                social[platform] = hits[:3]
    # Also grab bare social domain links
    social_domains = re.findall(
        r'href=["\'][^"\']*(facebook\.com|instagram\.com|x\.com|twitter\.com'
        r'|linkedin\.com|youtube\.com|tiktok\.com)[^"\']',
        full_text, re.I
    )
    for d in social_domains:
        key = d.split(".")[0].capitalize()
        social.setdefault(key, ["(link found)"])
    if social:
        checks["social_media"] = {k: v for k, v in social.items()}
        for platform, handles in list(social.items())[:5]:
            print(f"    ✓ {platform}: {handles[:2]}")
        score += 10
    else:
        checks["social_media"] = {}
        print("    ✗ No social media links found")

    # ── Final score ───────────────────────────────────────────────────────────
    findings["checks"] = checks
    findings["score"]  = score

    bar  = "█" * (score // 5) + "░" * (20 - score // 5)
    pct  = score
    if score >= 80:
        verdict = "COMPLIANT  – site displays required Danish business information"
    elif score >= 50:
        verdict = "PARTIAL    – some required information missing (suspicious)"
    elif score >= 20:
        verdict = "NON-COMPLIANT – significant information missing (high risk)"
    else:
        verdict = "FRAUDULENT INDICATOR – almost none of the required DK business info present"
    findings["verdict"] = verdict

    print(f"\n  {'─'*58}")
    print(f"  DK Compliance Score : {pct}/100  [{bar}]")
    print(f"  Verdict             : {verdict}")
    print(f"  {'─'*58}")

    return findings


# ── 13. AI synthesis ──────────────────────────────────────────────────────────

def do_ai_analysis(hostname: str, all_findings: dict) -> str:
    section("13 · AI Analysis (GitHub Copilot Pro / GPT-4o)")
    if not API_KEY:
        msg = "  [!] GITHUB_TOKEN not set – skipping AI analysis."
        print(msg)
        return msg

    client = OpenAI(api_key=API_KEY, base_url=COPILOT_BASE_URL)

    system_prompt = textwrap.dedent("""
        You are a digital forensics expert specialising in revealing the true identity
        and origin of websites that hide behind privacy services, Cloudflare, or other
        obfuscation layers.

        Given collected reconnaissance data, produce a structured report with ALL of
        the following numbered sections:

        1. **True Owner / Organisation** – most likely real entity behind the site

        2. **Country of Origin** – where the operation physically runs

        3. **Hosting Infrastructure** – actual servers, CDN, cloud provider

        4. **Technology Stack** – CMS, frameworks, notable software

        5. **Red Flags / Suspicious Indicators** – anything suggesting fraud, grey-market
           retail, dropshipping, brand impersonation, etc.

        6. **Cross-Site Identity Network** – based on shared analytics IDs, favicon hashes,
           and JS fingerprints, list any other domains likely operated by the same entity.

        7. **Danish Compliance** – if the site targets Danish consumers, evaluate the
           DK Compliance Score (0-100) and what the missing items reveal about the operator.
           CVR verification result, company name match, address plausibility.

        8. **SITE LEGITIMACY SCORE: X/100**
           Rate how legitimate and trustworthy this site appears to real consumers.
           This is NOT your confidence in the verdict – it is an assessment of the site itself.

           Scoring rubric (each item adds to the score):
             +20  Verified legal entity (CVR / company register confirmed, name matches site)
             +15  Physical address present and matches registered company
             +15  Phone number present and appears to match the country/company
             +10  Email address present and on matching domain
             +10  Working contact form present
             +10  Active, matching social media presence
             +10  Domain age > 2 years with consistent WHOIS history
             +5   SSL certificate issued to the company (not generic/Cloudflare)
             +5   No shared-IP neighbours that are known fraud/grey-market sites

           Deductions (each item subtracts from the score):
             -20  CVR missing or cannot be verified / does not match site name
             -15  No physical address for a country-targeted site
             -15  WHOIS privacy + no other identifying information
             -10  Site is a near-clone of other known grey-market or fake-shop domains
             -10  Analytics ID shared with known suspicious/fraudulent sites
             -10  IP shared with many unrelated commercial sites (shared hosting fraud cluster)
             -5   SSL cert issued generically (Cloudflare / Let's Encrypt with no company name)
             -5   No social media presence for a consumer-facing retail site

           Output format for this section:
           **SITE LEGITIMACY SCORE: XX/100 – [one-line label]**
           Label must be one of:
             100–80  LIKELY LEGITIMATE
             79–60   QUESTIONABLE – verify before purchasing
             59–40   SUSPICIOUS – significant trust signals missing
             39–20   HIGH RISK – strong indicators of fraud or impersonation
             19–0    FRAUDULENT – do not engage

        9. **Forensic Confidence: X%**
           How certain are YOU (the analyst) of your overall assessment, given the
           quality and completeness of the available evidence?
           - 90–100%  Multiple independent signals all point the same way
           - 70–89%   Strong evidence but one or two gaps
           - 50–69%   Moderate evidence; conflicting signals exist
           - <50%     Thin evidence; assessment is speculative

        10. **Key Evidence** – concise bullet list of the 5-8 most conclusive data points
            that drove both scores above.

        Be direct. Never hedge with "it could be legitimate" without citing a specific
        positive signal from the data. Provide your best assessment even with incomplete data.
    """)

    user_prompt = (
        f"Target domain: {hostname}\n\n"
        f"Reconnaissance data (JSON):\n{json.dumps(all_findings, indent=2, default=str)}"
    )

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=1500,
        )
        analysis = resp.choices[0].message.content
        print(analysis)
        return analysis
    except Exception as exc:
        msg = f"  [!] GitHub Copilot API error: {exc}"
        print(msg)
        return msg


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python origin_finder.py <domain_or_url>")
        sys.exit(1)

    raw_input = sys.argv[1]
    url, hostname = normalise(raw_input)

    print(f"\n{'═'*60}")
    print(f"  ORIGIN FINDER  –  {hostname}")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'═'*60}")

    all_findings: dict = {"target": hostname}

    # Run all reconnaissance modules
    all_findings["whois"]       = do_whois(hostname)
    all_findings["dns"]         = do_dns(hostname)
    all_findings["ssl_cert"]    = do_ssl_cert(hostname)
    all_findings["crt_sh"]      = do_crt_sh(hostname)

    response, h_findings        = do_headers(url, hostname)
    all_findings["headers"]     = h_findings

    all_findings["html"]        = do_html(response)
    all_findings["tech"]        = do_tech(response, h_findings)
    all_findings["robots"]      = do_robots(url)

    ip = h_findings.get("resolved_ip", "")
    all_findings["ip_whois"]    = do_ip_whois(ip)
    all_findings["reverse_ip"]  = do_reverse_ip(ip)
    all_findings["fingerprint"]       = do_fingerprint(url, hostname, all_findings["html"])
    all_findings["danish_compliance"] = do_danish_compliance(url, hostname, all_findings["html"])

    # AI synthesis of all gathered data
    all_findings["ai_analysis"] = do_ai_analysis(hostname, all_findings)

    # Save raw data
    out_file = f"{hostname.replace('.', '_')}_origin_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.json"
    with open(out_file, "w") as f:
        json.dump(all_findings, f, indent=2, default=str)

    print(f"\n{'═'*60}")
    print(f"  Raw data saved to: {out_file}")
    print(f"{'═'*60}\n")

    # ── Post-analysis modules ─────────────────────────────────────────────────
    # Create a shared output directory for all supplementary outputs
    out_dir = f"{hostname.replace('.', '_')}_analysis_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}"

    # ── 14. Legal framework analysis ──────────────────────────────────────────
    try:
        from law_analyzer import run_law_analysis
        all_findings["legal_analysis"] = run_law_analysis(hostname, all_findings, out_dir)
        # Re-save JSON with legal analysis included
        with open(out_file, "w") as f:
            json.dump(all_findings, f, indent=2, default=str)
    except ImportError:
        print("  [!] law_analyzer.py not found in the same directory – skipping legal analysis.")

    # ── 15. Evidence collection (triggered when site is suspicious/fraudulent) ─
    ai_verdict   = all_findings.get("ai_analysis", "")
    m_score      = re.search(r"SITE LEGITIMACY SCORE:\s*(\d+)/100", ai_verdict)
    legitimacy   = int(m_score.group(1)) if m_score else 100
    dk_score     = all_findings.get("danish_compliance", {}).get("score", 100)
    is_suspicious = (
        legitimacy < 60
        or dk_score < 40
        or bool(re.search(r"HIGH RISK|FRAUDULENT", ai_verdict, re.I))
    )

    if is_suspicious:
        print(f"\n  ⚠  Site flagged as suspicious/fraudulent (legitimacy={legitimacy}, dk_score={dk_score})")
        print("     Automatically triggering evidence collection...")
        try:
            from evidence_collector import collect_evidence
            all_findings["evidence_collection"] = collect_evidence(
                url, hostname, all_findings, out_dir
            )
            with open(out_file, "w") as f:
                json.dump(all_findings, f, indent=2, default=str)
        except ImportError:
            print("  [!] evidence_collector.py not found – skipping evidence collection.")
    else:
        print(f"\n  ✓ Site legitimacy score {legitimacy}/100 – evidence collection not triggered.")
        print("     Run manually if needed:  python evidence_collector.py " + url)

    # ── 16. Electronic reporting to authorities ───────────────────────────────
    try:
        from reporting_tool import generate_reports
        all_findings["reports"] = generate_reports(hostname, all_findings, out_dir)
        with open(out_file, "w") as f:
            json.dump(all_findings, f, indent=2, default=str)
    except ImportError:
        print("  [!] reporting_tool.py not found – skipping report generation.")

    # ── 17. Payment processor tracing ────────────────────────────────────────
    try:
        from payment_tracer import run_payment_trace
        ev_dir = Path(out_dir) / "evidence" if is_suspicious else None
        payment_out = Path(out_dir) / "payment_trace"
        all_findings["payment_trace"] = run_payment_trace(
            hostname          = hostname,
            existing_findings = all_findings,
            out_dir           = payment_out,
            evidence_dir      = ev_dir,
            do_live_probe     = True,
        )
        with open(out_file, "w") as f:
            json.dump(all_findings, f, indent=2, default=str)
    except ImportError:
        print("  [!] payment_tracer.py not found – skipping payment trace.")
    except Exception as exc:
        print(f"  [!] Payment trace error: {exc}")

    print(f"\n{'═'*60}")
    print(f"  All outputs saved under : {out_dir}/")
    print(f"  Full JSON               : {out_file}")
    if is_suspicious:
        print(f"  Evidence archive        : {out_dir}/evidence/")
    print(f"  Legal complaint         : {out_dir}/legal_complaint.txt")
    print(f"  Authority reports       : {out_dir}/reports/SUBMISSION_GUIDE.txt")
    print(f"  Payment trace reports   : {out_dir}/payment_trace/")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()
