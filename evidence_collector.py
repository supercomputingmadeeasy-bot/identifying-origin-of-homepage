#!/usr/bin/env python3
"""
evidence_collector.py  –  Digital evidence preservation for suspected fraudulent websites.

If a site is identified as fake or fraudulent, this script downloads the COMPLETE
website for use as forensic evidence:

  • All HTML pages (up to max_pages, following internal links)
  • All JavaScript files (critical for detecting malicious code)
  • All CSS stylesheets
  • All images and other assets
  • Full HTTP response headers for every resource
  • SHA-256 hash of every file (chain of custody)
  • Timestamped ZIP archive with evidence manifest
  • Screenshots of key pages (if Playwright is installed)

The resulting archive and manifest can be submitted directly to:
  police, prosecutor, attorney, or consumer authorities.

Standalone usage:
    python evidence_collector.py <url> [output_dir]
    python evidence_collector.py https://dkoutlet24.com

Called from origin_finder.py (auto-triggered when legitimacy score < 60):
    from evidence_collector import collect_evidence
    collect_evidence(url, hostname, all_findings, out_dir)
"""

import sys
import os
import re
import json
import hashlib
import zipfile
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin, quote
from collections import deque

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
    )
}
TIMEOUT       = 15
MAX_PAGES     = 40       # max HTML pages to crawl
MAX_ASSETS    = 150      # max JS/CSS/image assets to download
MAX_FILE_MB   = 20       # skip individual files larger than this

# Asset types to download
ASSET_EXTENSIONS = {
    ".js", ".mjs", ".jsx",
    ".css",
    ".html", ".htm",
    ".json", ".xml",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".txt",
}

# Extensions to skip when crawling (binaries we don't need for evidence)
SKIP_EXTENSIONS = {
    ".zip", ".gz", ".tar", ".rar", ".7z",
    ".exe", ".dmg", ".pkg", ".deb",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv",
}


# ── Evidence Collector ────────────────────────────────────────────────────────

class EvidenceCollector:

    def __init__(self, base_url: str, hostname: str, out_dir: str):
        self.base_url   = base_url.rstrip("/")
        self.hostname   = hostname
        self.out_dir    = Path(out_dir)
        self.pages_dir  = self.out_dir / "pages"
        self.assets_dir = self.out_dir / "assets"
        self.headers_dir= self.out_dir / "headers"

        for d in (self.pages_dir, self.assets_dir, self.headers_dir):
            d.mkdir(parents=True, exist_ok=True)

        self.session    = requests.Session()
        self.session.headers.update(HEADERS)

        self.visited_pages  : set  = set()
        self.visited_assets : set  = set()
        self.manifest       : list = []    # list of evidence entries
        self.errors         : list = []

    # ── URL helpers ───────────────────────────────────────────────────────────

    def _is_internal(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc in ("", self.hostname) or \
               parsed.netloc.endswith("." + self.hostname)

    def _safe_filename(self, url: str, suffix: str = "") -> str:
        parsed = urlparse(url)
        path   = parsed.path.strip("/") or "index"
        # Keep only safe characters
        path   = re.sub(r"[^\w/.\-]", "_", path)
        if parsed.query:
            qs = re.sub(r"[^\w.\-=&]", "_", parsed.query)[:80]
            path = f"{path}__{qs}"
        if suffix and not path.endswith(suffix):
            path = f"{path}{suffix}"
        return path[:200]   # OS filename length limit

    def _hash_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    # ── Downloader ────────────────────────────────────────────────────────────

    def _fetch(self, url: str) -> tuple:
        """
        Fetch URL.  Returns (response, content_bytes) or (None, None) on error.
        Saves response headers to headers_dir for evidence.
        """
        try:
            r = self.session.get(
                url, timeout=TIMEOUT,
                allow_redirects=True,
                stream=True
            )
            # Size guard
            clen = int(r.headers.get("Content-Length", 0) or 0)
            if clen > MAX_FILE_MB * 1024 * 1024:
                print(f"    [SKIP] {url} – too large ({clen // 1048576} MB)")
                return None, None

            content = b""
            for chunk in r.iter_content(chunk_size=65536):
                content += chunk
                if len(content) > MAX_FILE_MB * 1024 * 1024:
                    print(f"    [SKIP] {url} – exceeded {MAX_FILE_MB} MB")
                    return None, None

            # Save headers as evidence
            hdr_name = re.sub(r"[^\w.\-]", "_", url.replace("https://", "").replace("http://", ""))[:200]
            hdr_path = self.headers_dir / f"{hdr_name}.headers.txt"
            with open(hdr_path, "w", encoding="utf-8") as f:
                f.write(f"REQUEST: GET {url}\n")
                f.write(f"FINAL URL: {r.url}\n")
                f.write(f"STATUS: {r.status_code}\n")
                f.write(f"DATE: {datetime.now(timezone.utc).isoformat()}\n")
                f.write("RESPONSE HEADERS:\n")
                for k, v in r.headers.items():
                    f.write(f"  {k}: {v}\n")

            return r, content

        except Exception as exc:
            self.errors.append({"url": url, "error": str(exc)})
            print(f"    [ERROR] {url}: {exc}")
            return None, None

    def _save_file(self, content: bytes, sub_dir: Path, rel_path: str) -> Path:
        """Save content to sub_dir/rel_path, creating intermediate dirs."""
        dest = sub_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(content)
        return dest

    def _record(self, url: str, dest: Path, content: bytes,
                 file_type: str, status_code: int):
        """Add an entry to the evidence manifest."""
        self.manifest.append({
            "url":         url,
            "saved_as":    str(dest.relative_to(self.out_dir)),
            "type":        file_type,
            "size_bytes":  len(content),
            "sha256":      self._hash_bytes(content),
            "status_code": status_code,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        })

    # ── Link/asset extraction ─────────────────────────────────────────────────

    def _extract_links(self, html: str, page_url: str) -> list:
        """Extract internal page links from HTML."""
        soup  = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            full = urljoin(page_url, href)
            # Strip fragment
            full = full.split("#")[0]
            if self._is_internal(full) and full not in self.visited_pages:
                parsed = urlparse(full)
                ext    = Path(parsed.path).suffix.lower()
                if ext not in SKIP_EXTENSIONS:
                    links.append(full)
        return links

    def _extract_assets(self, html: str, css: str, page_url: str) -> list:
        """Extract JS, CSS, image URLs from HTML and CSS source."""
        soup   = BeautifulSoup(html, "html.parser")
        assets = []

        tag_attrs = [
            ("script",  "src"),
            ("link",    "href"),
            ("img",     "src"),
            ("img",     "data-src"),
            ("img",     "data-lazy-src"),
            ("source",  "src"),
            ("source",  "srcset"),
            ("iframe",  "src"),
            ("video",   "src"),
        ]
        for tag_name, attr in tag_attrs:
            for tag in soup.find_all(tag_name):
                val = tag.get(attr, "").strip()
                if not val or val.startswith(("data:", "javascript:", "#")):
                    continue
                if val.startswith("//"):
                    val = "https:" + val
                full = urljoin(page_url, val)
                ext  = Path(urlparse(full).path).suffix.lower()
                if ext in ASSET_EXTENSIONS or ext in {".js", ".css"}:
                    assets.append(full)

        # Inline style background-image URLs
        for tag in soup.find_all(style=True):
            for m in re.finditer(r'url\(["\']?([^"\')\s]+)["\']?\)', tag["style"]):
                full = urljoin(page_url, m.group(1))
                assets.append(full)

        # CSS url() references
        if css:
            for m in re.finditer(r'url\(["\']?([^"\')\s]+)["\']?\)', css):
                full = urljoin(page_url, m.group(1))
                assets.append(full)

        # All <link rel="stylesheet">
        for tag in soup.find_all("link", rel=lambda r: r and "stylesheet" in r):
            href = tag.get("href", "").strip()
            if href:
                full = urljoin(page_url, href)
                assets.append(full)

        return assets

    # ── Crawl ─────────────────────────────────────────────────────────────────

    def spider(self):
        """
        BFS crawl of the site.  Downloads all pages and their assets.
        Prioritises the homepage, then follows links depth-first up to MAX_PAGES.
        """
        queue = deque([self.base_url])
        print(f"\n  [CRAWL] Starting evidence collection for {self.hostname}")
        print(f"          Max pages: {MAX_PAGES} | Max assets: {MAX_ASSETS}")

        while queue and len(self.visited_pages) < MAX_PAGES:
            page_url = queue.popleft()
            if page_url in self.visited_pages:
                continue
            self.visited_pages.add(page_url)

            print(f"  [PAGE {len(self.visited_pages):02d}] {page_url}")
            r, content = self._fetch(page_url)
            if r is None or content is None:
                continue

            # Save the HTML page
            rel_path = self._safe_filename(page_url, ".html")
            dest     = self._save_file(content, self.pages_dir, rel_path)
            self._record(page_url, dest, content, "page/html", r.status_code)

            try:
                html = content.decode("utf-8", errors="replace")
            except Exception:
                continue

            # Queue new internal links
            links = self._extract_links(html, page_url)
            for link in links:
                if link not in self.visited_pages:
                    queue.append(link)

            # Download assets on this page
            assets = self._extract_assets(html, "", page_url)
            for asset_url in assets:
                self._download_asset(asset_url)

        print(f"\n  [CRAWL] Completed: {len(self.visited_pages)} pages, "
              f"{len(self.visited_assets)} assets, {len(self.errors)} errors")

    def _download_asset(self, url: str):
        """Download a single asset (JS/CSS/image)."""
        if url in self.visited_assets:
            return
        if len(self.visited_assets) >= MAX_ASSETS:
            return
        self.visited_assets.add(url)

        parsed = urlparse(url)
        ext    = Path(parsed.path).suffix.lower()

        # Determine file type label
        if ext in {".js", ".mjs", ".jsx"}:
            ftype = "javascript"
        elif ext == ".css":
            ftype = "stylesheet"
        elif ext in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg"}:
            ftype = "image"
        elif ext in {".json", ".xml"}:
            ftype = "data"
        else:
            ftype = "asset"

        print(f"  [ASSET] {ftype:<12} {url[:80]}")
        r, content = self._fetch(url)
        if r is None or content is None:
            return

        rel_path = self._safe_filename(url)
        if not Path(rel_path).suffix:
            rel_path = rel_path + (ext or ".bin")
        dest = self._save_file(content, self.assets_dir, rel_path)
        self._record(url, dest, content, ftype, r.status_code)

        # If it's a CSS file, also download fonts/images referenced in it
        if ftype == "stylesheet":
            try:
                css_text = content.decode("utf-8", errors="replace")
                css_assets = self._extract_assets("", css_text, url)
                for a in css_assets[:20]:
                    self._download_asset(a)
            except Exception:
                pass

    # ── Screenshot (optional, requires playwright) ────────────────────────────

    def take_screenshots(self):
        """Take screenshots of homepage and key pages if Playwright is available."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("  [SCREENSHOT] Playwright not installed – skipping screenshots.")
            print("               Install with: pip install playwright && playwright install chromium")
            return

        scr_dir = self.out_dir / "screenshots"
        scr_dir.mkdir(exist_ok=True)

        pages_to_capture = list(self.visited_pages)[:5]
        print(f"\n  [SCREENSHOT] Capturing {len(pages_to_capture)} page(s)...")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx     = browser.new_context(viewport={"width": 1280, "height": 900})
            page    = ctx.new_page()

            for i, page_url in enumerate(pages_to_capture):
                try:
                    page.goto(page_url, wait_until="networkidle", timeout=20000)
                    fn   = f"screenshot_{i+1:02d}_{re.sub(r'[^\w]', '_', page_url)[:60]}.png"
                    dest = scr_dir / fn
                    page.screenshot(path=str(dest), full_page=True)
                    sha  = self._hash_bytes(dest.read_bytes())
                    self.manifest.append({
                        "url":      page_url,
                        "saved_as": str(dest.relative_to(self.out_dir)),
                        "type":     "screenshot",
                        "sha256":   sha,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    print(f"  [SCREENSHOT] Saved: {dest.name}")
                except Exception as exc:
                    print(f"  [SCREENSHOT] Failed for {page_url}: {exc}")

            browser.close()

    # ── Manifest & archive ────────────────────────────────────────────────────

    def write_manifest(self, findings: dict) -> Path:
        """
        Write evidence_manifest.txt (chain of custody document)
        and manifest.json (machine-readable).
        """
        now      = datetime.now(timezone.utc)
        txt_path = self.out_dir / "evidence_manifest.txt"
        json_path = self.out_dir / "manifest.json"

        ai_text  = findings.get("ai_analysis", "")
        m = re.search(r"SITE LEGITIMACY SCORE:\s*(\d+)/100[^\n]*", ai_text)
        legitimacy = m.group(0).strip() if m else "N/A"

        lines = [
            "═" * 70,
            "  DIGITAL EVIDENCE MANIFEST – CHAIN OF CUSTODY DOCUMENT",
            "═" * 70,
            f"  Target domain   : {self.hostname}",
            f"  Base URL        : {self.base_url}",
            f"  Collection date : {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"  Collected by    : Origin Finder / evidence_collector.py",
            f"  AI verdict      : {legitimacy}",
            f"  Pages crawled   : {len(self.visited_pages)}",
            f"  Assets saved    : {len(self.visited_assets)}",
            f"  Errors          : {len(self.errors)}",
            f"  Total files     : {len(self.manifest)}",
            "─" * 70,
            "",
            "  LEGAL NOTICE:",
            "  This archive was collected in read-only, non-destructive fashion",
            "  using standard HTTP GET requests, identical to how any browser",
            "  would access the site. All files are in their original form as",
            "  served by the target server. SHA-256 hashes verify file integrity.",
            "",
            "─" * 70,
            "  FILE INVENTORY (URL | SHA-256 | size)",
            "─" * 70,
            "",
        ]

        for entry in self.manifest:
            lines.append(f"  {entry['type']:<12}  {entry.get('sha256','')[:16]}…  "
                         f"{entry.get('size_bytes', 0):>8} B  {entry['url'][:80]}")

        if self.errors:
            lines += [
                "",
                "─" * 70,
                "  FETCH ERRORS (URLs that could not be retrieved):",
                "─" * 70,
            ]
            for err in self.errors:
                lines.append(f"  {err['url']}: {err['error']}")

        lines += [
            "",
            "═" * 70,
            "  END OF MANIFEST",
            "═" * 70,
        ]

        txt_path.write_text("\n".join(lines), encoding="utf-8")
        json_path.write_text(
            json.dumps({"manifest": self.manifest, "errors": self.errors}, indent=2),
            encoding="utf-8"
        )
        return txt_path

    def create_archive(self) -> Path:
        """Zip the entire evidence directory into a single .zip file."""
        now      = datetime.now(timezone.utc)
        zip_name = f"{self.hostname.replace('.','_')}_evidence_{now.strftime('%Y%m%d_%H%M%S')}.zip"
        zip_path = self.out_dir.parent / zip_name

        print(f"\n  [ARCHIVE] Creating evidence ZIP: {zip_path}")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(self.out_dir.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(self.out_dir.parent))

        size_mb = zip_path.stat().st_size / 1048576
        print(f"  [ARCHIVE] Done – {size_mb:.1f} MB  ({len(self.manifest)} files archived)")
        return zip_path


# ── Public entry point ────────────────────────────────────────────────────────

def collect_evidence(url: str, hostname: str,
                     findings: dict, out_dir: str) -> dict:
    """
    Collect full site evidence. Called automatically from origin_finder.py
    when the site is identified as suspicious or fraudulent.

    Returns a summary dict for inclusion in origin_finder's JSON output.
    """
    print(f"\n{'─'*60}")
    print("  15 · Evidence Collection (site download for forensics)")
    print('─'*60)

    # Check if we should run based on AI verdict / compliance score
    ai_text = findings.get("ai_analysis", "")
    score   = findings.get("danish_compliance", {}).get("score", 100)
    is_risky = bool(re.search(r"HIGH RISK|FRAUDULENT|SUSPICIOUS", ai_text, re.I))
    m = re.search(r"SITE LEGITIMACY SCORE:\s*(\d+)/100", ai_text)
    legitimacy_score = int(m.group(1)) if m else 100

    evidence_dir = os.path.join(out_dir, "evidence")

    print(f"\n  Legitimacy score : {legitimacy_score}/100")
    print(f"  DK compliance   : {score}/100")
    print(f"  Risk flag       : {'YES – collecting evidence' if is_risky else 'LOW – collecting anyway (called explicitly)'}")

    collector = EvidenceCollector(url, hostname, evidence_dir)

    # Full crawl + asset download
    collector.spider()

    # Screenshots (optional dependency)
    collector.take_screenshots()

    # Write manifest and create archive
    manifest_path = collector.write_manifest(findings)
    archive_path  = collector.create_archive()

    print(f"\n  ✓ Evidence manifest : {manifest_path}")
    print(f"  ✓ Evidence archive  : {archive_path}")
    print(f"  ✓ Pages collected   : {len(collector.visited_pages)}")
    print(f"  ✓ Assets collected  : {len(collector.visited_assets)}")

    return {
        "pages_collected":   len(collector.visited_pages),
        "assets_collected":  len(collector.visited_assets),
        "errors":            len(collector.errors),
        "evidence_dir":      evidence_dir,
        "manifest":          str(manifest_path),
        "archive":           str(archive_path),
        "file_count":        len(collector.manifest),
    }


# ── Standalone usage ──────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python evidence_collector.py <url> [output_dir]")
        print("       Example: python evidence_collector.py https://dkoutlet24.com")
        sys.exit(1)

    raw_url = sys.argv[1].strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    hostname = urlparse(raw_url).hostname or raw_url
    out_dir  = sys.argv[2] if len(sys.argv) > 2 else hostname.replace(".", "_") + "_evidence_run"

    result = collect_evidence(raw_url, hostname, findings={}, out_dir=out_dir)
    print(f"\n  Done. Archive: {result['archive']}")


if __name__ == "__main__":
    main()
