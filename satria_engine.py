#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SATRIA SQLi Auditor — safe, evidence-based SQL injection assessment.

Scope:
- Same-origin crawling of HTML links and GET forms.
- Baseline stability checks.
- Error/syntax differential checks.
- Boolean-based differential checks (non-extractive).
- Optional low-delay time-based checks (2 seconds; explicitly opt-in).
- URL-encoded metacharacter checks.
- Evidence-backed JSON and HTML reports.

Safety:
- GET requests only. Forms using POST are inventoried but never submitted.
- No login bypass, UNION data extraction, database/table enumeration,
  credential retrieval, destructive statements, stacked queries, or OOB exfiltration.
- Use only on systems for which you have explicit authorization.
"""

from __future__ import annotations

import argparse
import dataclasses
import difflib
import hashlib
import html
import json
import re
import statistics
import sys
import socket
import ipaddress
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import (
    parse_qsl, urlencode, urljoin, urlparse, urlunparse, quote, unquote
)

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as exc:
    raise SystemExit(
        "Dependensi belum tersedia. Jalankan: pip install requests beautifulsoup4"
    ) from exc


VERSION = "1.0.0"
USER_AGENT = f"SATRIA-SQLi-Auditor/{VERSION} (authorized security testing)"
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"PostgreSQL.*ERROR", r"pg_query\(",
    r"pg_exec\(", r"Microsoft SQL Server", r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver", r"Unclosed quotation mark",
    r"Oracle error", r"ORA-\d{4,5}", r"SQLite/JDBCDriver",
    r"SQLite.Exception", r"sqlite3\.OperationalError",
    r"SQLSTATE\[[0-9A-Z]+\]", r"syntax error at or near",
    r"unterminated quoted string", r"Incorrect syntax near",
]
SQL_ERROR_RE = re.compile("|".join(f"(?:{p})" for p in SQL_ERROR_PATTERNS), re.I)
VOLATILE_PATTERNS = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.I), "<UUID>"),
    (re.compile(r"\b20\d{2}-\d{2}-\d{2}[T ][0-9:.+\-Z ]+\b"), "<DATETIME>"),
    (re.compile(r"\b\d{10,13}\b"), "<TIMESTAMP>"),
    (re.compile(r"\bcsrf[^\"'<>:= ]*([\"'<>:= ]+)[a-z0-9_-]{8,}", re.I), "csrf=<TOKEN>"),
]


@dataclasses.dataclass
class ResponseSample:
    url: str
    status: int | None
    elapsed: float
    body: str
    normalized: str
    body_hash: str
    length: int
    content_type: str
    error_signatures: list[str]
    error: str | None = None


@dataclasses.dataclass
class Finding:
    severity: str
    confidence: str
    category: str
    parameter: str
    location: str
    url: str
    title: str
    evidence: dict[str, Any]
    recommendation: str


class SQLiAuditor:
    def __init__(
        self,
        target: str,
        output_dir: Path,
        max_pages: int = 12,
        timeout: float = 8.0,
        delay: float = 0.15,
        verify_tls: bool = True,
        enable_time_probes: bool = False,
        max_requests: int = 250,
    ):
        self.target = self._normalize_url(target)
        self._reject_non_public_target(self.target)
        self.origin = self._origin(self.target)
        self.output_dir = output_dir
        self.max_pages = max(1, min(max_pages, 50))
        self.timeout = max(2.0, min(timeout, 20.0))
        self.delay = max(0.0, min(delay, 2.0))
        self.verify_tls = verify_tls
        self.enable_time_probes = enable_time_probes
        self.max_requests = max(20, min(max_requests, 1000))
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cache-Control": "no-cache",
        })
        self.visited: set[str] = set()
        self.get_forms: list[dict[str, Any]] = []
        self.post_forms: list[dict[str, Any]] = []
        self.vectors: list[dict[str, Any]] = []
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.stats = {
            "pages_fetched": 0, "get_parameters": 0, "get_forms": 0,
            "post_forms_inventoried_not_submitted": 0,
            "requests": 0, "time_probes_enabled": enable_time_probes,
        }

    @staticmethod
    def _normalize_url(url: str) -> str:
        p = urlparse(url.strip())
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Target harus berupa URL http:// atau https:// yang valid.")
        if p.username or p.password:
            raise ValueError("Jangan memasukkan kredensial pada URL target.")
        return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))

    @staticmethod
    def _reject_non_public_target(url: str) -> None:
        host = (urlparse(url).hostname or "").strip("[]").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
            raise ValueError("Target localhost ditolak.")
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise ValueError(f"DNS target tidak dapat diresolusi: {exc}") from exc
        if not addresses:
            raise ValueError("Target tidak memiliki alamat IP yang dapat diresolusi.")
        for address in addresses:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
            if not ip.is_global:
                raise ValueError(f"Target dengan IP non-publik ditolak: {ip}")

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        p = urlparse(url)
        return (p.scheme, (p.hostname or "").lower(), p.port or (443 if p.scheme == "https" else 80))

    def _same_origin(self, url: str) -> bool:
        try:
            return self._origin(url) == self.origin
        except Exception:
            return False

    def _canonical(self, url: str) -> str:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))

    @staticmethod
    def _normalize_body(body: str) -> str:
        value = body[:500_000]
        for pattern, replacement in VOLATILE_PATTERNS:
            value = pattern.sub(replacement, value)
        value = re.sub(r"\s+", " ", value)
        return value.strip()

    def _request(self, url: str, label: str = "request") -> ResponseSample:
        if self.request_count >= self.max_requests:
            raise RuntimeError(f"Batas permintaan tercapai ({self.max_requests}).")
        if not self._same_origin(url):
            raise ValueError("Permintaan lintas-origin ditolak.")
        if self.delay:
            time.sleep(self.delay)
        self.request_count += 1
        started = time.monotonic()
        try:
            response = self.session.get(
                url, timeout=self.timeout, allow_redirects=False,
                verify=self.verify_tls,
            )
            elapsed = time.monotonic() - started
            body = response.text[:500_000]
            normalized = self._normalize_body(body)
            errors = sorted(set(m.group(0)[:120] for m in SQL_ERROR_RE.finditer(body)))[:8]
            return ResponseSample(
                url=url, status=response.status_code, elapsed=elapsed,
                body=body, normalized=normalized,
                body_hash=hashlib.sha256(normalized.encode("utf-8", "ignore")).hexdigest(),
                length=len(body), content_type=response.headers.get("Content-Type", ""),
                error_signatures=errors,
            )
        except requests.RequestException as exc:
            elapsed = time.monotonic() - started
            return ResponseSample(
                url=url, status=None, elapsed=elapsed, body="", normalized="",
                body_hash="", length=0, content_type="", error_signatures=[],
                error=f"{type(exc).__name__}: {exc}",
            )
        finally:
            self.stats["requests"] = self.request_count

    @staticmethod
    def _similarity(a: ResponseSample, b: ResponseSample) -> float:
        if a.status != b.status:
            return 0.0
        return difflib.SequenceMatcher(
            None, a.normalized[:120_000], b.normalized[:120_000], autojunk=False
        ).ratio()

    def _fetch_and_parse(self, url: str) -> list[str]:
        sample = self._request(url, "crawl")
        if sample.error:
            self.errors.append(f"Crawl gagal {url}: {sample.error}")
            return []
        self.stats["pages_fetched"] += 1
        ctype = sample.content_type.lower()
        if "html" not in ctype and "<html" not in sample.body[:1000].lower():
            return []
        soup = BeautifulSoup(sample.body, "html.parser")
        discovered: list[str] = []

        for anchor in soup.find_all("a", href=True):
            absolute = urljoin(url, anchor["href"])
            if self._same_origin(absolute):
                p = urlparse(absolute)
                if p.scheme in ("http", "https"):
                    discovered.append(self._canonical(absolute))

        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            if not self._same_origin(action):
                continue
            method = (form.get("method") or "get").lower()
            fields = []
            for field in form.find_all(["input", "select", "textarea"]):
                name = field.get("name")
                if not name or field.has_attr("disabled"):
                    continue
                typ = (field.get("type") or "").lower()
                if typ in ("submit", "button", "image", "file", "password"):
                    continue
                value = field.get("value", "")
                if field.name == "textarea":
                    value = field.text or ""
                fields.append({"name": name, "value": str(value)[:200], "type": typ or field.name})
            item = {"page": url, "action": self._canonical(action), "method": method, "fields": fields}
            if method == "get":
                self.get_forms.append(item)
                self.stats["get_forms"] += 1
                discovered.append(self._build_url(action, [(f["name"], f["value"]) for f in fields]))
            else:
                # POST bodies may change application state; inventory only.
                self.post_forms.append(item)
                self.stats["post_forms_inventoried_not_submitted"] += 1

        return discovered

    @staticmethod
    def _build_url(url: str, pairs: list[tuple[str, str]]) -> str:
        p = urlparse(url)
        existing = parse_qsl(p.query, keep_blank_values=True)
        merged = existing + pairs
        return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(merged, doseq=True), ""))

    def crawl(self) -> None:
        queue = deque([self.target])
        while queue and len(self.visited) < self.max_pages and self.request_count < self.max_requests:
            url = self._canonical(queue.popleft())
            if url in self.visited:
                continue
            self.visited.add(url)
            print(f"[Discovery] {len(self.visited)}/{self.max_pages} | {url}", flush=True)
            for child in self._fetch_and_parse(url):
                if child not in self.visited and child not in queue and len(self.visited) + len(queue) < self.max_pages * 3:
                    queue.append(child)

        # Build parameter vectors from crawled URLs and the initial target.
        seen: set[tuple[str, str, str]] = set()
        for page in list(self.visited) + [self.target]:
            p = urlparse(page)
            for key, value in parse_qsl(p.query, keep_blank_values=True):
                ident = (self._canonical(urlunparse((p.scheme,p.netloc,p.path,p.params,"",""))), key, "query")
                if ident not in seen:
                    seen.add(ident)
                    self.vectors.append({"url": page, "parameter": key, "value": value, "location": "query"})
        for form in self.get_forms:
            for field in form["fields"]:
                ident = (form["action"], field["name"], "GET form")
                if ident not in seen:
                    seen.add(ident)
                    self.vectors.append({
                        "url": self._build_url(form["action"], [(f["name"], f["value"]) for f in form["fields"]]),
                        "parameter": field["name"], "value": field["value"],
                        "location": "GET form",
                    })
        self.stats["get_parameters"] = len(self.vectors)

    @staticmethod
    def _mutate_parameter(url: str, parameter: str, payload: str) -> str:
        p = urlparse(url)
        pairs = parse_qsl(p.query, keep_blank_values=True)
        replaced = False
        output = []
        for key, value in pairs:
            if key == parameter and not replaced:
                output.append((key, payload))
                replaced = True
            else:
                output.append((key, value))
        if not replaced:
            output.append((parameter, payload))
        return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(output, doseq=True), ""))

    def _baseline(self, url: str) -> tuple[ResponseSample, ResponseSample]:
        first = self._request(url, "baseline-1")
        second = self._request(url, "baseline-2")
        return first, second

    def _add_finding(self, finding: Finding) -> None:
        key = (finding.category, finding.url, finding.parameter, finding.location)
        if not any((f.category, f.url, f.parameter, f.location) == key for f in self.findings):
            self.findings.append(finding)

    def _test_vector(self, vector: dict[str, Any], index: int, total: int) -> None:
        url, param = vector["url"], vector["parameter"]
        print(f"[SQLi] Parameter {index}/{total} | {param} | {vector['location']}", flush=True)
        base1, base2 = self._baseline(url)
        if base1.error or base2.error or base1.status is None or base2.status is None:
            self.errors.append(f"Baseline gagal untuk {url} ({param}).")
            return
        baseline_similarity = self._similarity(base1, base2)
        if baseline_similarity < 0.72:
            print(f"  [Skip] Respons dasar tidak stabil (similarity={baseline_similarity:.2f}).", flush=True)
            return

        original_value = vector.get("value", "")
        if original_value == "":
            original_value = "satria"

        # Syntax/error differential: an isolated quote should not be treated as proof by itself.
        syntax_results = []
        for label, suffix in [("single_quote", "'"), ("double_quote", '"'), ("paired_quote", "''")]:
            probe_url = self._mutate_parameter(url, param, str(original_value) + suffix)
            sample = self._request(probe_url, label)
            syntax_results.append((label, sample))
        errors_found = []
        for label, sample in syntax_results:
            if sample.error_signatures:
                errors_found.extend(sample.error_signatures)
        if errors_found:
            self._add_finding(Finding(
                severity="medium", confidence="indikasi",
                category="SQL syntax/error differential", parameter=param,
                location=vector["location"], url=url,
                title="Respons memunculkan pola pesan kesalahan SQL",
                evidence={
                    "baseline_status": base1.status,
                    "baseline_similarity": round(baseline_similarity, 3),
                    "probe_error_signatures": sorted(set(errors_found))[:8],
                    "note": "Pola error adalah indikasi; belum membuktikan bahwa input dapat mengubah query.",
                },
                recommendation="Periksa query dan parameterisasi di sisi server; verifikasi manual dengan akun dan data uji.",
            ))

        # Boolean differential probes: compare true and false predicates, without extracting rows.
        boolean_pairs = [
            ("single_quote_string", "' AND '1'='1", "' AND '1'='2"),
            ("numeric_predicate", " AND 1=1", " AND 1=2"),
            ("double_quote_string", '" AND "1"="1', '" AND "1"="2'),
        ]
        for family, true_suffix, false_suffix in boolean_pairs:
            true_sample = self._request(self._mutate_parameter(url, param, str(original_value) + true_suffix), family + "-true")
            false_sample = self._request(self._mutate_parameter(url, param, str(original_value) + false_suffix), family + "-false")
            if true_sample.error or false_sample.error or true_sample.status is None or false_sample.status is None:
                continue
            true_base = self._similarity(base1, true_sample)
            false_base = self._similarity(base1, false_sample)
            true_false = self._similarity(true_sample, false_sample)
            length_delta = abs(true_sample.length - false_sample.length)
            status_diff = true_sample.status != false_sample.status
            # Require stable baseline + clear paired differential, not just any changed response.
            if (true_base >= 0.90 and false_base <= 0.82 and true_false <= 0.82) or (
                status_diff and true_base >= 0.90
            ):
                self._add_finding(Finding(
                    severity="high", confidence="kuat — diferensial boolean",
                    category="Boolean-based SQL injection (non-extractive)",
                    parameter=param, location=vector["location"], url=url,
                    title="Pasangan kondisi SQL benar/salah menghasilkan respons berbeda",
                    evidence={
                        "probe_family": family,
                        "baseline_vs_true_similarity": round(true_base, 3),
                        "baseline_vs_false_similarity": round(false_base, 3),
                        "true_vs_false_similarity": round(true_false, 3),
                        "true_status": true_sample.status,
                        "false_status": false_sample.status,
                        "true_false_length_delta": length_delta,
                        "note": "Temuan kuat, tetapi tetap perlu verifikasi karena logika aplikasi dapat memengaruhi respons.",
                    },
                    recommendation="Gunakan prepared statements/parameterized queries; jangan menyusun SQL dengan konkatenasi input.",
                ))
                break

        # Encoded metacharacter differential; this is supporting evidence only.
        encoded = self._request(
            self._mutate_parameter(url, param, str(original_value) + "'"),
            "encoded-apostrophe",
        )
        if encoded.status is not None:
            similarity = self._similarity(base1, encoded)
            if similarity < 0.70 and not encoded.error_signatures:
                self._add_finding(Finding(
                    severity="info", confidence="lemah — perlu verifikasi",
                    category="Encoded metacharacter response differential",
                    parameter=param, location=vector["location"], url=url,
                    title="Input dengan apostrof terenkode mengubah respons",
                    evidence={
                        "baseline_similarity": round(similarity, 3),
                        "encoded_status": encoded.status,
                        "note": "Perubahan respons saja bukan bukti SQL injection.",
                    },
                    recommendation="Periksa decoding berulang, validasi input, dan parameterisasi query.",
                ))

        if self.enable_time_probes:
            self._time_probe(url, param, str(original_value), base1, base2, vector["location"])

    def _time_probe(
        self, url: str, param: str, value: str,
        base1: ResponseSample, base2: ResponseSample, location: str
    ) -> None:
        baseline = statistics.median([base1.elapsed, base2.elapsed])
        # Short, bounded delay payloads. No data retrieval and no stacked statements.
        payloads = [
            ("mysql_sleep", value + "' AND SLEEP(2)-- "),
            ("postgres_sleep", value + "' AND (SELECT pg_sleep(2)) IS NULL-- "),
        ]
        for family, payload in payloads:
            sample = self._request(self._mutate_parameter(url, param, payload), "time-" + family)
            if sample.error or sample.status is None:
                continue
            delta = sample.elapsed - baseline
            if delta >= 1.6:
                self._add_finding(Finding(
                    severity="high", confidence="indikasi kuat — time differential",
                    category="Time-based SQL injection (non-extractive)",
                    parameter=param, location=location, url=url,
                    title="Probe jeda singkat menghasilkan keterlambatan respons",
                    evidence={
                        "probe_family": family,
                        "baseline_median_seconds": round(baseline, 3),
                        "probe_seconds": round(sample.elapsed, 3),
                        "delta_seconds": round(delta, 3),
                        "delay_seconds_requested": 2,
                        "note": "Satu pengukuran belum konklusif; ulangi pada kondisi jaringan stabil sebelum menyatakan terkonfirmasi.",
                    },
                    recommendation="Verifikasi dengan pengukuran berulang dan gunakan prepared statements.",
                ))
                break

    def run(self) -> dict[str, Any]:
        print("=" * 72)
        print("SATRIA SQLi AUDITOR — SAFE / EVIDENCE-BASED")
        print("=" * 72)
        print(f"Target       : {self.target}")
        print(f"Same-origin  : {self.origin}")
        print(f"Max pages    : {self.max_pages}")
        print(f"Max requests : {self.max_requests}")
        print(f"Time probes  : {'ON (2s bounded)' if self.enable_time_probes else 'OFF'}")
        print("Metode       : GET only; POST forms inventoried, never submitted.")
        print("-" * 72, flush=True)

        self.crawl()
        total = len(self.vectors)
        print(f"[Discovery selesai] halaman={self.stats['pages_fetched']} | parameter={total} | POST form tidak dikirim={len(self.post_forms)}", flush=True)
        for index, vector in enumerate(self.vectors, 1):
            if self.request_count >= self.max_requests - 8:
                self.errors.append("Pengujian dihentikan karena mendekati batas permintaan.")
                break
            try:
                self._test_vector(vector, index, total)
            except RuntimeError as exc:
                self.errors.append(str(exc))
                break
            except Exception as exc:
                self.errors.append(f"Kesalahan pada {vector.get('url')} / {vector.get('parameter')}: {type(exc).__name__}: {exc}")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        report = self._make_report()
        json_path = self.output_dir / "satria_sqli_report.json"
        html_path = self.output_dir / "satria_sqli_report.html"
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        html_path.write_text(self._html_report(report), encoding="utf-8")
        print("-" * 72)
        print(f"[Selesai] Requests={self.request_count} | Temuan={len(self.findings)}")
        print(f"[Report JSON] {json_path}")
        print(f"[Report HTML] {html_path}")
        return report

    def _make_report(self) -> dict[str, Any]:
        confirmed = [dataclasses.asdict(f) for f in self.findings if f.confidence.startswith("kuat")]
        return {
            "tool": "SATRIA SQLi Auditor",
            "version": VERSION,
            "scan_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": self.target,
            "scope": {
                "same_origin_only": True,
                "methods_sent": ["GET"],
                "post_forms": "inventoried but not submitted",
                "data_extraction": False,
                "authentication_bypass": False,
                "out_of_band": False,
                "destructive_payloads": False,
            },
            "summary": {
                "findings_total": len(self.findings),
                "strong_boolean_findings": len(confirmed),
                "pages": self.stats["pages_fetched"],
                "vectors": len(self.vectors),
                "requests": self.request_count,
            },
            "coverage": {
                "where_clause_boolean_differential": "tested where GET input vectors exist",
                "visible_sql_errors": "tested with quote perturbations; indicative only",
                "boolean_blind": "tested with paired true/false predicates",
                "time_blind": "tested only when --time-probes is enabled; bounded 2-second delays",
                "union_column_count_and_text_column": "not tested — requires UNION exploitation",
                "database_version_and_schema_enumeration": "not tested — data/schema extraction excluded",
                "login_bypass": "not tested — authentication bypass excluded",
                "out_of_band_and_exfiltration": "not tested — OOB interaction/exfiltration excluded",
                "xml_encoded_filter_bypass": "only URL-encoded apostrophe differential is observed; XML-body exploit not tested",
                "POST_JSON_COOKIE_HEADERS": "not tested; POST forms are inventoried only",
            },
            "stats": self.stats,
            "findings": [dataclasses.asdict(f) for f in self.findings],
            "post_forms_not_submitted": self.post_forms,
            "errors": self.errors,
            "limitations": [
                "No finding does not prove the application is free of SQL injection.",
                "Only discovered same-origin GET query/form parameters are tested.",
                "Authentication-required, multi-step, POST/JSON, cookie/header, and out-of-band paths may be missed.",
                "WAF, caching, rate limiting, dynamic content, and network jitter can affect results.",
                "A strong differential finding should be manually reproduced in an authorized test environment.",
            ],
        }

    @staticmethod
    def _html_report(report: dict[str, Any]) -> str:
        findings = report["findings"]
        rows = []
        for f in findings:
            ev = html.escape(json.dumps(f["evidence"], ensure_ascii=False, indent=2))
            rows.append(
                "<tr>"
                f"<td>{html.escape(f['severity'])}</td>"
                f"<td>{html.escape(f['confidence'])}</td>"
                f"<td>{html.escape(f['category'])}</td>"
                f"<td>{html.escape(f['parameter'])}</td>"
                f"<td><code>{html.escape(f['url'])}</code></td>"
                f"<td>{html.escape(f['title'])}<details><summary>Bukti</summary><pre>{ev}</pre></details></td>"
                "</tr>"
            )
        table = "".join(rows) or '<tr><td colspan="6">Tidak ada temuan yang memenuhi ambang bukti.</td></tr>'
        cov = "".join(
            f"<li><b>{html.escape(k)}:</b> {html.escape(str(v))}</li>"
            for k, v in report["coverage"].items()
        )
        return f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SATRIA SQLi Report</title>
<style>
body{{font:15px/1.55 system-ui,Segoe UI,Arial;margin:28px;color:#172033;background:#f5f7fb}}
main{{max-width:1200px;margin:auto;background:white;padding:28px;border-radius:14px}}
h1{{margin-top:0}} .meta{{color:#536078}} table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #dce2eb;padding:10px;text-align:left;vertical-align:top}} th{{background:#eef2f8}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6fa;padding:10px}}
code{{overflow-wrap:anywhere}} .notice{{padding:12px;background:#fff4d6;border-left:4px solid #d59a00}}
</style></head><body><main>
<h1>SATRIA — SQL Injection Assessment</h1>
<p class="meta">Target: {html.escape(report['target'])}<br>Waktu: {html.escape(report['generated_at'])}</p>
<div class="notice">Laporan ini menggunakan probe non-destruktif. Tidak ada data tabel, kredensial, atau data pengguna yang diekstrak.</div>
<h2>Ringkasan</h2><pre>{html.escape(json.dumps(report['summary'], ensure_ascii=False, indent=2))}</pre>
<h2>Temuan</h2><table><thead><tr><th>Severity</th><th>Confidence</th><th>Kategori</th><th>Parameter</th><th>URL</th><th>Judul / bukti</th></tr></thead>
<tbody>{table}</tbody></table>
<h2>Cakupan pemeriksaan</h2><ul>{cov}</ul>
<h2>Form POST yang tidak dikirim</h2><pre>{html.escape(json.dumps(report['post_forms_not_submitted'], ensure_ascii=False, indent=2))}</pre>
<h2>Keterbatasan dan error</h2><pre>{html.escape(json.dumps({'limitations':report['limitations'],'errors':report['errors']}, ensure_ascii=False, indent=2))}</pre>
</main></body></html>"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pemindai SQLi berbasis bukti dengan probe GET non-destruktif."
    )
    parser.add_argument("target", help="URL target yang secara eksplisit diizinkan untuk diuji")
    parser.add_argument("--out", default="satria_sqli_output", help="Direktori laporan")
    parser.add_argument("--max-pages", type=int, default=12)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--delay", type=float, default=0.15, help="Jeda antar-request")
    parser.add_argument("--max-requests", type=int, default=250)
    parser.add_argument("--time-probes", action="store_true",
                        help="Aktifkan probe time-based dengan delay maksimum 2 detik")
    parser.add_argument("--insecure", action="store_true",
                        help="Nonaktifkan verifikasi TLS (hindari kecuali diperlukan)")
    args = parser.parse_args()

    try:
        auditor = SQLiAuditor(
            target=args.target,
            output_dir=Path(args.out),
            max_pages=args.max_pages,
            timeout=args.timeout,
            delay=args.delay,
            verify_tls=not args.insecure,
            enable_time_probes=args.time_probes,
            max_requests=args.max_requests,
        )
        auditor.run()
        return 0
    except KeyboardInterrupt:
        print("\nDihentikan oleh pengguna.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
