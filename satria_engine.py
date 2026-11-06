%%writefile satria_engine.py
"""SATRIA WebSec engine — core (struktur dipertahankan dari vuln_pipeline.py v27).

API publik yang dipakai bagian lain di GitHub tetap sama:
    run_pipeline(scrape_data=...)      -> dict hasil
    render_pdf(result, path=...)       -> Path PDF

Integrasi PortSwigger TIDAK mengubah fungsi lama; ia menambah lapisan baru
(katalog lab + lab-scoped detection) yang dipanggil di akhir run_pipeline.

Do not use this scanner against systems without explicit authorization.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from html import unescape as _html_unescape
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup, Comment


# ══════════════════════════════════════════════════════════════════════════════
# KETAHANAN HTTP PORTSWIGGER (juga melindungi fetch awal milik app.py)
# ══════════════════════════════════════════════════════════════════════════════
# app.py mengambil halaman target SEBELUM memanggil run_pipeline(). Karena itu,
# retry di dalam run_pipeline saja tidak cukup. requests.Session.request dipasangi
# wrapper khusus host lab PortSwigger agar requests.get() milik app.py juga retry.
# Hanya metode aman (GET/HEAD/OPTIONS) yang diulang; POST/PUT/DELETE tidak pernah.

_SATRIA_PORTSWIGGER_RETRY_STATUSES = {408, 425, 429, 500, 502, 503, 504}
_SATRIA_PORTSWIGGER_HOST_SUFFIX = ".web-security-academy.net"

def _satria_is_portswigger_lab_url(url: Any) -> bool:
    try:
        host = (urlparse(str(url)).hostname or "").lower().rstrip(".")
        return host == "web-security-academy.net" or host.endswith(_SATRIA_PORTSWIGGER_HOST_SUFFIX)
    except Exception:
        return False

def _satria_retry_request(original_request, session, method, url, kwargs):
    method_u = str(method or "GET").upper()
    if method_u not in {"GET", "HEAD", "OPTIONS"} or not _satria_is_portswigger_lab_url(url):
        return original_request(session, method, url, **kwargs)

    try:
        attempts = int(os.getenv("SATRIA_PORTSWIGGER_HTTP_ATTEMPTS", "4"))
    except (TypeError, ValueError):
        attempts = 4
    attempts = max(1, min(attempts, 6))
    last_error = None

    for attempt in range(attempts):
        try:
            response = original_request(session, method, url, **kwargs)
            status = int(getattr(response, "status_code", 0) or 0)
            if status not in _SATRIA_PORTSWIGGER_RETRY_STATUSES or attempt >= attempts - 1:
                return response

            # Tutup koneksi respons gagal sebelum mencoba ulang.
            try:
                response.close()
            except Exception:
                pass

            retry_after = None
            try:
                retry_after = int(float(response.headers.get("Retry-After", "")))
            except (TypeError, ValueError, AttributeError):
                pass
            delay = retry_after if retry_after is not None else min(8.0, 1.5 * (2 ** attempt))
            time.sleep(max(0.5, min(float(delay), 15.0)))
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            last_error = exc
            if attempt >= attempts - 1:
                raise
            time.sleep(min(8.0, 1.5 * (2 ** attempt)))

    if last_error is not None:
        raise last_error
    raise requests.exceptions.RequestException("Permintaan PortSwigger gagal tanpa respons yang dapat digunakan.")

# Idempotent: aman pada Streamlit rerun / import ulang.
_SATRIA_ORIGINAL_SESSION_REQUEST = requests.sessions.Session.request
if not getattr(_SATRIA_ORIGINAL_SESSION_REQUEST, "_satria_portswigger_retry", False):
    def _satria_session_request_with_retry(self, method, url, **kwargs):
        return _satria_retry_request(
            _SATRIA_ORIGINAL_SESSION_REQUEST, self, method, url, kwargs
        )
    _satria_session_request_with_retry._satria_portswigger_retry = True
    _satria_session_request_with_retry._satria_original = _SATRIA_ORIGINAL_SESSION_REQUEST
    requests.sessions.Session.request = _satria_session_request_with_retry

try:
    from jinja2 import Environment, select_autoescape
except Exception:                                    # pragma: no cover
    Environment = None
    select_autoescape = None

try:
    from weasyprint import HTML
except Exception:                                    # pragma: no cover
    HTML = None

try:
    from publicsuffix2 import get_sld
except Exception:                                    # pragma: no cover
    get_sld = None

# ══════════════════════════════════════════════════════════════════════════════
# KONFIGURASI
# ══════════════════════════════════════════════════════════════════════════════
KIOSAPI_BASE_URL = "https://kiosapi.com/v1"
ARTIFACTS_DIR = Path("artifacts")
SCRAPE_PATH = "artifacts/scrape_result.json"
FINDINGS_PATH = "artifacts/findings.json"
OUTPUT_PDF = "artifacts/laporan_kerentanan.pdf"

MODEL_PRIMARY = os.getenv("KIOSAPI_MODEL", "qwen/qwen3-30b").strip()
MODEL_FALLBACKS = [
    os.getenv("KIOSAPI_MODEL_FALLBACK_1", "zai/glm-4.7-flash").strip(),
    os.getenv("KIOSAPI_MODEL_FALLBACK_2", "meta/llama-3.1-8b").strip(),
]
MODEL_FALLBACKS = [m for m in MODEL_FALLBACKS if m and m != MODEL_PRIMARY]

MAX_AGENT_ITERATIONS = 25
MAX_TOKENS_LLM = 16384
KIOSAPI_MAX_OUTPUT_TOKENS = max(256, int(os.getenv("KIOSAPI_MAX_OUTPUT_TOKENS", "2048")))
KIOSAPI_MAX_PROMPT_CHARS = max(4000, int(os.getenv("KIOSAPI_MAX_PROMPT_CHARS", "18000")))
MAX_PARSED_CHARS = 300000
MAX_RAW_HTML_FOR_VERIFICATION = 600000

NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CENSYS_BASE_V3 = "https://api.platform.censys.io/v3"
SLEEP_BETWEEN_NVD = 3.0
CENSYS_RATE_SLEEP = 1.0
REQUEST_TIMEOUT = 20

ENABLE_LLM = os.getenv("SATRIA_ENABLE_LLM", "0").strip() in {"1", "true", "yes"}
RUN_CENSYS = os.getenv("SATRIA_RUN_CENSYS", "0").strip() in {"1", "true", "yes"}
RUN_NVD = os.getenv("SATRIA_RUN_NVD", "0").strip() in {"1", "true", "yes"}
RUN_ACTIVE_TOOLS = True
ACTIVE_SCAN_AUTHORIZED = False       # gate eksplisit; tidak pernah diaktifkan otomatis
ALLOW_PARTIAL_TOOLS = True

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_UNKNOWN_VERSION_TOKENS = {"", "unknown", "n/a", "na", "none", "undefined", "null", "-"}

CVE_SEARCH_AUDIT: list[dict[str, Any]] = []
OSV_LOOKUP_STATUS: dict[str, str] = {}
HTML_SOURCE_METADATA: dict[str, Any] = {
    "html_source_field": "unknown",
    "html_source_is_full_dom": None,
    "html_source_note": "Metadata sumber HTML belum tersedia.",
}


def _load_kiosapi_api_key() -> str:
    key = os.getenv("KIOSAPI_API_KEY", "").strip()
    if key:
        return key
    try:
        from google.colab import userdata  # type: ignore
        return str(userdata.get("KIOSAPI_API_KEY") or "").strip()
    except Exception:
        return ""


def _load_censys_api_token() -> str:
    token = os.getenv("CENSYS_API_TOKEN", "").strip()
    if token:
        return token
    try:
        from google.colab import userdata  # type: ignore
        return str(userdata.get("CENSYS_API_TOKEN") or "").strip()
    except Exception:
        return ""


KIOSAPI_API_KEY = _load_kiosapi_api_key()
CENSYS_PAT = _load_censys_api_token()


def _is_known_version(ver: Optional[str]) -> bool:
    if ver is None:
        return False
    return str(ver).strip().lower() not in _UNKNOWN_VERSION_TOKENS


def confirm_active_scan_authorization() -> bool:
    """Minta konfirmasi eksplisit sebelum request aktif dikirim ke target."""
    global ACTIVE_SCAN_AUTHORIZED
    if ACTIVE_SCAN_AUTHORIZED:
        return True
    if not RUN_ACTIVE_TOOLS:
        return False
    print("\n[AUTHORIZATION GATE] Active scan membutuhkan izin eksplisit.")
    print("Hanya lanjutkan bila Anda pemilik sistem atau punya izin tertulis.")
    try:
        token = input("Ketik SAYA MEMILIKI IZIN untuk mengaktifkan probe aktif: ").strip()
    except Exception:
        token = ""
    ACTIVE_SCAN_AUTHORIZED = token == "SAYA MEMILIKI IZIN"
    if not ACTIVE_SCAN_AUTHORIZED:
        print("[AUTHORIZATION GATE] Ditolak; probe aktif dilewati, audit pasif tetap jalan.")
    return ACTIVE_SCAN_AUTHORIZED


def active_probe_enabled() -> bool:
    return bool(RUN_ACTIVE_TOOLS and ACTIVE_SCAN_AUTHORIZED)


# ══════════════════════════════════════════════════════════════════════════════
# Utility URL & scope  (FIX #7 — scope konservatif)
# ══════════════════════════════════════════════════════════════════════════════
def normalize_url(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"URL target tidak valid: {value!r}")
    return value


def _safe_request_url(url: str) -> str:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    if parsed.username or parsed.password:
        raise ValueError("URL tidak boleh memuat kredensial username/password.")
    return normalized


def _slugify(url: str) -> str:
    try:
        host = urlparse(normalize_url(url)).hostname or "target"
    except Exception:
        host = "target"
    return re.sub(r"[^a-zA-Z0-9.-]+", "_", host).strip("_") or "target"


def _registrable_domain(hostname: str) -> str:
    hostname = (hostname or "").lower().strip().rstrip(".")
    if not hostname:
        return ""
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    if get_sld is not None:
        try:
            sld = get_sld(hostname)
            if sld:
                return sld.lower()
        except Exception:
            pass
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def split_in_scope_targets(targets: list[str], base_url: str) -> tuple[list[str], list[str]]:
    """Scope konservatif: hostname target + subdomain di bawahnya. IP hanya bila target awal IP sama."""
    try:
        base_host = (urlparse(normalize_url(base_url)).hostname or "").lower().rstrip(".")
    except Exception:
        base_host = ""
    if not base_host:
        return [], sorted({str(t).strip() for t in targets if str(t).strip()})
    try:
        base_ip = ipaddress.ip_address(base_host)
    except ValueError:
        base_ip = None

    in_scope: set[str] = {base_host}
    out_scope: set[str] = set()
    for raw in targets or []:
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            if "://" in text:
                host = urlparse(text).hostname or ""
            else:
                host = text.split("/", 1)[0].split(":", 1)[0]
            host = host.strip().strip("[]").lower().rstrip(".")
            if not host:
                continue
            try:
                ip_obj = ipaddress.ip_address(host)
                if base_ip is not None and ip_obj == base_ip:
                    in_scope.add(host)
                else:
                    out_scope.add(host)
                continue
            except ValueError:
                pass
            if base_ip is None and (host == base_host or host.endswith("." + base_host)):
                in_scope.add(host)
            else:
                out_scope.add(host)
        except Exception:
            out_scope.add(text)

    out_scope.difference_update(in_scope)
    return sorted(in_scope), sorted(out_scope)


# ══════════════════════════════════════════════════════════════════════════════
# FIX #8 — Persistensi hasil scraping sebagai file .html (sumber kebenaran)
# ══════════════════════════════════════════════════════════════════════════════
def persist_scrape_artifacts(scrape: dict[str, Any]) -> dict[str, Path]:
    data = scrape.get("data", scrape) if isinstance(scrape, dict) else {}
    html_source_field = "html" if isinstance(data.get("html"), str) and data.get("html").strip() else (
        "html-llm" if isinstance(data.get("html-llm"), str) and data.get("html-llm").strip() else "missing"
    )
    html = data.get("html") or data.get("html-llm") or ""
    md = data.get("markdown") or data.get("markdown-llm") or ""
    if not html.strip():
        raise RuntimeError("Scraper tidak mengembalikan HTML. Tidak membuat laporan tanpa bukti HTML.")
    meta = scrape.get("meta", {}) if isinstance(scrape.get("meta", {}), dict) else {}
    url = meta.get("url") or scrape.get("url") or "unknown"
    try:
        url = normalize_url(url) if url != "unknown" else url
    except ValueError:
        pass

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    slug = _slugify(url)
    html_path = ARTIFACTS_DIR / f"scrape_{slug}.html"
    md_path = ARTIFACTS_DIR / f"scrape_{slug}.md"
    meta_path = ARTIFACTS_DIR / f"scrape_{slug}.meta.json"

    html_path.write_text(html, encoding="utf-8")
    if md:
        md_path.write_text(md, encoding="utf-8")
    meta_path.write_text(json.dumps({
        "url": url, "meta": meta,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "html_chars": len(html), "markdown_chars": len(md),
        "html_source_field": html_source_field,
        "html_source_is_full_dom": html_source_field == "html",
        "html_sha256": hashlib.sha256(html.encode("utf-8", "ignore")).hexdigest(),
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"      [Persist] HTML: {html_path} ({len(html):,} chars; field={html_source_field})")
    return {"html": html_path, "markdown": md_path, "meta": meta_path}


def load_scrape_html(html_path: Path) -> tuple[str, str]:
    global HTML_SOURCE_METADATA
    html_path = Path(html_path)
    if not html_path.exists():
        print(f"\n[!] ERROR: file scraping tidak ditemukan: {html_path}")
        sys.exit(1)
    html = html_path.read_text(encoding="utf-8")
    meta_path = html_path.with_name(html_path.name.replace(".html", ".meta.json"))
    target_url = "unknown"
    metadata: dict[str, Any] = {}
    if meta_path.exists():
        try:
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            target_url = metadata.get("url", "unknown")
        except Exception as exc:
            metadata = {"metadata_read_error": str(exc)[:200]}
    HTML_SOURCE_METADATA = {
        "html_source_field": metadata.get("html_source_field", "unknown"),
        "html_source_is_full_dom": metadata.get("html_source_is_full_dom"),
        "html_source_note": metadata.get("html_source_note", "Metadata fidelity HTML tidak tercatat."),
        "html_sha256": metadata.get("html_sha256", ""),
        "html_chars": metadata.get("html_chars", len(html)),
    }
    return html, target_url


# ══════════════════════════════════════════════════════════════════════════════
# Audit HTTP pasif
# ══════════════════════════════════════════════════════════════════════════════
HEADER_CHECKS = [
    ("content-security-policy", "Missing Content-Security-Policy", "medium",
     "CSP tidak terdeteksi pada respons aplikasi yang diuji.",
     "Terapkan CSP dan uji dalam Report-Only sebelum penegakan."),
    ("strict-transport-security", "Missing HSTS", "low",
     "Strict-Transport-Security tidak terdeteksi pada respons HTTPS.",
     "Aktifkan HSTS setelah seluruh subdomain siap."),
    ("x-content-type-options", "Missing X-Content-Type-Options", "low",
     "X-Content-Type-Options tidak terdeteksi.",
     "Atur X-Content-Type-Options: nosniff."),
    ("x-frame-options", "Missing clickjacking header", "low",
     "X-Frame-Options tidak terdeteksi; periksa juga CSP frame-ancestors.",
     "Atur frame-ancestors dan/atau X-Frame-Options."),
    ("referrer-policy", "Missing Referrer-Policy", "info",
     "Referrer-Policy tidak terdeteksi.",
     "Pilih strict-origin-when-cross-origin atau lebih ketat."),
    ("permissions-policy", "Missing Permissions-Policy", "info",
     "Permissions-Policy tidak terdeteksi.",
     "Batasi fitur browser yang tidak digunakan."),
]


def analyze_http_security(url: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "requested_url": url, "final_url": "", "status_code": None,
        "server": "", "powered_by": "", "headers": {}, "cookies": [],
        "findings": [], "errors": [], "assessment_limited": False, "notes": [],
        "cors": {"allow_origin": "", "allow_credentials": ""},
    }
    response = None
    try:
        safe_url = _safe_request_url(url)
        response = requests.get(
            safe_url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
            headers={"User-Agent": "DefensiveSecurityAudit/1.0 (+passive checks)"},
            stream=True,
        )
        result["final_url"] = response.url
        result["status_code"] = response.status_code
        result["headers"] = {k.lower(): str(v)[:1000] for k, v in response.headers.items()}
        result["server"] = response.headers.get("Server", "")
        result["powered_by"] = response.headers.get("X-Powered-By", "")
        final_parsed = urlparse(response.url)
        requested_parsed = urlparse(safe_url)
        status = int(response.status_code)
        restricted_status = status in {401, 403, 429} or status >= 500
        result["assessment_limited"] = restricted_status
        if restricted_status:
            result["notes"].append(
                f"Respons HTTP {status} membatasi penilaian; header yang tidak ada "
                "tidak otomatis disimpulkan hilang pada halaman aplikasi."
            )

        if final_parsed.hostname != requested_parsed.hostname:
            result["findings"].append({
                "type": "Cross-host redirect (observasi)", "severity": "info",
                "evidence": f"Redirect berakhir di host {final_parsed.hostname}; status HTTP {status}.",
                "risk": "Perlu memastikan perpindahan host memang diharapkan.",
                "recommendation": "Tinjau konfigurasi redirect dan pastikan domain tujuan tepercaya.",
                "verification": "deterministic_http_observation",
            })

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        if not restricted_status and 200 <= status < 400:
            for header, label, severity, risk, recommendation in HEADER_CHECKS:
                if header == "strict-transport-security" and final_parsed.scheme.lower() != "https":
                    continue
                if header == "x-frame-options" and "frame-ancestors" in headers_lower.get("content-security-policy", "").lower():
                    continue
                if header not in headers_lower:
                    result["findings"].append({
                        "type": label, "severity": severity,
                        "evidence": f"Header {header} tidak ada pada respons HTTP {status}.",
                        "risk": risk, "recommendation": recommendation,
                        "verification": "deterministic_http_header_observation",
                    })

        if safe_url.lower().startswith("https://") and final_parsed.scheme.lower() != "https":
            result["findings"].append({
                "type": "HTTPS downgrade redirect", "severity": "medium",
                "evidence": f"URL akhir memakai skema {final_parsed.scheme}.",
                "risk": "Koneksi dapat berakhir tanpa enkripsi.",
                "recommendation": "Pastikan redirect mempertahankan HTTPS.",
                "verification": "deterministic_http_redirect_observation",
            })

        if result["server"]:
            result["findings"].append({
                "type": "Server banner disclosure (observasi)", "severity": "info",
                "evidence": f"Server: {result['server'][:200]} (HTTP {status}).",
                "risk": "Banner membantu fingerprinting, bukan bukti kerentanan.",
                "recommendation": "Minimalkan detail versi pada header server.",
                "verification": "deterministic_http_observation",
            })
        if result["powered_by"]:
            result["findings"].append({
                "type": "Technology header disclosure (observasi)", "severity": "info",
                "evidence": f"X-Powered-By: {result['powered_by'][:200]} (HTTP {status}).",
                "risk": "Header mengungkap petunjuk teknologi.",
                "recommendation": "Hapus/minimalkan header X-Powered-By.",
                "verification": "deterministic_http_observation",
            })

        if not restricted_status and 200 <= status < 400:
            raw_cookies = []
            try:
                raw_cookies = response.raw.headers.getlist("Set-Cookie")
            except Exception:
                sc = response.headers.get("Set-Cookie")
                if sc:
                    raw_cookies = [sc]
            for raw_cookie in raw_cookies:
                cookie = SimpleCookie()
                try:
                    cookie.load(raw_cookie)
                except Exception as exc:
                    result["errors"].append(f"Cookie parsing: {exc}")
                    continue
                for name, morsel in cookie.items():
                    flags = {
                        "secure": bool(morsel["secure"]),
                        "httponly": bool(morsel["httponly"]),
                        "samesite": morsel["samesite"] or "",
                    }
                    result["cookies"].append({"name": name, **flags})
            try:
                response.close()
            except Exception:
                pass
            if active_probe_enabled():
                try:
                    cors = requests.get(
                        safe_url,
                        headers={"Origin": "https://untrusted-origin.invalid",
                                 "User-Agent": "DefensiveSecurityAudit/1.0"},
                        timeout=REQUEST_TIMEOUT, allow_redirects=False,
                    )
                    acao = cors.headers.get("Access-Control-Allow-Origin", "")
                    acac = cors.headers.get("Access-Control-Allow-Credentials", "").lower()
                    result["cors"] = {"allow_origin": acao, "allow_credentials": acac,
                                      "status_code": cors.status_code}
                    if cors.status_code < 400 and acao == "https://untrusted-origin.invalid" and acac == "true":
                        result["findings"].append({
                            "type": "Reflected CORS origin dengan credentials", "severity": "medium",
                            "evidence": "Origin uji direfleksikan bersama Access-Control-Allow-Credentials: true.",
                            "risk": "Jika origin arbitrer dipercaya pada endpoint berautentikasi, data dapat dibaca lintas origin.",
                            "recommendation": "Validasi Origin terhadap allowlist ketat.",
                            "verification": "candidate_active_cors",
                        })
                    cors.close()
                except Exception as exc:
                    result["errors"].append(f"CORS check: {exc}")
            else:
                result["notes"].append("Uji CORS aktif dilewati (pemindaian aktif nonaktif).")
    except Exception as exc:
        result["errors"].append(str(exc))
    finally:
        try:
            if response is not None:
                response.close()
        except Exception:
            pass
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Parsing & utility
# ══════════════════════════════════════════════════════════════════════════════
def coerce_to_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    for attr in ("to_dict", "model_dump", "dict"):
        if hasattr(obj, attr):
            try:
                return getattr(obj, attr)()
            except Exception:
                pass
    return json.loads(json.dumps(obj, default=str))


SECRET_PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret": r"(?i)aws_secret_access_key\s*=\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
    "Google API": r"AIza[0-9A-Za-z_-]{35}",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Private Key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Database URI": r"(?:mysql|postgres|mongodb)://[^:\s]+:[^@\s]+@[^\s\"'<>]+",
    "Firebase": r"[a-z0-9-]+\.firebaseio\.com",
    "S3 Bucket": r"[a-z0-9.-]+\.s3\.amazonaws\.com",
    "Internal IP": r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
}


def extract_security_components(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    out: list[str] = ["=== [1] FORMS & INPUTS ==="]
    for form in soup.find_all("form"):
        attrs = " ".join(f'{k}="{v}"' for k, v in form.attrs.items())
        out.append(f"<form {attrs}>")
        for el in form.find_all(["input", "textarea", "select", "button"]):
            el_attrs = " ".join(f'{k}="{v}"' for k, v in el.attrs.items())
            out.append(f"  <{el.name} {el_attrs}>")
        out.append("</form>")

    out.append("\n=== [2] SCRIPTS ===")
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            out.append(f"External Script: src={src} type={script.get('type', 'text/javascript')} "
                       f"integrity={script.get('integrity', 'MISSING_SRI')}")
        elif script.string:
            out.append(f"Inline Script:\n{script.string.strip()}\n---")

    out.append("\n=== [3] HIDDEN CONTENT ===")
    for el in soup.find_all(style=lambda s: s and ("display:none" in s or "visibility:hidden" in s)):
        out.append(f"Hidden Element: {str(el)[:500]}")
    for el in soup.find_all(attrs={"type": "hidden"}):
        out.append(f"Hidden Input: name={el.get('name')} value={el.get('value')}")

    out.append("\n=== [4] EVENT HANDLERS & JS LINKS ===")
    for el in soup.find_all(True):
        for k, v in el.attrs.items():
            if k.startswith("on") or (k in ("href", "src") and isinstance(v, str)
                                      and ("javascript:" in v or "data:" in v)):
                out.append(f'<{el.name} {k}="{v}">')

    out.append("\n=== [5] FRAMEWORK DIRECTIVES ===")
    for el in soup.find_all(True):
        for k in el.attrs:
            if k.startswith(("v-", "ng-", "[", "(", "@")):
                out.append(f'<{el.name} {k}="{el.get(k)}">')

    out.append("\n=== [6] META & BASE ===")
    for tag in soup.find_all(["meta", "base"]):
        out.append(str(tag))

    out.append("\n=== [7] HTML COMMENTS ===")
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        out.append(f"<!-- {comment.strip()} -->")

    out.append("\n=== [8] STRUCTURED DATA ===")
    for script in soup.find_all("script", type=["application/json", "application/ld+json"]):
        if script.string:
            out.append(script.string.strip())

    out.append("\n=== [9] REGEX SECRETS ===")
    for label, pattern in SECRET_PATTERNS.items():
        for m in set(re.findall(pattern, html)):
            if len(str(m)) < 100:
                out.append(f"[{label}] {m}")

    out.append("\n=== [10] TEXT CONTEXT ===")
    for tag in soup.find_all(["h1", "h2", "h3", "label", "button"]):
        text = tag.get_text(strip=True)
        if text and len(text) < 100:
            out.append(f"<{tag.name}> {text}")

    extracted = "\n".join(out)
    if len(extracted) > MAX_PARSED_CHARS:
        extracted = extracted[:MAX_PARSED_CHARS] + "\n...[PARSING DIPOTONG]..."
    print(f"      [Parsing] {len(extracted):,} karakter komponen dari {len(html):,} HTML.")
    return extracted


def get_all_hostnames_and_ips(html: str, base_url: str) -> list[str]:
    if not base_url or base_url == "unknown":
        return []
    try:
        base_url = normalize_url(base_url)
    except ValueError:
        return []
    soup = BeautifulSoup(html or "", "html.parser")
    raw_urls: set[str] = set()
    for tag, attr in [("a", "href"), ("script", "src"), ("link", "href"),
                      ("img", "src"), ("form", "action")]:
        for el in soup.find_all(tag):
            val = el.get(attr)
            if val:
                raw_urls.add(urljoin(base_url, val))
    targets: set[str] = set()
    base_host = urlparse(base_url).hostname
    if base_host:
        targets.add(base_host)
    for u in raw_urls:
        host = urlparse(u).hostname
        if host:
            targets.add(host)
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", html):
        try:
            if ipaddress.ip_address(ip).is_global:
                targets.add(ip)
        except Exception:
            pass
    return list(targets)


def repair_json(json_str: str) -> str:
    json_str = re.sub(r",\s*([\]}])", r"\1", json_str)
    json_str = re.sub(r"^```(?:json)?\s*|\s*```$", "", json_str.strip(), flags=re.S)
    if json_str.startswith("{") and not json_str.endswith("}"):
        json_str += '"}'
    open_braces = json_str.count("{") - json_str.count("}")
    open_brackets = json_str.count("[") - json_str.count("]")
    return json_str + "}" * max(0, open_braces) + "]" * max(0, open_brackets)


# ══════════════════════════════════════════════════════════════════════════════
# FIX #12 — Deteksi teknologi deterministik
# ══════════════════════════════════════════════════════════════════════════════
def extract_tech_versions_deterministic(html: str) -> list[dict]:
    found: dict[str, dict] = {}

    def add(name: str, version: str, source: str = "Regex") -> None:
        if name and version and name not in found:
            found[name] = {"name": name, "version": version, "source": source}

    for m in re.finditer(r'<meta name="generator" content="WordPress ([\d.]+)"', html, re.I):
        add("WordPress", m.group(1))

    alias = {"wordpress-seo": "Yoast SEO"}
    for m in re.finditer(r"/wp-content/plugins/([a-zA-Z0-9_\-]+)/[^\"']*?[?&]ver="
                         r"([0-9][0-9A-Za-z.\-]*)", html, re.I):
        slug, ver = m.group(1), m.group(2)
        add(alias.get(slug.lower(), slug), ver)

    for m in re.finditer(r"/wp-content/themes/([a-zA-Z0-9_\-]+)/[^\"']*?[?&]ver="
                         r"([0-9][0-9A-Za-z.\-]*)", html, re.I):
        add(m.group(1), m.group(2))

    js_libs = [
        (r"jquery[.-]?([\d.]+)(?:\.min)?\.js", "jQuery"),
        (r"bootstrap[.-]?([\d.]+)(?:\.min)?\.(?:css|js)", "Bootstrap"),
        (r"vue[.-]?([\d.]+)(?:\.min)?\.js", "Vue.js"),
        (r"react[.-]?([\d.]+)(?:\.min)?\.js", "React"),
        (r"angular[.-]?([\d.]+)(?:\.min)?\.js", "AngularJS"),
    ]
    for pattern, name in js_libs:
        for m in re.finditer(pattern, html, re.I):
            add(name, m.group(1))

    for m in re.finditer(r"cdn\.jsdelivr\.net/npm/([a-zA-Z0-9_-]+)@([\d.]+)", html, re.I):
        add(m.group(1), m.group(2), source="Regex-NPM")

    return list(found.values())


# ══════════════════════════════════════════════════════════════════════════════
# FIX #11 — Temuan kode deterministik
# ══════════════════════════════════════════════════════════════════════════════
AD_NETWORK_HOSTS = {"js.juicyads.com", "cdn.ouo.io", "juicyads.com", "ouo.io"}


def detect_code_findings_deterministic(html: str, base_url: str) -> list[dict]:
    soup = BeautifulSoup(html or "", "html.parser")
    out: list[dict] = []

    for script in soup.find_all("script"):
        src = script.get("src") or ""
        stype = script.get("type", "text/javascript")
        integrity = script.get("integrity")
        if not src:
            continue

        if src.startswith("data:text/javascript"):
            out.append({
                "type": "Inline JavaScript Execution via data:text/javascript",
                "severity": "medium",
                "evidence": f"External Script: src={src[:120]}... type={stype} integrity=MISSING_SRI",
                "quote": src[:300],
                "risk": "Skrip data URI dieksekusi tanpa CSP ketat; menambah permukaan XSS.",
                "recommendation": "Hindari data URI script; gunakan file JS dengan nonce/hash CSP.",
                "verification": "deterministic_code_check",
            })
            continue

        if not src.startswith(("http://", "https://", "//")):
            continue

        if not integrity:
            out.append({
                "type": "Missing Subresource Integrity (SRI)",
                "severity": "medium",
                "evidence": f"External Script: src={src} type={stype} integrity=MISSING_SRI",
                "quote": f"External Script: src={src} type={stype} integrity=MISSING_SRI",
                "risk": "Tanpa SRI, perubahan skrip di CDN pihak ketiga tidak terdeteksi browser.",
                "recommendation": "Tambahkan atribut integrity pada semua skrip eksternal.",
                "verification": "deterministic_code_check",
            })

        try:
            host = (urlparse(urljoin(base_url, src)).hostname or "").lower()
        except Exception:
            host = ""
        if any(host == h or host.endswith("." + h) for h in AD_NETWORK_HOSTS):
            out.append({
                "type": "Third-Party Ad Network Script Loading",
                "severity": "medium",
                "evidence": f"External Script: src={src} type={stype} integrity={integrity or 'MISSING_SRI'}",
                "quote": f"External Script: src={src} type={stype}",
                "risk": "Skrip iklan pihak ketiga dapat mengeksekusi kode arbitrer.",
                "recommendation": "Batasi sumber via CSP; sandbox konten iklan.",
                "verification": "deterministic_code_check",
            })

    for script in soup.find_all("script"):
        content = script.string or ""
        if "data:text/javascript;base64," in content:
            out.append({
                "type": "Inline base64 data-URI JavaScript",
                "severity": "medium",
                "evidence": "Inline script memuat data:text/javascript;base64.",
                "quote": content[:300],
                "risk": "Payload base64 sulit diaudit dan sulit di-CSP-kan.",
                "recommendation": "Refactor ke file JS statis dengan nonce/hash CSP.",
                "verification": "deterministic_code_check",
            })

    print(f"      [Code Check] {len(out)} temuan kode deterministik.")
    return out


# ══════════════════════════════════════════════════════════════════════════════
# NVD / OSV (opsional, hanya bila diaktifkan)
# ══════════════════════════════════════════════════════════════════════════════
def _version_tuple(v: str) -> list[int]:
    return [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v)]


def _version_cmp(a: str, b: str) -> int:
    pa, pb = _version_tuple(a), _version_tuple(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return (pa > pb) - (pa < pb)


def _iter_nvd_cpe_matches(configurations):
    def walk(node):
        if not isinstance(node, dict):
            return
        for item in node.get("cpeMatch", []) or []:
            if isinstance(item, dict):
                yield item
        for child in node.get("children", []) or []:
            yield from walk(child)

    for cfg in configurations or []:
        if isinstance(cfg, dict):
            for node in cfg.get("nodes", []) or []:
                yield from walk(node)


def search_nvd_verified(technology_name: str, version: str) -> list[dict]:
    name = str(technology_name or "").strip()
    version = str(version or "").strip()
    audit = {"technology": name, "version": version or "unknown", "nvd_status": "not_started",
             "nvd_pages": 0, "nvd_total_results": None, "nvd_cpe_matches": 0,
             "nvd_rejected_candidates": 0, "nvd_error": ""}
    if not RUN_NVD or not name or not _is_known_version(version):
        audit["nvd_status"] = "skipped"
        CVE_SEARCH_AUDIT.append(audit)
        return []

    query = f"{name} {version}".strip()
    time.sleep(max(float(SLEEP_BETWEEN_NVD), 6.2 if not NVD_API_KEY else 0.5))
    items: list[dict] = []
    start_index, page_size, total_results = 0, 2000, None
    try:
        while start_index < 10000:
            params = {"keywordSearch": query, "resultsPerPage": page_size, "startIndex": start_index}
            headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
            response = requests.get(NVD_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            payload = response.json()
            page_items = payload.get("vulnerabilities", []) or []
            items.extend(page_items)
            audit["nvd_pages"] += 1
            total_results = int(payload.get("totalResults", len(items)) or 0)
            if not page_items or len(items) >= total_results:
                break
            start_index += len(page_items)
    except Exception as exc:
        audit["nvd_status"] = "error_or_rate_limited"
        audit["nvd_error"] = str(exc)[:300]
        CVE_SEARCH_AUDIT.append(audit)
        return []

    audit["nvd_status"] = "complete"
    audit["nvd_total_results"] = total_results
    verified: list[dict] = []
    for item in items:
        cve = item.get("cve", {}) if isinstance(item, dict) else {}
        cve_id = cve.get("id", "")
        metrics = cve.get("metrics", {}) or {}
        score, sev = None, "unknown"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                score = m.get("cvssData", {}).get("baseScore")
                sev = (m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity") or "unknown")
                break
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        verified.append({
            "id": cve_id, "description": desc[:500], "cvss": score, "severity": str(sev).lower(),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "technology": f"{name} {version}", "source": "NVD",
            "verification_status": "nvd_keyword_candidate",
            "verification_note": "Kandidat keyword NVD; verifikasi CPE/rentang versi sebelum menyatakan rentan.",
        })
    audit["nvd_cpe_matches"] = len(verified)
    CVE_SEARCH_AUDIT.append(audit)
    return verified


def search_osv_verified(technology_name: str, version: str) -> list[dict]:
    name = re.sub(r"\s+", " ", str(technology_name or "").strip())
    version = str(version or "").strip()
    if not _is_known_version(version):
        return []
    mappings = [
        (("jquery",), "npm", "jquery"), (("bootstrap",), "npm", "bootstrap"),
        (("lodash",), "npm", "lodash"), (("axios",), "npm", "axios"),
        (("react",), "npm", "react"), (("vue",), "npm", "vue"),
        (("wordpress",), "WordPress", "wordpress"), (("django",), "PyPI", "Django"),
        (("flask",), "PyPI", "Flask"),
    ]
    low = name.lower()
    pkg = next(((eco, pname) for keys, eco, pname in mappings if any(k in low for k in keys)), None)
    if not pkg:
        return []
    ecosystem, package = pkg
    try:
        response = requests.post("https://api.osv.dev/v1/query",
                                 json={"package": {"name": package, "ecosystem": ecosystem},
                                       "version": version},
                                 timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return []
        payload = response.json()
    except Exception:
        return []
    out = []
    for item in payload.get("vulns", []) or []:
        out.append({
            "id": item.get("id", ""), "aliases": item.get("aliases", []),
            "description": (item.get("summary") or item.get("details") or "")[:500],
            "severity": "unknown", "url": f"https://osv.dev/vulnerability/{item.get('id', '')}",
            "technology": f"{name} {version}", "source": "OSV.dev",
            "verification_status": "osv_candidate",
            "verification_note": "Kandidat OSV; verifikasi rentang terdampak sebelum menyatakan rentan.",
        })
    return out


# ══════════════════════════════════════════════════════════════════════════════
# FIX #13/#14/#16 — Kanonisasi, dedup, klasifikasi
# ══════════════════════════════════════════════════════════════════════════════
HTTP_CANON = {
    "missing_csp": ("Missing Content-Security-Policy", "medium",
                    "Kebijakan CSP tidak terdeteksi.",
                    "Terapkan CSP dan uji dalam Report-Only sebelum penegakan."),
    "missing_hsts": ("Missing HSTS", "low",
                     "Strict-Transport-Security tidak terdeteksi.",
                     "Aktifkan HSTS setelah seluruh subdomain siap."),
    "missing_xcto": ("Missing X-Content-Type-Options", "low",
                     "X-Content-Type-Options tidak terdeteksi.",
                     "Atur X-Content-Type-Options: nosniff."),
    "missing_xfo": ("Missing clickjacking header", "low",
                    "X-Frame-Options tidak terdeteksi dan CSP frame-ancestors tidak ada.",
                    "Atur frame-ancestors di CSP dan/atau X-Frame-Options."),
    "missing_referrer_policy": ("Missing Referrer-Policy", "info",
                                "Referrer-Policy tidak terdeteksi.",
                                "Gunakan strict-origin-when-cross-origin."),
    "missing_permissions_policy": ("Missing Permissions-Policy", "info",
                                   "Permissions-Policy tidak terdeteksi.",
                                   "Batasi fitur browser yang tidak digunakan."),
    "server_banner": ("Server banner disclosure", "info",
                      "Banner server membantu fingerprinting.",
                      "Minimalkan detail versi pada header server."),
}

_HTTP_FACT_SIGNATURES = [
    ("missing_csp", ("content-security-policy", "content security policy")),
    ("missing_hsts", ("strict-transport-security", "hsts")),
    ("missing_xcto", ("x-content-type-options", "mime sniffing")),
    ("missing_xfo", ("x-frame-options", "clickjacking", "frame-ancestors")),
    ("missing_referrer_policy", ("referrer-policy",)),
    ("missing_permissions_policy", ("permissions-policy",)),
    ("server_banner", ("server banner", "x-powered-by")),
]

_NON_HTTP_SIGNATURES = [
    ("missing_sri", ("subresource integrity", "integrity=missing")),
    ("inline_data_js", ("data:text/javascript",)),
    ("ad_network_script", ("juicyads", "ouo.io", "third-party ad")),
]


def _canonical_finding_signature(finding: dict) -> Optional[tuple[str, str]]:
    text = f"{finding.get('type', '')} {finding.get('evidence', '')}".lower()
    for tag, keywords in _HTTP_FACT_SIGNATURES:
        if any(kw in text for kw in keywords):
            return ("http", tag)
    for tag, keywords in _NON_HTTP_SIGNATURES:
        if any(kw in text for kw in keywords):
            return ("code", tag)
    return None


def _finding_source_rank(finding: dict) -> int:
    v = finding.get("verification", "")
    if v in ("deterministic_check", "deterministic_code_check"):
        return 0
    if isinstance(v, str) and v.startswith("tool_verified"):
        return 1
    return 2


def _severity_rank(sev: str) -> int:
    sev = str(sev).lower()
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def dedup_and_merge_findings(findings: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = {}
    passthrough: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        sig = _canonical_finding_signature(f)
        if sig is None:
            passthrough.append(f)
        else:
            groups.setdefault(sig, []).append(f)

    merged: list[dict] = []
    for sig, group in groups.items():
        kind, tag = sig
        group_sorted = sorted(group, key=_finding_source_rank)
        primary = dict(group_sorted[0])
        if kind == "http" and tag in HTTP_CANON:
            typ, sev_canon, risk, rec = HTTP_CANON[tag]
            primary["type"] = typ
            primary["risk"] = risk
            primary["recommendation"] = rec
            if _severity_rank(primary.get("severity", "info")) > _severity_rank(sev_canon):
                primary["severity"] = sev_canon
        extra = []
        for g in group_sorted[1:]:
            ev = str(g.get("evidence", "")).strip()
            if ev and ev.lower() != str(primary.get("evidence", "")).strip().lower():
                extra.append(f"[{g.get('verification', g.get('type', 'sumber lain'))}] {ev}")
        if extra:
            base = str(primary.get("evidence", "")).rstrip(". ")
            primary["evidence"] = base + ". Bukti tambahan: " + " | ".join(extra)
        most_severe = min(group, key=lambda g: _severity_rank(g.get("severity", "info")))
        if _severity_rank(most_severe.get("severity", "info")) < _severity_rank(primary.get("severity", "info")):
            primary["severity"] = most_severe.get("severity")
        merged.append(primary)
    return passthrough + merged


def summarize(findings: list[dict]) -> dict:
    valid = [f for f in findings if isinstance(f, dict)]
    by = {s: 0 for s in SEVERITY_ORDER}
    for f in valid:
        sev = str(f.get("severity", "info")).lower()
        if sev not in by:
            sev = "info"
        by[sev] += 1
    return {"total": len(valid), "by_severity": by}


"""Katalog lengkap lab PortSwigger Web Security Academy.

Setiap lab punya: kategori, level, judul, probe (keluarga deteksi), dan tag.
Tag dipakai mesin deteksi untuk memastikan temuan DIATRIBUSIKAN ke lab yang
benar saja — temuan tanpa bukti bertag lengkap TIDAK dilaporkan sebagai
detected, melainkan not_verified / not_applicable.
"""

# ══════════════════════════════════════════════════════════════════════════════
# LEVEL & TAG
# ══════════════════════════════════════════════════════════════════════════════
LEVELS = ("LAB", "APPRENTICE", "PRACTITIONER", "EXPERT")

# Aturan tag: (tag, kata kunci pada judul). Urutan penting (tag pertama menang).
_TAG_RULES = [
    ("where", ("where clause",)),
    ("login_bypass", ("login bypass", "bypass authentication")),
    ("union", ("union attack",)),
    ("blind", ("blind",)),
    ("time_based", ("time delay", "time-based", "time sensitive", "time-sensitive")),
    ("oob", ("out-of-band", "out of band", "shellshock")),
    ("error_based", ("error-based", "error messages", "debug page")),
    ("xml", ("xml", "xinclude", "dtd", "external entity")),
    ("oracle", ("oracle",)),
    ("mysql_mssql", ("mysql", "microsoft")),
    ("db_dump", ("listing the database", "database contents")),
    ("nothing_encoded", ("nothing encoded",)),
    ("svg_allowed", ("svg markup",)),
    ("onclick_context", ("onclick event",)),
    ("doc_write", ("document.write",)),
    ("inner_html", ("innerhtml",)),
    ("jquery_selector", ("jquery selector",)),
    ("jquery_anchor", ("jquery anchor",)),
    ("hashchange", ("hashchange",)),
    ("select_element", ("select element",)),
    ("custom_tags", ("custom ones",)),
    ("no_csrf_defense", ("no defenses",)),
    ("reflected", ("reflected",)),
    ("stored", ("stored",)),
    ("dom_sink", ("dom xss", "dom-based", "document.write", "innerhtml",
                  "jquery anchor", "jquery selector", "hashchange")),
    ("javascript_context", ("javascript string", "template literal", "javascript url")),
    ("attribute_context", ("attribute",)),
    ("csp_bypass", ("csp bypass", "protected by csp", "very strict csp")),
    ("angularjs", ("angularjs",)),
    ("filter_blocked", ("blocked",)),
    ("canonical_tag", ("canonical link",)),
    ("dangling_markup", ("dangling markup",)),
    ("cookie_theft", ("steal cookies", "capture passwords")),
    ("csrf_defense_bypass", ("bypass csrf",)),
    ("frame_buster", ("frame buster",)),
    ("multistep", ("multistep", "multi-step")),
    ("sameSite", ("samesite",)),
    ("referer", ("referer",)),
    ("csrf_token", ("csrf token",)),
    ("web_message", ("web messages",)),
    ("json_parse", ("json.parse",)),
    ("dom_clobbering", ("clobbering",)),
    ("open_redirect", ("open redirect", "redirection")),
    ("percent_encoding", ("encoding", "url-decode")),
    ("xxe_ssrf", ("ssrf",)),
    ("image_upload", ("image file upload",)),
    ("local_dtd", ("local dtd",)),
    ("param_entities", ("parameter entities",)),
    ("blacklist_bypass", ("blacklist",)),
    ("whitelist_bypass", ("whitelist",)),
    ("protocol_confusion", ("insecure protocols",)),
    ("null_origin", ("null origin",)),
    ("origin_reflection", ("origin reflection",)),
    ("cl_te", ("cl.te",)),
    ("te_cl", ("te.cl",)),
    ("cl_zero", ("cl.0", "0.cl")),
    ("h2", ("h2.", "http/2")),
    ("crlf", ("crlf",)),
    ("tunnelling", ("tunnelling",)),
    ("desync", ("desync",)),
    ("cache_poison", ("cache poisoning",)),
    ("cache_deception", ("cache deception",)),
    ("output_redirect", ("output redirection",)),
    ("os_cmd", ("os command",)),
    ("sandbox", ("sandboxed",)),
    ("documented_exploit", ("documented exploit",)),
    ("path_absolute", ("absolute path",)),
    ("path_stripped", ("stripped",)),
    ("null_byte", ("null byte",)),
    ("role_param", ("user role", "role controlled")),
    ("idor", ("object reference", "user id controlled", "id controlled")),
    ("admin_panel", ("admin functionality", "admin")),
    ("url_based", ("url-based",)),
    ("method_bypass", ("method-based", "request method")),
    ("referer_based", ("referer-based",)),
    ("multi_step", ("multi-step", "one step")),
    ("user_enum", ("username enumeration",)),
    ("two_fa", ("2fa",)),
    ("password_reset", ("password reset",)),
    ("brute_force", ("brute-force", "brute force")),
    ("cookie_bruteforce", ("stay-logged-in",)),
    ("offline_crack", ("offline password",)),
    ("timing", ("timing",)),
    ("account_lock", ("account lock",)),
    ("websocket_handshake", ("handshake",)),
    ("websocket_hijack", ("cross-site websocket",)),
    ("unkeyed_header", ("unkeyed header", "unknown header", "multiple headers")),
    ("unkeyed_cookie", ("unkeyed cookie",)),
    ("unkeyed_query", ("unkeyed query",)),
    ("param_cloaking", ("parameter cloaking",)),
    ("fat_get", ("fat get",)),
    ("normalization", ("normalization",)),
    ("cache_key_injection", ("cache key injection",)),
    ("internal_cache", ("internal cache",)),
    ("serialized_object", ("serialized objects",)),
    ("serialized_types", ("serialized data types",)),
    ("php_object", ("php",)),
    ("java_gadget", ("java deserialization", "java deserialization", "commons")),
    ("ruby_gadget", ("ruby",)),
    ("phar", ("phar",)),
    ("custom_gadget", ("custom gadget",)),
    ("debug_exposure", ("debug",)),
    ("backup_file", ("backup files", "version control")),
    ("auth_bypass_info", ("bypass via information disclosure",)),
    ("client_side_trust", ("client-side",)),
    ("logic_flaw", ("logic flaw", "logic vulnerability")),
    ("workflow", ("workflow",)),
    ("state_machine", ("state machine",)),
    ("encryption_oracle", ("encryption oracle",)),
    ("email_parsing", ("email address parsing",)),
    ("host_header", ("host header",)),
    ("host_header_bypass", ("host header authentication bypass",)),
    ("routing_ssrf", ("routing-based",)),
    ("connection_state", ("connection state",)),
    ("oauth_implicit", ("implicit flow",)),
    ("oauth_redirect", ("redirect_uri",)),
    ("oauth_token_theft", ("stealing oauth", "access tokens")),
    ("profile_linking", ("profile linking",)),
    ("openid", ("openid",)),
    ("webshell", ("web shell",)),
    ("content_type_bypass", ("content-type",)),
    ("extension_bypass", ("extension",)),
    ("polyglot", ("polyglot",)),
    ("race_condition", ("race condition",)),
    ("jwt_unverified", ("unverified signature",)),
    ("jwt_flawed", ("flawed signature",)),
    ("jwt_weak_key", ("weak signing key",)),
    ("jwt_jwk", ("jwk",)),
    ("jwt_jku", ("jku",)),
    ("jwt_kid", ("kid",)),
    ("jwt_alg_confusion", ("algorithm confusion",)),
    ("targeted_scan", ("targeted scanning",)),
    ("nonstandard_data", ("non-standard data",)),
    ("client_proto", ("client-side prototype",)),
    ("server_proto", ("server-side prototype",)),
    ("proto_dom_xss", ("dom xss via",)),
    ("proto_sanitization", ("sanitization",)),
    ("proto_third_party", ("third-party libraries",)),
    ("proto_rce", ("remote code execution",)),
    ("proto_exfil", ("exfiltrating",)),
    ("graphql_private", ("private graphql posts",)),
    ("graphql_fields", ("graphql fields",)),
    ("graphql_endpoint", ("graphql endpoint", "hidden graphql")),
    ("graphql_bruteforce", ("brute force protections",)),
    ("graphql_csrf", ("csrf exploits over graphql",)),
    ("rate_limit", ("rate limit",)),
    ("single_endpoint", ("single-endpoint",)),
    ("multi_endpoint", ("multi-endpoint",)),
    ("limit_overrun", ("limit overrun",)),
    ("partial_construction", ("partial construction",)),
    ("nosql_detect", ("detecting nosql",)),
    ("nosql_auth", ("bypass authentication",)),
    ("nosql_extract", ("extract data", "extract unknown fields")),
    ("api_docs", ("documentation",)),
    ("param_pollution", ("parameter pollution",)),
    ("unused_endpoint", ("unused api",)),
    ("mass_assignment", ("mass assignment",)),
    ("llm_agency", ("excessive agency",)),
    ("llm_api", ("llm apis",)),
    ("prompt_injection", ("prompt injection",)),
    ("llm_output", ("output handling",)),
    ("ai_agent", ("ai agent",)),
    ("ai_scanner", ("ai scanner",)),
    ("web_cache_deception", ("cache deception",)),
    ("path_mapping", ("path mapping",)),
    ("path_delimiter", ("path delimiters",)),
    ("origin_normalization", ("origin server normalization",)),
    ("cache_normalization", ("cache server normalization",)),
    ("exact_match", ("exact-match",)),
]


# Tag yang hanya relevan pada kategori tertentu (mencegah judul lintas kategori
# menyuntikkan tag yang salah, mis. "CSRF token protection" pada lab clickjacking).
_TAG_SCOPE: dict[str, set[str]] = {
    "csrf_token": {"csrf"},
    "sameSite": {"csrf"},
    "referer": {"csrf"},
    "frame_buster": {"clickjacking"},
    "multistep": {"clickjacking"},
    "csrf_defense_bypass": {"xss"},
    "cookie_theft": {"xss"},
    "auth_bypass_info": {"info_disclosure"},
    "host_header_bypass": {"host_header"},
    "path_absolute": {"path_traversal"},
    "path_stripped": {"path_traversal"},
    "null_byte": {"path_traversal"},
    "os_cmd": {"os_command"},
    "sandbox": {"ssti"},
    "documented_exploit": {"ssti"},
    "oob": {"sql_injection", "xxe", "ssrf", "os_command"},
    "oracle": {"sql_injection"},
    "mysql_mssql": {"sql_injection"},
    "db_dump": {"sql_injection"},
}


def derive_tags(category_key: str, title: str) -> frozenset:
    """Tag yang HARUS dibuktikan agar lab boleh disebut 'detected'."""
    low = title.lower()
    tags = {category_key}
    for tag, keywords in _TAG_RULES:
        scope = _TAG_SCOPE.get(tag)
        if scope and category_key not in scope:
            continue
        if any(k in low for k in keywords):
            tags.add(tag)
    return frozenset(tags)


# ══════════════════════════════════════════════════════════════════════════════
# KATALOG
# ══════════════════════════════════════════════════════════════════════════════
_RAW_CATALOG: dict[str, tuple[str, str, list[tuple[str, str]]]] = {
    "sql_injection": ("SQL injection", "sqli", [
        ("APPRENTICE", "SQL injection vulnerability in WHERE clause allowing retrieval of hidden data"),
        ("APPRENTICE", "SQL injection vulnerability allowing login bypass"),
        ("PRACTITIONER", "SQL injection attack, querying the database type and version on Oracle"),
        ("PRACTITIONER", "SQL injection attack, querying the database type and version on MySQL and Microsoft"),
        ("PRACTITIONER", "SQL injection attack, listing the database contents on non-Oracle databases"),
        ("PRACTITIONER", "SQL injection attack, listing the database contents on Oracle"),
        ("PRACTITIONER", "SQL injection UNION attack, determining the number of columns returned by the query"),
        ("PRACTITIONER", "SQL injection UNION attack, finding a column containing text"),
        ("PRACTITIONER", "SQL injection UNION attack, retrieving data from other tables"),
        ("PRACTITIONER", "SQL injection UNION attack, retrieving multiple values in a single column"),
        ("PRACTITIONER", "Blind SQL injection with conditional responses"),
        ("PRACTITIONER", "Blind SQL injection with conditional errors"),
        ("PRACTITIONER", "Visible error-based SQL injection"),
        ("PRACTITIONER", "Blind SQL injection with time delays"),
        ("PRACTITIONER", "Blind SQL injection with time delays and information retrieval"),
        ("PRACTITIONER", "Blind SQL injection with out-of-band interaction"),
        ("PRACTITIONER", "Blind SQL injection with out-of-band data exfiltration"),
        ("PRACTITIONER", "SQL injection with filter bypass via XML encoding"),
    ]),
    "xss": ("Cross-site scripting", "xss", [
        ("APPRENTICE", "Reflected XSS into HTML context with nothing encoded"),
        ("APPRENTICE", "Stored XSS into HTML context with nothing encoded"),
        ("APPRENTICE", "DOM XSS in document.write sink using source location.search"),
        ("APPRENTICE", "DOM XSS in innerHTML sink using source location.search"),
        ("APPRENTICE", "DOM XSS in jQuery anchor href attribute sink using location.search source"),
        ("APPRENTICE", "DOM XSS in jQuery selector sink using a hashchange event"),
        ("APPRENTICE", "Reflected XSS into attribute with angle brackets HTML-encoded"),
        ("APPRENTICE", "Stored XSS into anchor href attribute with double quotes HTML-encoded"),
        ("APPRENTICE", "Reflected XSS into a JavaScript string with angle brackets HTML encoded"),
        ("PRACTITIONER", "DOM XSS in document.write sink using source location.search inside a select element"),
        ("PRACTITIONER", "DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded"),
        ("PRACTITIONER", "Reflected DOM XSS"),
        ("PRACTITIONER", "Stored DOM XSS"),
        ("PRACTITIONER", "Reflected XSS into HTML context with most tags and attributes blocked"),
        ("PRACTITIONER", "Reflected XSS into HTML context with all tags blocked except custom ones"),
        ("PRACTITIONER", "Reflected XSS with some SVG markup allowed"),
        ("PRACTITIONER", "Reflected XSS in canonical link tag"),
        ("PRACTITIONER", "Reflected XSS into a JavaScript string with single quote and backslash escaped"),
        ("PRACTITIONER", "Reflected XSS into a JavaScript string with angle brackets and double quotes "
                         "HTML-encoded and single quotes escaped"),
        ("PRACTITIONER", "Stored XSS into onclick event with angle brackets and double quotes HTML-encoded "
                         "and single quotes and backslash escaped"),
        ("PRACTITIONER", "Reflected XSS into a template literal with angle brackets, single, double quotes, "
                         "backslash and backticks Unicode-escaped"),
        ("PRACTITIONER", "Exploiting cross-site scripting to steal cookies"),
        ("PRACTITIONER", "Exploiting cross-site scripting to capture passwords"),
        ("PRACTITIONER", "Exploiting XSS to bypass CSRF defenses"),
        ("EXPERT", "Reflected XSS with AngularJS sandbox escape without strings"),
        ("EXPERT", "Reflected XSS with AngularJS sandbox escape and CSP"),
        ("EXPERT", "Reflected XSS with event handlers and href attributes blocked"),
        ("EXPERT", "Reflected XSS in a JavaScript URL with some characters blocked"),
        ("PRACTITIONER", "Reflected XSS protected by very strict CSP, with dangling markup attack"),
        ("EXPERT", "Reflected XSS protected by CSP, with CSP bypass"),
    ]),
    "csrf": ("Cross-site request forgery (CSRF)", "csrf", [
        ("APPRENTICE", "CSRF vulnerability with no defenses"),
        ("PRACTITIONER", "CSRF where token validation depends on request method"),
        ("PRACTITIONER", "CSRF where token validation depends on token being present"),
        ("PRACTITIONER", "CSRF where token is not tied to user session"),
        ("PRACTITIONER", "CSRF where token is tied to non-session cookie"),
        ("PRACTITIONER", "CSRF where token is duplicated in cookie"),
        ("PRACTITIONER", "SameSite Lax bypass via method override"),
        ("PRACTITIONER", "SameSite Strict bypass via client-side redirect"),
        ("PRACTITIONER", "SameSite Strict bypass via sibling domain"),
        ("PRACTITIONER", "CSRF where Referer validation depends on header being present"),
        ("PRACTITIONER", "CSRF with broken Referer validation"),
    ]),
    "clickjacking": ("Clickjacking", "clickjacking", [
        ("APPRENTICE", "Basic clickjacking with CSRF token protection"),
        ("APPRENTICE", "Clickjacking with form input data prefilled from a URL parameter"),
        ("APPRENTICE", "Clickjacking with a frame buster script"),
        ("PRACTITIONER", "Exploiting clickjacking vulnerability to trigger DOM-based XSS"),
        ("PRACTITIONER", "Multistep clickjacking"),
    ]),
    "dom": ("DOM-based vulnerabilities", "dom", [
        ("PRACTITIONER", "DOM XSS using web messages"),
        ("PRACTITIONER", "DOM XSS using web messages and a JavaScript URL"),
        ("PRACTITIONER", "DOM XSS using web messages and JSON.parse"),
        ("PRACTITIONER", "DOM-based open redirection"),
        ("PRACTITIONER", "DOM-based cookie manipulation"),
        ("EXPERT", "Exploiting DOM clobbering to enable XSS"),
        ("EXPERT", "Clobbering DOM attributes to bypass HTML filters"),
    ]),
    "cors": ("Cross-origin resource sharing (CORS)", "cors", [
        ("APPRENTICE", "CORS vulnerability with basic origin reflection"),
        ("APPRENTICE", "CORS vulnerability with trusted null origin"),
        ("PRACTITIONER", "CORS vulnerability with trusted insecure protocols"),
    ]),
    "xxe": ("XML external entity (XXE) injection", "xxe", [
        ("APPRENTICE", "Exploiting XXE using external entities to retrieve files"),
        ("APPRENTICE", "Exploiting XXE to perform SSRF attacks"),
        ("PRACTITIONER", "Blind XXE with out-of-band interaction"),
        ("PRACTITIONER", "Blind XXE with out-of-band interaction via XML parameter entities"),
        ("PRACTITIONER", "Exploiting blind XXE to exfiltrate data using a malicious external DTD"),
        ("PRACTITIONER", "Exploiting blind XXE to retrieve data via error messages"),
        ("PRACTITIONER", "Exploiting XInclude to retrieve files"),
        ("PRACTITIONER", "Exploiting XXE via image file upload"),
        ("EXPERT", "Exploiting XXE to retrieve data by repurposing a local DTD"),
    ]),
    "ssrf": ("Server-side request forgery (SSRF)", "ssrf", [
        ("APPRENTICE", "Basic SSRF against the local server"),
        ("APPRENTICE", "Basic SSRF against another back-end system"),
        ("PRACTITIONER", "Blind SSRF with out-of-band detection"),
        ("PRACTITIONER", "SSRF with blacklist-based input filter"),
        ("PRACTITIONER", "SSRF with filter bypass via open redirection vulnerability"),
        ("EXPERT", "Blind SSRF with Shellshock exploitation"),
        ("EXPERT", "SSRF with whitelist-based input filter"),
    ]),
    "smuggling": ("HTTP request smuggling", "smuggling", [
        ("PRACTITIONER", "HTTP request smuggling, confirming a CL.TE vulnerability via differential responses"),
        ("PRACTITIONER", "HTTP request smuggling, confirming a TE.CL vulnerability via differential responses"),
        ("PRACTITIONER", "Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability"),
        ("PRACTITIONER", "Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability"),
        ("PRACTITIONER", "Exploiting HTTP request smuggling to reveal front-end request rewriting"),
        ("PRACTITIONER", "Exploiting HTTP request smuggling to capture other users' requests"),
        ("PRACTITIONER", "Exploiting HTTP request smuggling to deliver reflected XSS"),
        ("PRACTITIONER", "Response queue poisoning via H2.TE request smuggling"),
        ("PRACTITIONER", "H2.CL request smuggling"),
        ("PRACTITIONER", "HTTP/2 request smuggling via CRLF injection"),
        ("PRACTITIONER", "HTTP/2 request splitting via CRLF injection"),
        ("EXPERT", "0.CL request smuggling"),
        ("PRACTITIONER", "CL.0 request smuggling"),
        ("PRACTITIONER", "HTTP request smuggling, basic CL.TE vulnerability"),
        ("PRACTITIONER", "HTTP request smuggling, basic TE.CL vulnerability"),
        ("PRACTITIONER", "HTTP request smuggling, obfuscating the TE header"),
        ("EXPERT", "Exploiting HTTP request smuggling to perform web cache poisoning"),
        ("EXPERT", "Exploiting HTTP request smuggling to perform web cache deception"),
        ("EXPERT", "Bypassing access controls via HTTP/2 request tunnelling"),
        ("EXPERT", "Web cache poisoning via HTTP/2 request tunnelling"),
        ("EXPERT", "Client-side desync"),
        ("EXPERT", "Server-side pause-based request smuggling"),
    ]),
    "os_command": ("OS command injection", "os_command", [
        ("APPRENTICE", "OS command injection, simple case"),
        ("PRACTITIONER", "Blind OS command injection with time delays"),
        ("PRACTITIONER", "Blind OS command injection with output redirection"),
        ("PRACTITIONER", "Blind OS command injection with out-of-band interaction"),
        ("PRACTITIONER", "Blind OS command injection with out-of-band data exfiltration"),
    ]),
    "ssti": ("Server-side template injection", "ssti", [
        ("PRACTITIONER", "Basic server-side template injection"),
        ("PRACTITIONER", "Basic server-side template injection (code context)"),
        ("PRACTITIONER", "Server-side template injection using documentation"),
        ("PRACTITIONER", "Server-side template injection in an unknown language with a documented exploit"),
        ("PRACTITIONER", "Server-side template injection with information disclosure via user-supplied objects"),
        ("EXPERT", "Server-side template injection in a sandboxed environment"),
        ("EXPERT", "Server-side template injection with a custom exploit"),
    ]),
    "path_traversal": ("Path traversal", "path_traversal", [
        ("APPRENTICE", "File path traversal, simple case"),
        ("PRACTITIONER", "File path traversal, traversal sequences blocked with absolute path bypass"),
        ("PRACTITIONER", "File path traversal, traversal sequences stripped non-recursively"),
        ("PRACTITIONER", "File path traversal, traversal sequences stripped with superfluous URL-decode"),
        ("PRACTITIONER", "File path traversal, validation of start of path"),
        ("PRACTITIONER", "File path traversal, validation of file extension with null byte bypass"),
    ]),
    "access_control": ("Access control vulnerabilities", "access_control", [
        ("APPRENTICE", "Unprotected admin functionality"),
        ("APPRENTICE", "Unprotected admin functionality with unpredictable URL"),
        ("APPRENTICE", "User role controlled by request parameter"),
        ("APPRENTICE", "User role can be modified in user profile"),
        ("APPRENTICE", "User ID controlled by request parameter"),
        ("APPRENTICE", "User ID controlled by request parameter, with unpredictable user IDs"),
        ("APPRENTICE", "User ID controlled by request parameter with data leakage in redirect"),
        ("APPRENTICE", "User ID controlled by request parameter with password disclosure"),
        ("APPRENTICE", "Insecure direct object references"),
        ("PRACTITIONER", "URL-based access control can be circumvented"),
        ("PRACTITIONER", "Method-based access control can be circumvented"),
        ("PRACTITIONER", "Multi-step process with no access control on one step"),
        ("PRACTITIONER", "Referer-based access control"),
    ]),
    "authentication": ("Authentication", "auth", [
        ("APPRENTICE", "Username enumeration via different responses"),
        ("APPRENTICE", "2FA simple bypass"),
        ("APPRENTICE", "Password reset broken logic"),
        ("PRACTITIONER", "Username enumeration via subtly different responses"),
        ("PRACTITIONER", "Username enumeration via response timing"),
        ("PRACTITIONER", "Broken brute-force protection, IP block"),
        ("PRACTITIONER", "Username enumeration via account lock"),
        ("PRACTITIONER", "2FA broken logic"),
        ("PRACTITIONER", "Brute-forcing a stay-logged-in cookie"),
        ("PRACTITIONER", "Offline password cracking"),
        ("PRACTITIONER", "Password reset poisoning via middleware"),
        ("PRACTITIONER", "Password brute-force via password change"),
        ("EXPERT", "Broken brute-force protection, multiple credentials per request"),
        ("EXPERT", "2FA bypass using a brute-force attack"),
    ]),
    "websockets": ("WebSockets", "websocket", [
        ("APPRENTICE", "Manipulating WebSocket messages to exploit vulnerabilities"),
        ("PRACTITIONER", "Cross-site WebSocket hijacking"),
        ("PRACTITIONER", "Manipulating the WebSocket handshake to exploit vulnerabilities"),
    ]),
    "cache_poisoning": ("Web cache poisoning", "cache_poisoning", [
        ("PRACTITIONER", "Web cache poisoning with an unkeyed header"),
        ("PRACTITIONER", "Web cache poisoning with an unkeyed cookie"),
        ("PRACTITIONER", "Web cache poisoning with multiple headers"),
        ("PRACTITIONER", "Targeted web cache poisoning using an unknown header"),
        ("PRACTITIONER", "Web cache poisoning via an unkeyed query string"),
        ("PRACTITIONER", "Web cache poisoning via an unkeyed query parameter"),
        ("PRACTITIONER", "Parameter cloaking"),
        ("PRACTITIONER", "Web cache poisoning via a fat GET request"),
        ("PRACTITIONER", "URL normalization"),
        ("EXPERT", "Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria"),
        ("EXPERT", "Combining web cache poisoning vulnerabilities"),
        ("EXPERT", "Cache key injection"),
        ("EXPERT", "Internal cache poisoning"),
    ]),
    "deserialization": ("Insecure deserialization", "deserialization", [
        ("APPRENTICE", "Modifying serialized objects"),
        ("PRACTITIONER", "Modifying serialized data types"),
        ("PRACTITIONER", "Using application functionality to exploit insecure deserialization"),
        ("PRACTITIONER", "Arbitrary object injection in PHP"),
        ("PRACTITIONER", "Exploiting Java deserialization with Apache Commons"),
        ("PRACTITIONER", "Exploiting PHP deserialization with a pre-built gadget chain"),
        ("PRACTITIONER", "Exploiting Ruby deserialization using a documented gadget chain"),
        ("EXPERT", "Developing a custom gadget chain for Java deserialization"),
        ("EXPERT", "Developing a custom gadget chain for PHP deserialization"),
        ("EXPERT", "Using PHAR deserialization to deploy a custom gadget chain"),
    ]),
    "info_disclosure": ("Information disclosure", "info_disclosure", [
        ("APPRENTICE", "Information disclosure in error messages"),
        ("APPRENTICE", "Information disclosure on debug page"),
        ("APPRENTICE", "Source code disclosure via backup files"),
        ("APPRENTICE", "Authentication bypass via information disclosure"),
        ("PRACTITIONER", "Information disclosure in version control history"),
    ]),
    "business_logic": ("Business logic vulnerabilities", "business_logic", [
        ("APPRENTICE", "Excessive trust in client-side controls"),
        ("APPRENTICE", "High-level logic vulnerability"),
        ("APPRENTICE", "Inconsistent security controls"),
        ("APPRENTICE", "Flawed enforcement of business rules"),
        ("PRACTITIONER", "Low-level logic flaw"),
        ("PRACTITIONER", "Inconsistent handling of exceptional input"),
        ("PRACTITIONER", "Weak isolation on dual-use endpoint"),
        ("PRACTITIONER", "Insufficient workflow validation"),
        ("PRACTITIONER", "Authentication bypass via flawed state machine"),
        ("PRACTITIONER", "Infinite money logic flaw"),
        ("PRACTITIONER", "Authentication bypass via encryption oracle"),
        ("EXPERT", "Bypassing access controls using email address parsing discrepancies"),
    ]),
    "host_header": ("HTTP Host header attacks", "host_header", [
        ("APPRENTICE", "Basic password reset poisoning"),
        ("APPRENTICE", "Host header authentication bypass"),
        ("PRACTITIONER", "Web cache poisoning via ambiguous requests"),
        ("PRACTITIONER", "Routing-based SSRF"),
        ("PRACTITIONER", "SSRF via flawed request parsing"),
        ("PRACTITIONER", "Host validation bypass via connection state attack"),
        ("EXPERT", "Password reset poisoning via dangling markup"),
    ]),
    "oauth": ("OAuth authentication", "oauth", [
        ("APPRENTICE", "Authentication bypass via OAuth implicit flow"),
        ("PRACTITIONER", "SSRF via OpenID dynamic client registration"),
        ("PRACTITIONER", "Forced OAuth profile linking"),
        ("PRACTITIONER", "OAuth account hijacking via redirect_uri"),
        ("PRACTITIONER", "Stealing OAuth access tokens via an open redirect"),
        ("EXPERT", "Stealing OAuth access tokens via a proxy page"),
    ]),
    "file_upload": ("File upload vulnerabilities", "file_upload", [
        ("APPRENTICE", "Remote code execution via web shell upload"),
        ("APPRENTICE", "Web shell upload via Content-Type restriction bypass"),
        ("PRACTITIONER", "Web shell upload via path traversal"),
        ("PRACTITIONER", "Web shell upload via extension blacklist bypass"),
        ("PRACTITIONER", "Web shell upload via obfuscated file extension"),
        ("PRACTITIONER", "Remote code execution via polyglot web shell upload"),
        ("EXPERT", "Web shell upload via race condition"),
    ]),
    "jwt": ("JWT", "jwt", [
        ("APPRENTICE", "JWT authentication bypass via unverified signature"),
        ("APPRENTICE", "JWT authentication bypass via flawed signature verification"),
        ("PRACTITIONER", "JWT authentication bypass via weak signing key"),
        ("PRACTITIONER", "JWT authentication bypass via jwk header injection"),
        ("PRACTITIONER", "JWT authentication bypass via jku header injection"),
        ("PRACTITIONER", "JWT authentication bypass via kid header path traversal"),
        ("EXPERT", "JWT authentication bypass via algorithm confusion"),
        ("EXPERT", "JWT authentication bypass via algorithm confusion with no exposed key"),
    ]),
    "essential": ("Essential skills", "essential", [
        ("PRACTITIONER", "Discovering vulnerabilities quickly with targeted scanning"),
        ("PRACTITIONER", "Scanning non-standard data structures"),
    ]),
    "prototype_pollution": ("Prototype pollution", "prototype_pollution", [
        ("PRACTITIONER", "Client-side prototype pollution via browser APIs"),
        ("PRACTITIONER", "DOM XSS via client-side prototype pollution"),
        ("PRACTITIONER", "DOM XSS via an alternative prototype pollution vector"),
        ("PRACTITIONER", "Client-side prototype pollution via flawed sanitization"),
        ("PRACTITIONER", "Client-side prototype pollution in third-party libraries"),
        ("PRACTITIONER", "Privilege escalation via server-side prototype pollution"),
        ("PRACTITIONER", "Detecting server-side prototype pollution without polluted property reflection"),
        ("PRACTITIONER", "Bypassing flawed input filters for server-side prototype pollution"),
        ("PRACTITIONER", "Remote code execution via server-side prototype pollution"),
        ("EXPERT", "Exfiltrating sensitive data via server-side prototype pollution"),
    ]),
    "graphql": ("GraphQL API vulnerabilities", "graphql", [
        ("APPRENTICE", "Accessing private GraphQL posts"),
        ("PRACTITIONER", "Accidental exposure of private GraphQL fields"),
        ("PRACTITIONER", "Finding a hidden GraphQL endpoint"),
        ("PRACTITIONER", "Bypassing GraphQL brute force protections"),
        ("PRACTITIONER", "Performing CSRF exploits over GraphQL"),
    ]),
    "race": ("Race conditions", "race", [
        ("APPRENTICE", "Limit overrun race conditions"),
        ("PRACTITIONER", "Bypassing rate limits via race conditions"),
        ("PRACTITIONER", "Multi-endpoint race conditions"),
        ("PRACTITIONER", "Single-endpoint race conditions"),
        ("PRACTITIONER", "Exploiting time-sensitive vulnerabilities"),
        ("EXPERT", "Partial construction race conditions"),
    ]),
    "nosql": ("NoSQL injection", "nosql", [
        ("APPRENTICE", "Detecting NoSQL injection"),
        ("APPRENTICE", "Exploiting NoSQL operator injection to bypass authentication"),
        ("PRACTITIONER", "Exploiting NoSQL injection to extract data"),
        ("PRACTITIONER", "Exploiting NoSQL operator injection to extract unknown fields"),
    ]),
    "api": ("API testing", "api", [
        ("APPRENTICE", "Exploiting an API endpoint using documentation"),
        ("PRACTITIONER", "Exploiting server-side parameter pollution in a query string"),
        ("PRACTITIONER", "Finding and exploiting an unused API endpoint"),
        ("PRACTITIONER", "Exploiting a mass assignment vulnerability"),
        ("EXPERT", "Exploiting server-side parameter pollution in a REST URL"),
    ]),
    "llm": ("Web LLM attacks", "llm", [
        ("APPRENTICE", "Exploiting LLM APIs with excessive agency"),
        ("PRACTITIONER", "Exploiting vulnerabilities in LLM APIs"),
        ("PRACTITIONER", "Indirect prompt injection"),
        ("EXPERT", "Exploiting insecure output handling in LLMs"),
        ("APPRENTICE", "Exploiting AI agents to perform destructive actions"),
        ("APPRENTICE", "Exploiting AI agents to exfiltrate sensitive information"),
        ("PRACTITIONER", "Exploiting AI agents to trigger secondary vulnerabilities"),
        ("PRACTITIONER", "Bypassing AI scanner defenses to exfiltrate sensitive information"),
    ]),
    "cache_deception": ("Web cache deception", "cache_deception", [
        ("APPRENTICE", "Exploiting path mapping for web cache deception"),
        ("PRACTITIONER", "Exploiting path delimiters for web cache deception"),
        ("PRACTITIONER", "Exploiting origin server normalization for web cache deception"),
        ("PRACTITIONER", "Exploiting cache server normalization for web cache deception"),
        ("EXPERT", "Exploiting exact-match cache rules for web cache deception"),
    ]),
}


def _build_lab_db() -> dict[str, dict]:
    db: dict[str, dict] = {}
    for cat_key, (cat_title, probe, labs) in _RAW_CATALOG.items():
        entries = []
        for idx, (level, title) in enumerate(labs, start=1):
            entries.append({
                "id": f"{cat_key}-{idx:02d}",
                "level": level,
                "title": title,
                "probe": probe,
                "category": cat_key,
                "tags": derive_tags(cat_key, title),
            })
        db[cat_key] = {"title": cat_title, "probe": probe, "labs": entries}
    return db


LAB_DB: dict[str, dict] = _build_lab_db()
LAB_INDEX: dict[str, dict] = {
    lab["id"]: lab for cat in LAB_DB.values() for lab in cat["labs"]
}
TOTAL_LABS = len(LAB_INDEX)
CATEGORY_TITLES = {k: v["title"] for k, v in LAB_DB.items()}

# Probe → kategori & jumlah lab (untuk pelaporan cakupan)
PROBE_COVERAGE = {
    probe: {
        "category": cat["title"],
        "labs": len(cat["labs"]),
    }
    for probe, cat in ((v["probe"], v) for v in LAB_DB.values())
}


"""Konteks target + gerbang kelayakan (applicability) per keluarga lab.

Aturan inti anti "lab lain ikut muncul":
  1. Semua bukti HARUS berasal dari respons target yang sedang dipindai.
  2. Sebuah keluarga probe hanya dijalankan bila prasyaratnya ADA di target.
  3. Temuan wajib membawa tag; lab hanya 'detected' bila tag lab ⊆ tag temuan.
  4. Setiap temuan menyimpan `target` dan diverifikasi ulang sebelum dilaporkan.
"""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from bs4 import BeautifulSoup


# ══════════════════════════════════════════════════════════════════════════════
# KONTEKS
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class TargetContext:
    url: str
    host: str
    scheme: str
    html: str = ""
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    params: dict[str, list[str]] = field(default_factory=dict)
    js_text: str = ""
    soup: Any = None
    authorized: bool = False
    http_log: list[dict] = field(default_factory=list)
    body_lower: str = ""

    # ── helper ───────────────────────────────────────────────────────────────
    @property
    def base(self) -> str:
        p = urlparse(self.url)
        return f"{p.scheme}://{p.netloc}"

    @property
    def path(self) -> str:
        return urlparse(self.url).path or "/"

    def abs_url(self, path_or_url: str) -> str:
        from urllib.parse import urljoin
        return urljoin(self.url, path_or_url)

    def header(self, name: str) -> str:
        return str(self.headers.get(name.lower(), "") or "")

    def all_inputs(self) -> list[dict]:
        out = []
        for form in self.forms:
            out.extend(form.get("inputs", []))
        return out

    def input_names(self) -> list[str]:
        return [str(i.get("name", "")).lower() for i in self.all_inputs() if i.get("name")]

    def all_param_names(self) -> list[str]:
        return sorted(set(list(self.params) + self.input_names()))

    def cookie_names(self) -> list[str]:
        return [str(c.get("name", "")) for c in self.cookies]

    def cookie_values(self) -> list[str]:
        return [str(c.get("value", "")) for c in self.cookies if c.get("value")]

    def has_query(self) -> bool:
        return bool(self.params)

    def find_tokens(self, pattern: str, flags: int = re.I) -> list[str]:
        return re.findall(pattern, self.html or "", flags)


def build_target_context(url: str, html: str, http_result: Optional[dict] = None,
                         authorized: bool = False) -> TargetContext:
    """Bangun konteks dari SATU target saja (tidak mencampur data target lain)."""
    http_result = http_result or {}
    parsed = urlparse(url)
    soup = BeautifulSoup(html or "", "html.parser") if (html or "").strip() else None

    forms: list[dict] = []
    if soup is not None:
        for form in soup.find_all("form"):
            inputs = []
            for el in form.find_all(["input", "textarea", "select", "button"]):
                inputs.append({
                    "name": el.get("name") or "",
                    "type": (el.get("type") or el.name or "").lower(),
                    "value": el.get("value") or "",
                    "tag": el.name,
                    "accept": el.get("accept") or "",
                })
            forms.append({
                "action": form.get("action") or "",
                "method": (form.get("method") or "get").lower(),
                "enctype": (form.get("enctype") or "").lower(),
                "inputs": inputs,
                "raw": str(form)[:4000],
            })

    js_chunks: list[str] = []
    if soup is not None:
        for script in soup.find_all("script"):
            if script.string:
                js_chunks.append(script.string)
            elif script.get("src"):
                js_chunks.append(f"/* external */ {script.get('src')}")
    for m in re.findall(r"<script[^>]*>(.*?)</script>", html or "", re.S | re.I):
        js_chunks.append(m)

    headers = {str(k).lower(): str(v) for k, v in (http_result.get("headers") or {}).items()}

    return TargetContext(
        url=url,
        host=(parsed.hostname or "").lower(),
        scheme=(parsed.scheme or "https").lower(),
        html=html or "",
        status=int(http_result.get("status_code") or 0),
        headers=headers,
        cookies=list(http_result.get("cookies") or []),
        forms=forms,
        params={k: v for k, v in parse_qs(parsed.query, keep_blank_values=True).items()},
        js_text="\n".join(js_chunks),
        soup=soup,
        authorized=bool(authorized),
        body_lower=(html or "").lower(),
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEMUAN
# ══════════════════════════════════════════════════════════════════════════════
def make_finding(ctx: TargetContext, probe: str, tags: set[str], *,
                 type_: str, severity: str, evidence: str, risk: str,
                 recommendation: str, verification: str,
                 confidence: str = "confirmed") -> dict:
    """Finding selalu membawa target + tag; dipakai untuk atribusi lab."""
    return {
        "type": type_,
        "severity": severity.lower(),
        "evidence": evidence,
        "risk": risk,
        "recommendation": recommendation,
        "verification": verification,
        "probe": probe,
        "tags": sorted(set(tags)),
        "confidence": confidence,
        "target": ctx.url,
        "host": ctx.host,
        "section": "portswigger",
    }


# ══════════════════════════════════════════════════════════════════════════════
# PRASYARAT / APPLICABILITY
# ══════════════════════════════════════════════════════════════════════════════
LOGIN_HINTS = re.compile(r"type=[\"']?password", re.I)
REDIRECT_PARAMS = {"redirect", "redirect_uri", "redirect_url", "next", "return",
                   "returnurl", "return_url", "dest", "destination", "continue",
                   "url", "target", "r", "to"}
FILE_PARAMS = {"file", "filename", "path", "page", "template", "img", "image",
               "download", "doc", "document", "folder", "dir", "load", "read"}
URL_PARAMS = {"url", "uri", "dest", "destination", "host", "image", "img", "src",
              "source", "feed", "webhook", "callback", "proxy", "site", "link"}
SERIALIZED_RE = re.compile(r"(rO0AB|O:\d+:\"|a:\d+:\{|__PHP_Incomplete_Class|aced0005)", re.I)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}")


def _has_login_form(ctx: TargetContext) -> bool:
    return any(
        any(i.get("type") == "password" for i in f["inputs"])
        for f in ctx.forms
    )


def _has_post_form(ctx: TargetContext) -> bool:
    return any(f["method"] == "post" for f in ctx.forms)


def _has_text_input(ctx: TargetContext) -> bool:
    return any(i.get("type") in ("text", "search", "textarea", "email", "")
               for i in ctx.all_inputs())


def _has_xml_surface(ctx: TargetContext) -> bool:
    low = ctx.html.lower()
    if "application/xml" in low or "text/xml" in low or "soap" in low:
        return True
    if any("xml" in (f.get("enctype") or "") for f in ctx.forms):
        return True
    return bool(re.search(r"<[a-z]+:[a-z]+[^>]*xmlns", ctx.html, re.I))


def _has_upload(ctx: TargetContext) -> bool:
    return any(i.get("type") == "file" for i in ctx.all_inputs())


def _has_jwt(ctx: TargetContext) -> bool:
    blob = " ".join(ctx.cookie_values()) + " " + ctx.html
    return bool(JWT_RE.search(blob))


def _has_serialized(ctx: TargetContext) -> bool:
    blob = " ".join(ctx.cookie_values())
    for value in ctx.cookie_values():
        if SERIALIZED_RE.search(value):
            return True
        try:
            decoded = base64.b64decode(value + "===").decode("latin-1", "ignore")
            if SERIALIZED_RE.search(decoded):
                return True
        except Exception:
            continue
    return bool(SERIALIZED_RE.search(blob))


def _has_json_api(ctx: TargetContext) -> bool:
    low = ctx.html.lower()
    return ("application/json" in low or "content-type': 'application/json" in low
            or "/api/" in low or '"username"' in low)


def _has_websocket(ctx: TargetContext) -> bool:
    return bool(re.search(r"(new\s+WebSocket|wss?://|Sec-WebSocket)", ctx.html, re.I))


def _has_graphql_hint(ctx: TargetContext) -> bool:
    return bool(re.search(r"(graphql|__schema|__typename)", ctx.html, re.I))


def _has_cache_surface(ctx: TargetContext) -> bool:
    return any(h in ctx.headers for h in ("age", "x-cache", "cf-cache-status",
                                          "x-cache-status", "cdn-cache-control"))


def _has_oauth(ctx: TargetContext) -> bool:
    return bool(re.search(r"(oauth|client_id=|redirect_uri=|/auth/|openid)", ctx.html, re.I))


def _has_host_header_surface(ctx: TargetContext) -> bool:
    return bool(re.search(r"(password reset|forgot|reset password|/reset|/forgot)", ctx.html, re.I))


def _has_llm_surface(ctx: TargetContext) -> bool:
    return bool(re.search(r"(chatbot|ai assistant|/chat|message|prompt|llm|openai)", ctx.html, re.I))


def _has_api_docs(ctx: TargetContext) -> bool:
    return bool(re.search(r"(swagger|openapi|/api/v\d|/rest/|/documentation)", ctx.html, re.I))


def _has_proto_hint(ctx: TargetContext) -> bool:
    return bool(re.search(r"(__proto__|constructor\s*\[\s*['\"]prototype|Object\.assign|"
                          r"location\.(hash|search)|qs\.parse|jQuery\.extend)", ctx.html, re.I))


def _has_ssrf_surface(ctx: TargetContext) -> bool:
    names = {n.lower() for n in ctx.all_param_names()}
    return bool(names & URL_PARAMS) or "stockapi" in ctx.body_lower


def _has_path_surface(ctx: TargetContext) -> bool:
    names = {n.lower() for n in ctx.all_param_names()}
    if names & FILE_PARAMS:
        return True
    return bool(re.search(r"(filename|/image\?|/download\?|/file\?)", ctx.html + ctx.url, re.I))


def _has_redirect_surface(ctx: TargetContext) -> bool:
    names = {n.lower() for n in ctx.all_param_names()}
    return bool(names & REDIRECT_PARAMS)


def _has_any_injection_surface(ctx: TargetContext) -> bool:
    return bool(ctx.params) or _has_text_input(ctx)


def applicability(ctx: TargetContext) -> dict[str, tuple[bool, str]]:
    """Apakah keluarga probe layak dijalankan pada target INI?"""
    a: dict[str, tuple[bool, str]] = {}

    a["sqli"] = (bool(ctx.params) or _has_text_input(ctx),
                 "tidak ada parameter/input yang bisa diuji")
    a["nosql"] = (_has_json_api(ctx) or _has_login_form(ctx),
                  "tidak ada endpoint JSON/login untuk operator NoSQL")
    a["xss"] = (bool(ctx.params) or _has_post_form(ctx) or bool(ctx.js_text),
                "tidak ada parameter, form, atau JavaScript")
    a["dom"] = (bool(ctx.js_text), "tidak ada JavaScript pada halaman")
    a["csrf"] = (_has_post_form(ctx), "tidak ada form POST")
    a["clickjacking"] = (True, "")
    a["cors"] = (True, "")
    a["xxe"] = (_has_xml_surface(ctx), "tidak ada permukaan XML/SOAP")
    a["ssrf"] = (_has_ssrf_surface(ctx), "tidak ada parameter URL/helper")
    a["smuggling"] = (bool(ctx.headers.get("server") or ctx.headers.get("via")),
                      "tidak ada indikasi front-end/proxy")
    a["os_command"] = (bool(ctx.params) or _has_text_input(ctx),
                       "tidak ada parameter yang bisa diuji")
    a["ssti"] = (bool(ctx.params) or _has_text_input(ctx),
                 "tidak ada parameter yang direfleksikan")
    a["path_traversal"] = (_has_path_surface(ctx), "tidak ada parameter nama file/path")
    a["access_control"] = (True, "")
    a["auth"] = (_has_login_form(ctx) or bool(LOGIN_HINTS.search(ctx.html)),
                 "tidak ada form login")
    a["websocket"] = (_has_websocket(ctx), "tidak ada WebSocket pada halaman")
    a["cache_poisoning"] = (_has_cache_surface(ctx), "tidak ada indikasi cache (Age/X-Cache)")
    a["cache_deception"] = (_has_cache_surface(ctx) or bool(ctx.cookies),
                            "tidak ada cache maupun sesi")
    a["deserialization"] = (_has_serialized(ctx), "tidak ada cookie/objek terserialisasi")
    a["info_disclosure"] = (True, "")
    a["business_logic"] = (True, "")
    a["host_header"] = (_has_host_header_surface(ctx) or "host" in ctx.body_lower,
                        "tidak ada fitur yang memakai Host (mis. reset password)")
    a["oauth"] = (_has_oauth(ctx), "tidak ada alur OAuth/OIDC")
    a["file_upload"] = (_has_upload(ctx), "tidak ada input upload file")
    a["jwt"] = (_has_jwt(ctx), "tidak ada token JWT")
    a["essential"] = (True, "")
    a["prototype_pollution"] = (_has_proto_hint(ctx) or bool(ctx.params),
                                "tidak ada sink/sumber prototype pollution")
    a["graphql"] = (_has_graphql_hint(ctx) or _has_api_docs(ctx),
                    "tidak ada endpoint GraphQL")
    a["race"] = (bool(ctx.forms) or bool(ctx.params),
                 "tidak ada endpoint transaksional")
    a["api"] = (_has_api_docs(ctx) or _has_json_api(ctx), "tidak ada permukaan API")
    a["llm"] = (_has_llm_surface(ctx), "tidak ada fitur LLM/chat")
    return a


"""Probe PASIF — hanya memakai bukti yang benar-benar ada pada respons target.

Prinsip:
  * Tidak ada temuan tanpa bukti tekstual/struktural dari target ini.
  * `confidence="confirmed"` hanya untuk fakta yang bisa dibuktikan dari satu respons
    (header hilang, token JWT `alg=none`, cookie terserialisasi, dsb.).
  * `confidence="candidate"` untuk indikasi kuat yang butuh uji aktif satu langkah.
"""

import base64
import binascii
import json
import re
from typing import Callable

from bs4 import BeautifulSoup

PASSIVE_PROBES: dict[str, list[Callable]] = {}


def passive(key: str):
    def deco(fn):
        PASSIVE_PROBES.setdefault(key, []).append(fn)
        return fn
    return deco


# ── util ─────────────────────────────────────────────────────────────────────
def _snip(text: str, needle: str, span: int = 110) -> str:
    idx = (text or "").lower().find((needle or "").lower())
    if idx < 0:
        return ""
    lo = max(0, idx - span // 2)
    return re.sub(r"\s+", " ", text[lo:idx + span]).strip()


def _reflection_context(html: str, idx: int) -> str:
    """Tentukan konteks HTML dengan melihat tag yang mengurung posisi idx."""
    before = html[:idx]
    last_open = before.rfind("<")
    last_close = before.rfind(">")
    if last_open > last_close:                      # di dalam tag
        tag_start = before.rfind("<", 0, last_open + 1)
        tag = before[tag_start:last_open + 1].lower()
        if tag.startswith("<script"):
            return "javascript"
        return "attribute"
    script_open = before.lower().rfind("<script")
    script_close = before.lower().rfind("</script")
    if script_open > script_close:
        return "javascript"
    return "html"


def _oneline(text: str, limit: int = 160) -> str:
    return re.sub(r"\s+", " ", text or "").strip()[:limit]


def _find_jwts(ctx) -> list[str]:
    blob = " ".join(ctx.cookie_values()) + " " + ctx.html
    return list(dict.fromkeys(jwt for jwt in JWT_TOKEN_RE.findall(blob) if jwt.count(".") >= 2))


JWT_TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")


def _b64url_json(part: str) -> dict:
    try:
        pad = "=" * (-len(part) % 4)
        raw = base64.urlsafe_b64decode(part + pad)
        return json.loads(raw.decode("utf-8", "ignore"))
    except Exception:
        return {}


SQL_ERROR_SIGNATURES = [
    ("sqlite", "sqlite error"),
    ("mysql", "you have an error in your sql syntax"),
    ("mysql", "warning: mysql"),
    ("postgresql", "pg_query()"),
    ("postgresql", "postgresql query failed"),
    ("mssql", "microsoft ole db provider for sql server"),
    ("mssql", "unclosed quotation mark after the character string"),
    ("oracle", "ora-01756"),
    ("oracle", "quoted string not properly terminated"),
    ("generic", "sql syntax"),
    ("generic", "sqlstate["),
]

STACKTRACE_SIGNATURES = [
    "traceback (most recent call last)",
    "fatal error:",
    "warning: include(",
    "notice: undefined",
    "django version",
    "werkzeug debugger",
    "stack trace:",
    "org.springframework.beans",
    "java.lang.nullpointerexception",
    "at java.base/",
]

BACKUP_HINTS = re.compile(r"(\.git/head|\.git/config|\.env\b|\.bak\b|\.old\b|~$|\.sql\b|backup\.zip)", re.I)


# ══════════════════════════════════════════════════════════════════════════════
# SQL injection
# ══════════════════════════════════════════════════════════════════════════════
@passive("sqli")
def p_sqli_errors(ctx):
    out = []
    low = ctx.body_lower
    for dbms, sig in SQL_ERROR_SIGNATURES:
        if sig in low:
            out.append(make_finding(
                ctx, "sqli", {"sql_injection", "error_based"},
                type_="SQL error terekspos pada respons",
                severity="medium",
                evidence=(f"Frasa error SQL ({dbms}) ditemukan pada respons {ctx.url}: "
                          f"\"{_snip(ctx.html, sig)}\""),
                risk="Pesan error basis data membocorkan struktur query; jika input masuk ke query, "
                     "ini jalur injeksi dan enumerasi skema.",
                recommendation="Matikan detail error di production, gunakan parameterized query, "
                               "dan validasi tipe input.",
                verification="deterministic_sql_error_signature",
                confidence="candidate",
            ))
            break
    return out


# ══════════════════════════════════════════════════════════════════════════════
# XSS / DOM
# ══════════════════════════════════════════════════════════════════════════════
DOM_SINK_PATTERNS = [
    (r"document\.write\s*\([^)]{0,80}location\.(search|hash)", "document.write(location.*)", "doc_write"),
    (r"\.innerHTML\s*=\s*[^;\n]{0,80}location\.(search|hash)", "innerHTML = location.*", "inner_html"),
    (r"\$\(\s*location\.(hash|search)\s*\)", "$(location.hash|search)", "jquery_selector"),
    (r"eval\s*\(\s*location\.(hash|search)", "eval(location.*)", ""),
    (r"document\.write\s*\([^)]{0,80}document\.(URL|referrer)", "document.write(document.URL)", "doc_write"),
]


@passive("xss")
def p_xss_reflection(ctx):
    out = []
    html = ctx.html or ""
    for name, values in ctx.params.items():
        for value in values:
            if len(value) < 3:
                continue
            if value not in html:
                continue
            idx = html.find(value)
            where = _reflection_context(html, idx)
            if where == "javascript":
                ctx_tags = {"xss", "reflected", "javascript_context"}
                label = "di dalam konteks JavaScript"
            elif where == "attribute":
                ctx_tags = {"xss", "reflected", "attribute_context"}
                label = "di dalam nilai atribut"
            else:
                ctx_tags = {"xss", "reflected"}
                label = "di dalam konteks HTML"
            unsafe = any(ch in value for ch in "<>\"'")
            ctx_tags.add("nothing_encoded")   # nilai muncul mentah = tidak ada encoding
            out.append(make_finding(
                ctx, "xss", ctx_tags,
                type_=f"Parameter '{name}' direfleksikan tanpa encoding ke respons ({label})",
                severity="high" if unsafe else "info",
                evidence=(f"Nilai parameter '{name}' muncul apa adanya di respons; konteks: {label}. "
                          f"Cuplikan: \"{_snip(html, value)}\""),
                risk=("Nilai yang direfleksikan tanpa encoding memungkinkan XSS bila penyerang "
                      "mengirim payload HTML/JS."),
                recommendation="Encode output sesuai konteks (HTML/atribut/JS) dan terapkan CSP dengan nonce.",
                verification="deterministic_reflection_context",
                confidence="confirmed" if unsafe else "candidate",
            ))
            break
    return out


@passive("xss")
def p_xss_dom_sinks(ctx):
    out = []
    js = ctx.js_text or ""
    for pattern, label, sink_tag in DOM_SINK_PATTERNS:
        m = re.search(pattern, js, re.I)
        if m:
            tags = {"xss", "dom", "dom_sink"}
            if sink_tag:
                tags.add(sink_tag)
            out.append(make_finding(
                ctx, "xss", tags,
                type_="DOM XSS: sink berbahaya menerima source dari URL",
                severity="high",
                evidence=f"Pola `{label}` ditemukan pada JavaScript target: \"{_snip(js, m.group(0))}\"",
                risk="Source yang dikendalikan URL mengalir ke sink eksekusi; payload dapat dijalankan tanpa refleksi server.",
                recommendation="Gunakan textContent/setAttribute, hindari document.write/innerHTML dengan data URL, "
                               "dan terapkan Trusted Types.",
                verification="deterministic_dom_sink_source",
            ))
            break
    if re.search(r"ng-app|angular\.module|\{\{.*\}\}", ctx.html or "", re.I) and re.search(
            r"\{\{", ctx.html or ""):
        out.append(make_finding(
            ctx, "xss", {"xss", "angularjs"},
            type_="AngularJS expression sink terdeteksi", severity="medium",
            evidence="Halaman memuat AngularJS (ng-app / {{ }}) sehingga ekspresi pengguna dapat dievaluasi.",
            risk="Bila input masuk ke ekspresi AngularJS tanpa sanitasi, sandbox escape dapat berujung XSS.",
            recommendation="Hindari menaruh input pengguna pada konteks template AngularJS; perketat CSP.",
            verification="deterministic_angularjs_hint",
            confidence="candidate",
        ))
    return out


@passive("dom")
def p_dom_messages(ctx):
    out = []
    js = ctx.js_text or ""
    if not re.search(r"addEventListener\(\s*['\"]message['\"]", js, re.I):
        return out
    if re.search(r"(eval|innerHTML|document\.write|location(\.href)?\s*=)", js, re.I):
        tags = {"dom", "web_message"}
        if re.search(r"JSON\.parse", js, re.I):
            tags.add("json_parse")
        if re.search(r"(javascript:|location\s*=)", js, re.I):
            tags.add("javascript_context")
        out.append(make_finding(
            ctx, "dom", tags,
            type_="DOM XSS via postMessage tanpa validasi origin",
            severity="high",
            evidence="Handler 'message' meneruskan data ke sink eksekusi; cuplikan: "
                     f"\"{_snip(js, 'addEventListener')}\"",
            risk="Halaman lain dapat mengirim pesan dan mengeksekusi JavaScript di origin target.",
            recommendation="Validasi event.origin terhadap allowlist dan jangan meneruskan data pesan ke sink HTML/JS.",
            verification="deterministic_postmessage_sink",
        ))
    if re.search(r"(location\s*=\s*[^;\n]{0,40}(location\.(search|hash)|document\.referrer))", js, re.I):
        out.append(make_finding(
            ctx, "dom", {"dom", "open_redirect"},
            type_="DOM-based open redirection", severity="medium",
            evidence=f"JavaScript menetapkan location dari sumber URL: \"{_snip(js, 'location')}\"",
            risk="Penyerang dapat mengalihkan pengguna ke domain berbahaya dari tautan target.",
            recommendation="Validasi tujuan redirect terhadap allowlist path/host.",
            verification="deterministic_dom_redirect",
        ))
    if re.search(r"document\.cookie\s*=\s*[^;\n]{0,60}(location|document\.URL)", js, re.I):
        out.append(make_finding(
            ctx, "dom", {"dom", "cookie_manipulation"},
            type_="DOM-based cookie manipulation", severity="medium",
            evidence="document.cookie diisi dari sumber URL.",
            risk="Cookie dapat diubah lintas halaman dan memengaruhi perilaku aplikasi.",
            recommendation="Jangan menurunkan cookie dari input URL; gunakan HttpOnly untuk cookie sesi.",
            verification="deterministic_dom_cookie",
        ))
    if re.search(r"(id\s*=\s*['\"][^'\"]+['\"][^>]*name\s*=|document\.getElementById\([^)]*\)\.(src|href))", ctx.html or "", re.I) \
            and re.search(r"document\.(forms|getElementById)", js, re.I):
        out.append(make_finding(
            ctx, "dom", {"dom", "dom_clobbering"},
            type_="Indikasi DOM clobbering (elemen id/name dapat menimpa variabel global)",
            severity="low",
            evidence="Halaman memakai akses DOM berdasarkan id/name sementara HTML mengizinkan elemen penimpa.",
            risk="Penyerang dapat menimpa variabel global untuk melewati filter atau mengubah alur.",
            recommendation="Gunakan akses eksplisit (querySelector + verifikasi tipe) dan hindari mengandalkan global DOM.",
            verification="deterministic_dom_clobbering_hint",
            confidence="candidate",
        ))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CSRF / clickjacking / CORS
# ══════════════════════════════════════════════════════════════════════════════
CSRF_TOKEN_NAMES = {"csrf", "csrf_token", "csrftoken", "xsrf", "xsrf_token",
                    "authenticity_token", "_token", "nonce", "csrfmiddlewaretoken",
                    "__requestverificationtoken", "csrf-token"}


@passive("csrf")
def p_csrf_forms(ctx):
    out = []
    soup = ctx.soup or BeautifulSoup(ctx.html or "", "html.parser")
    has_csrf_meta = any(
        "csrf" in (m.get("name") or "").lower() or "xsrf" in (m.get("name") or "").lower()
        for m in soup.find_all("meta")
    )
    session_cookie = any(
        any(k in (c.get("name") or "").lower() for k in ("session", "auth", "sid", "token"))
        for c in ctx.cookies
    )
    samesite_protected = any(
        any(k in (c.get("name") or "").lower() for k in ("session", "auth", "sid"))
        and (c.get("samesite") or "").lower() in ("lax", "strict")
        for c in ctx.cookies
    )
    unprotected = []
    for form in soup.find_all("form"):
        if (form.get("method") or "get").lower() != "post":
            continue
        has_token = any(
            (i.get("type") or "").lower() == "hidden"
            and any(t in (i.get("name") or "").lower() for t in CSRF_TOKEN_NAMES)
            for i in form.find_all("input")
        )
        if has_token or has_csrf_meta or samesite_protected:
            continue
        unprotected.append(form.get("action") or "(self)")
    if unprotected and (session_cookie or ctx.cookies):
        out.append(make_finding(
            ctx, "csrf", {"csrf", "no_csrf_defense"},
            type_="Form POST tanpa proteksi CSRF",
            severity="medium",
            evidence=(f"{len(unprotected)} form POST tanpa token CSRF, tanpa meta CSRF, dan cookie sesi "
                      f"tanpa SameSite=Lax/Strict. Contoh action: " + ", ".join(unprotected[:4])),
            risk="Form dapat dikirim dari origin lain saat korban terautentikasi.",
            recommendation="Tambahkan token CSRF per-sesi yang divalidasi server-side dan set SameSite=Lax.",
            verification="deterministic_csrf_form_analysis",
        ))
    return out


@passive("clickjacking")
def p_clickjacking(ctx):
    if not ctx.headers:
        return []
    xfo = ctx.header("x-frame-options")
    csp = ctx.header("content-security-policy").lower()
    if xfo or "frame-ancestors" in csp:
        return []
    if ctx.status in (401, 403, 429) or ctx.status >= 500:
        return []
    soup = ctx.soup or BeautifulSoup(ctx.html or "", "html.parser")
    sensitive = bool(soup.find("form")) or bool(soup.find("input", {"type": "password"}))
    return [make_finding(
        ctx, "clickjacking", {"clickjacking"},
        type_="Halaman dapat di-frame (clickjacking)",
        severity="medium",
        evidence=(f"Tidak ada X-Frame-Options dan tidak ada CSP frame-ancestors pada {ctx.url} "
                  f"(HTTP {ctx.status}); halaman {'memuat form' if sensitive else 'tidak memuat form'}."),
        risk="Penyerang dapat menempatkan halaman dalam iframe transparan dan menipu klik pengguna.",
        recommendation="Set X-Frame-Options: DENY/SAMEORIGIN atau CSP frame-ancestors 'self'.",
        verification="passive_frame_header_absence_only",
        confidence="candidate",
    )]


@passive("cors")
def p_cors_headers(ctx):
    acao = ctx.header("access-control-allow-origin")
    acac = ctx.header("access-control-allow-credentials").lower()
    if not acao:
        return []
    if acao == "*" and acac == "true":
        return [make_finding(
            ctx, "cors", {"cors"},
            type_="Konfigurasi CORS tidak valid (wildcard dengan credentials)",
            severity="medium",
            evidence=f"Access-Control-Allow-Origin: * bersama Access-Control-Allow-Credentials: true.",
            risk="Konfigurasi ini ditolak browser, tetapi menunjukkan kebijakan CORS longgar.",
            recommendation="Gunakan allowlist origin eksplisit dan hindari wildcard untuk endpoint berautentikasi.",
            verification="deterministic_cors_header_check",
            confidence="candidate",
        )]
    return []


# ══════════════════════════════════════════════════════════════════════════════
# Information disclosure
# ══════════════════════════════════════════════════════════════════════════════
@passive("info_disclosure")
def p_info_disclosure(ctx):
    out = []
    low = ctx.body_lower
    for sig in STACKTRACE_SIGNATURES:
        if sig in low:
            out.append(make_finding(
                ctx, "info_disclosure", {"info_disclosure", "error_based"},
                type_="Stack trace / pesan error internal terekspos",
                severity="medium",
                evidence=f"Pola \"{sig}\" ditemukan pada respons: \"{_snip(ctx.html, sig)}\"",
                risk="Detail internal (path, framework, versi, query) membantu penyerang menyusun serangan.",
                recommendation="Nonaktifkan mode debug, tangani exception secara generik, dan log detail di server.",
                verification="deterministic_stacktrace_signature",
            ))
            break
    if re.search(r"(phpinfo\(\)|php version|server at |document root|debug\s*=\s*true)", low):
        out.append(make_finding(
            ctx, "info_disclosure", {"info_disclosure", "debug_exposure"},
            type_="Halaman debug / konfigurasi internal dapat diakses",
            severity="medium",
            evidence=f"Penanda halaman debug ditemukan: \"{_snip(ctx.html, 'phpinfo')}\"",
            risk="Halaman debug membocorkan konfigurasi, path, dan variabel lingkungan.",
            recommendation="Blokir akses halaman debug/status di production.",
            verification="deterministic_debug_marker",
        ))
    for m in BACKUP_HINTS.finditer(ctx.html or ""):
        token = m.group(0)
        out.append(make_finding(
            ctx, "info_disclosure", {"info_disclosure", "backup_file"},
            type_="Referensi file backup / metadata versi terekspos",
            severity="low",
            evidence=f"Referensi \"{token}\" ditemukan di HTML: \"{_snip(ctx.html, token)}\"",
            risk="File backup atau metadata VCS dapat membocorkan source code dan kredensial.",
            recommendation="Hapus file backup dari document root dan blokir akses .git/.env.",
            verification="deterministic_backup_reference",
            confidence="candidate",
        ))
        break
    comments = re.findall(r"<!--(.*?)-->", ctx.html or "", re.S)
    for comment in comments:
        if re.search(r"(password|secret|token|api[_-]?key|todo|fixme)", comment, re.I):
            out.append(make_finding(
                ctx, "info_disclosure", {"info_disclosure"},
                type_="Komentar HTML memuat informasi sensitif",
                severity="low",
                evidence=f"Komentar: \"{_oneline(comment)}\"",
                risk="Komentar pengembang dapat membocorkan kredensial atau logika internal.",
                recommendation="Hapus komentar sensitif dari output produksi.",
                verification="deterministic_html_comment",
                confidence="candidate",
            ))
            break
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Access control / authentication
# ══════════════════════════════════════════════════════════════════════════════
@passive("access_control")
def p_access_control(ctx):
    out = []
    soup = ctx.soup or BeautifulSoup(ctx.html or "", "html.parser")
    admin_links = [a.get("href") for a in soup.find_all("a", href=True)
                   if re.search(r"/(admin|administrator|manage|internal)", str(a.get("href")), re.I)]
    if admin_links:
        out.append(make_finding(
            ctx, "access_control", {"access_control", "admin_panel"},
            type_="Tautan panel admin terekspos pada halaman pengguna",
            severity="low",
            evidence=f"Tautan admin ditemukan: {', '.join(sorted(set(map(str, admin_links)))[:5])}",
            risk="Jika otorisasi tidak dicek server-side, panel admin dapat diakses langsung.",
            recommendation="Terapkan otorisasi per-peran di server dan jangan mengandalkan penyembunyian URL.",
            verification="deterministic_admin_link",
            confidence="candidate",
        ))
    id_params = [n for n in ctx.all_param_names() if n in ("id", "userid", "user_id", "account", "uid")]
    if id_params:
        out.append(make_finding(
            ctx, "access_control", {"access_control", "idor"},
            type_="Parameter identitas objek dikendalikan klien",
            severity="low",
            evidence=f"Parameter identitas ditemukan: {', '.join(id_params)}; nilai dipakai langsung oleh aplikasi.",
            risk="Mengubah nilai dapat mengakses objek milik pengguna lain (IDOR).",
            recommendation="Verifikasi kepemilikan objek di server untuk setiap permintaan.",
            verification="deterministic_idor_param",
            confidence="candidate",
        ))
    role_params = [n for n in ctx.all_param_names() if re.search(r"(role|admin|is_?admin|privilege)", n, re.I)]
    if role_params:
        out.append(make_finding(
            ctx, "access_control", {"access_control", "role_param"},
            type_="Peran/privilege dikirim sebagai parameter klien",
            severity="medium",
            evidence=f"Parameter terkait peran: {', '.join(role_params)}.",
            risk="Jika server mempercayai nilai ini, eskalasi hak akses mungkin dilakukan.",
            recommendation="Simpan peran di sesi server-side; jangan terima peran dari klien.",
            verification="deterministic_role_param",
            confidence="candidate",
        ))
    return out


@passive("auth")
def p_auth_forms(ctx):
    out = []
    soup = ctx.soup or BeautifulSoup(ctx.html or "", "html.parser")
    for form in soup.find_all("form"):
        pwds = form.find_all("input", {"type": "password"})
        if not pwds:
            continue
        method = (form.get("method") or "get").lower()
        action = form.get("action") or "(self)"
        if method == "get":
            out.append(make_finding(
                ctx, "auth", {"authentication"},
                type_="Form login menggunakan method GET",
                severity="critical",
                evidence=f"Form login action={action} method=GET.",
                risk="Kredensial masuk ke URL, riwayat browser, log server, dan Referer.",
                recommendation="Ubah method form login menjadi POST.",
                verification="deterministic_login_method",
            ))
        break
    if re.search(r"(forgot|reset)[-_ ]?password|/reset", ctx.html or "", re.I):
        out.append(make_finding(
            ctx, "auth", {"authentication", "password_reset"},
            type_="Alur reset password tersedia", severity="info",
            evidence=f"Tautan/endpoint reset password terdeteksi pada {ctx.url}.",
            risk="Alur reset sering memuat token yang dapat diprediksi atau poisoning via Host.",
            recommendation="Gunakan token acak sekali-pakai, validasi Host, dan kedaluwarsakan cepat.",
            verification="deterministic_password_reset_surface",
            confidence="candidate",
        ))
    if re.search(r"(verification code|2fa|mfa|authenticator|otp)", ctx.html or "", re.I):
        out.append(make_finding(
            ctx, "auth", {"authentication", "two_fa"},
            type_="Alur 2FA terdeteksi", severity="info",
            evidence="Halaman memuat input langkah kedua (kode verifikasi/OTP).",
            risk="Jika status 2FA ditentukan klien, langkah kedua dapat dilewati.",
            recommendation="Simpan status 2FA di sesi server-side dan validasi setiap langkah.",
            verification="deterministic_2fa_surface",
            confidence="candidate",
        ))
    if re.search(r"(remember[-_ ]?me|stay[-_ ]?logged)", ctx.html or "", re.I):
        out.append(make_finding(
            ctx, "auth", {"authentication", "cookie_bruteforce"},
            type_="Fitur stay-logged-in aktif", severity="info",
            evidence="Form login memuat opsi remember-me.",
            risk="Cookie remember-me yang dapat diprediksi/di-brute-force memberi akses persisten.",
            recommendation="Gunakan token acak panjang yang disimpan server-side dan dapat dicabut.",
            verification="deterministic_remember_me",
            confidence="candidate",
        ))
    return out


# RULE-ANCHOR: JWT / deserialization / cache / host header / websocket / graphql / api / others


"""Probe PASIF (lanjutan) — keluarga lab yang tersisa."""

import base64
import re

from bs4 import BeautifulSoup

PASSIVE_PROBES = globals().get("PASSIVE_PROBES", {})
if "passive" not in globals():
    def passive(key: str):
        def deco(fn):
            PASSIVE_PROBES.setdefault(key, []).append(fn)
            return fn
        return deco


# ══════════════════════════════════════════════════════════════════════════════
# JWT
# ══════════════════════════════════════════════════════════════════════════════
@passive("jwt")
def p_jwt_structure(ctx):
    out = []
    for token in _find_jwts(ctx):
        parts = token.split(".")
        header = _b64url_json(parts[0]) if len(parts) >= 2 else {}
        alg = str(header.get("alg", "")).lower()
        tags = {"jwt"}
        note = ""

        if len(parts) == 2 or alg in ("none", ""):
            tags.add("jwt_unverified")
            out.append(make_finding(
                ctx, "jwt", tags,
                type_="JWT tanpa signature valid (alg none / unsigned)",
                severity="critical",
                evidence=f"Token JWT memakai alg={alg or 'kosong'} dengan {len(parts)} segmen: {token[:60]}...",
                risk="Klaim dapat diubah siapa pun dan diterima server tanpa verifikasi signature.",
                recommendation="Tolak alg 'none', verifikasi signature dengan library standar, dan validasi klaim.",
                verification="deterministic_jwt_alg_none",
            ))
            continue

        if "jwk" in header:
            tags.add("jwt_jwk")
            note = "header memuat JWK tertanam"
            out.append(make_finding(
                ctx, "jwt", tags,
                type_="JWT menerima JWK yang ditanam di header",
                severity="high",
                evidence=f"Header JWT memuat JWK: {str(header.get('jwk'))[:160]}",
                risk="Penyerang dapat menyisipkan kunci publik sendiri dan menandatangani token.",
                recommendation="Jangan memakai kunci dari header; gunakan kunci server yang tetap.",
                verification="deterministic_jwt_jwk_header",
            ))
        if "jku" in header:
            tags.add("jwt_jku")
            out.append(make_finding(
                ctx, "jwt", tags,
                type_="JWT memakai JKU dari header",
                severity="high",
                evidence=f"Header JWT memuat jku={str(header.get('jku'))[:160]}",
                risk="Penyerang dapat mengarahkan verifikasi ke JWKS miliknya.",
                recommendation="Batasi jku ke domain tepercaya atau hilangkan dukungan jku.",
                verification="deterministic_jwt_jku_header",
            ))
        kid = str(header.get("kid", ""))
        if kid and re.search(r"(\.\.|/|\\)", kid):
            tags.add("jwt_kid")
            out.append(make_finding(
                ctx, "jwt", tags,
                type_="JWT kid berisi path (path traversal)",
                severity="high",
                evidence=f"Header JWT kid={kid[:120]!r} memuat karakter path.",
                risk="kid dapat dipakai membaca file kunci lain atau memilih kunci penyerang.",
                recommendation="Validasi kid terhadap allowlist identifier, jangan pakai sebagai path.",
                verification="deterministic_jwt_kid_path",
            ))
        if alg in ("hs256", "hs384", "hs512"):
            tags.add("jwt_weak_key")
            out.append(make_finding(
                ctx, "jwt", tags,
                type_="JWT HMAC (HS256/384/512) berpotensi weak key",
                severity="medium",
                evidence=f"Token memakai {alg}; kekuatan bergantung pada entropi secret.",
                risk="Secret lemah dapat di-brute-force offline sehingga token dapat dipalsukan.",
                recommendation="Gunakan secret acak >=256-bit atau beralih ke RS256/EdDSA.",
                verification="deterministic_jwt_hmac",
                confidence="candidate",
            ))
        elif alg.startswith("rs") or alg.startswith("es"):
            tags.add("jwt_alg_confusion")
            out.append(make_finding(
                ctx, "jwt", tags,
                type_="JWT asimetris berpotensi algorithm confusion",
                severity="medium",
                evidence=f"Token memakai {alg}; server harus menolak alg yang tidak diharapkan.",
                risk="Jika server menerima HS256 dengan public key sebagai secret, token dapat dipalsukan.",
                recommendation="Kunci algoritma yang diizinkan per endpoint dan tolak perubahan alg.",
                verification="deterministic_jwt_asymmetric",
                confidence="candidate",
            ))
        if note and not out:
            out.append(make_finding(
                ctx, "jwt", tags,
                type_="JWT ditemukan pada sesi", severity="info",
                evidence=f"JWT terdeteksi ({note}).", risk="Permukaan uji token.",
                recommendation="Verifikasi signature dan klaim di server.",
                verification="deterministic_jwt_present", confidence="candidate",
            ))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Insecure deserialization
# ══════════════════════════════════════════════════════════════════════════════
PHP_SERIALIZED = re.compile(r'(^|[;{}])([aOsib]:\d+[:;])')
JAVA_SERIALIZED = re.compile(r"rO0AB|aced0005")
RUBY_SERIALIZED = re.compile(r"BAhJ|Marshal\.dump")


@passive("deserialization")
def p_deserialization(ctx):
    out = []
    for cookie in ctx.cookies:
        value = str(cookie.get("value") or "")
        name = cookie.get("name") or "?"
        if not value:
            continue
        candidates = [value]
        try:
            candidates.append(base64.b64decode(value + "===").decode("latin-1", "ignore"))
        except Exception:
            pass
        joined = " ".join(candidates)

        if PHP_SERIALIZED.search(joined):
            out.append(make_finding(
                ctx, "deserialization", {"deserialization", "serialized_object", "php_object"},
                type_="Cookie berisi objek PHP terserialisasi",
                severity="high",
                evidence=f"Cookie '{name}' memuat struktur serialize PHP: {joined[:120]}",
                risk="Jika objek di-deserialize tanpa allowlist kelas, injeksi objek dapat berujung RCE.",
                recommendation="Gunakan JSON/HMAC, dan jangan memanggil unserialize pada data klien.",
                verification="deterministic_php_serialized_cookie",
                confidence="candidate",
            ))
            continue
        if JAVA_SERIALIZED.search(joined):
            out.append(make_finding(
                ctx, "deserialization", {"deserialization", "serialized_object", "java_gadget"},
                type_="Cookie berisi objek Java terserialisasi",
                severity="high",
                evidence=f"Cookie '{name}' memuat magic bytes Java serialization.",
                risk="Deserialisasi Java pada input klien memungkinkan gadget chain RCE.",
                recommendation="Gunakan ObjectInputFilter allowlist atau format data non-biner.",
                verification="deterministic_java_serialized_cookie",
                confidence="candidate",
            ))
            continue
        if RUBY_SERIALIZED.search(joined):
            out.append(make_finding(
                ctx, "deserialization", {"deserialization", "serialized_object", "ruby_gadget"},
                type_="Cookie berisi objek Ruby Marshal",
                severity="high",
                evidence=f"Cookie '{name}' memuat data Marshal Ruby.",
                risk="Marshal.load pada input klien memungkinkan eksekusi kode via gadget.",
                recommendation="Jangan gunakan Marshal untuk data dari klien; gunakan JSON bertanda tangan.",
                verification="deterministic_ruby_serialized_cookie",
                confidence="candidate",
            ))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Web cache poisoning / deception
# ══════════════════════════════════════════════════════════════════════════════
@passive("cache_poisoning")
def p_cache_surface(ctx):
    if not any(h in ctx.headers for h in ("age", "x-cache", "cf-cache-status", "x-cache-status")):
        return []
    cache_hdr = {h: ctx.headers.get(h) for h in ("age", "x-cache", "cf-cache-status", "x-cache-status")
                 if h in ctx.headers}
    vary = ctx.header("vary")
    return [make_finding(
        ctx, "cache_poisoning", {"cache_poisoning"},
        type_="Respons melewati cache yang dapat dipengaruhi",
        severity="low",
        evidence=(f"Header cache terdeteksi {cache_hdr}; Vary=\"{vary or 'tidak ada'}\" "
                  f"pada {ctx.url}."),
        risk="Header/parameter yang tidak masuk cache key dapat meracuni respons untuk pengguna lain.",
        recommendation="Pastikan cache key mencakup seluruh input yang memengaruhi respons dan normalkan header.",
        verification="deterministic_cache_header_surface",
        confidence="candidate",
    )]


@passive("cache_deception")
def p_cache_deception_surface(ctx):
    if not ctx.cookies:
        return []
    if not any(h in ctx.headers for h in ("age", "x-cache", "cf-cache-status", "x-cache-status")):
        return []
    return [make_finding(
        ctx, "cache_deception", {"cache_deception"},
        type_="Konten berautentikasi berpotensi di-cache (web cache deception)",
        severity="medium",
        evidence=(f"Respons dengan cookie sesi memiliki header cache "
                  f"({ctx.header('x-cache') or ctx.header('cf-cache-status') or ctx.header('age')})."),
        risk="Penyerang dapat memancing korban membuka URL berakhiran statis agar respons privat ter-cache.",
        recommendation="Set Cache-Control: private/no-store untuk respons berautentikasi.",
        verification="deterministic_cache_deception_surface",
        confidence="candidate",
    )]


# ══════════════════════════════════════════════════════════════════════════════
# Host header
# ══════════════════════════════════════════════════════════════════════════════
@passive("host_header")
def p_host_header_surface(ctx):
    if not re.search(r"(password reset|forgot password|/reset|/forgot)", ctx.html or "", re.I):
        return []
    absolute_in_body = re.findall(r"https?://([a-z0-9.\-:]+)", ctx.html or "", re.I)
    hosts = {h.lower() for h in absolute_in_body}
    if not hosts:
        return []
    return [make_finding(
        ctx, "host_header", {"host_header", "password_reset"},
        type_="Alur reset password membangun URL absolut",
        severity="medium",
        evidence=f"URL absolut di halaman: {', '.join(sorted(hosts)[:5])} (reset password tersedia).",
        risk="Jika host diambil dari header Host, tautan reset dapat diarahkan ke domain penyerang.",
        recommendation="Bangun URL dari konfigurasi tetap dan validasi header Host.",
        verification="deterministic_absolute_url_in_reset",
        confidence="candidate",
    )]


# ══════════════════════════════════════════════════════════════════════════════
# WebSocket
# ══════════════════════════════════════════════════════════════════════════════
@passive("websocket")
def p_websocket_surface(ctx):
    m = re.search(r"(wss?://[^\s'\"<>]+)", ctx.html or "", re.I)
    if not m:
        return []
    url = m.group(1)
    tags = {"websockets"}
    if re.search(r"[?&](token|auth|session|jwt)=", url, re.I):
        tags.add("websocket_hijack")
    return [make_finding(
        ctx, "websocket", tags,
        type_="Endpoint WebSocket terdeteksi",
        severity="info",
        evidence=f"URL WebSocket: {url[:160]}",
        risk="Handshake tanpa validasi Origin memungkinkan cross-site WebSocket hijacking.",
        recommendation="Validasi header Origin dan gunakan token sekali-pakai untuk handshake.",
        verification="deterministic_websocket_endpoint",
        confidence="candidate",
    )]


# ══════════════════════════════════════════════════════════════════════════════
# GraphQL
# ══════════════════════════════════════════════════════════════════════════════
@passive("graphql")
def p_graphql_surface(ctx):
    if not re.search(r"(graphql|/gql\b)", ctx.html + ctx.url, re.I):
        return []
    return [make_finding(
        ctx, "graphql", {"graphql", "graphql_endpoint"},
        type_="Endpoint GraphQL tereferensi",
        severity="info",
        evidence=f"Referensi GraphQL ditemukan pada {ctx.url}.",
        risk="Endpoint GraphQL dapat mengekspos introspection dan field privat.",
        recommendation="Batasi endpoint, nonaktifkan introspection di production, terapkan rate limit.",
        verification="deterministic_graphql_reference",
        confidence="candidate",
    )]


# ══════════════════════════════════════════════════════════════════════════════
# NoSQL
# ══════════════════════════════════════════════════════════════════════════════
@passive("nosql")
def p_nosql_surface(ctx):
    soup = ctx.soup or BeautifulSoup(ctx.html or "", "html.parser")
    has_login = bool(soup.find("input", {"type": "password"}))
    json_hint = bool(re.search(r"(application/json|/api/login|\"username\")", ctx.html or "", re.I))
    if not (has_login and json_hint):
        return []
    return [make_finding(
        ctx, "nosql", {"nosql", "nosql_detect"},
        type_="Login berbasis JSON berpotensi injeksi operator NoSQL",
        severity="medium",
        evidence="Form login + endpoint JSON terdeteksi; body JSON memungkinkan operator seperti $ne.",
        risk="Jika objek JSON diteruskan langsung ke query Mongo, autentikasi dapat dilewati.",
        recommendation="Cast tipe input ke string dan tolak key yang dimulai dengan $.",
        verification="deterministic_nosql_json_login",
        confidence="candidate",
    )]


# ══════════════════════════════════════════════════════════════════════════════
# Prototype pollution
# ══════════════════════════════════════════════════════════════════════════════
@passive("prototype_pollution")
def p_proto_surface(ctx):
    out = []
    js = ctx.js_text or ""
    if re.search(r"(location\.(hash|search)|URLSearchParams)", js) and \
       re.search(r"(__proto__|constructor\s*\[\s*['\"]prototype|Object\.assign|jQuery\.extend|\.merge\()", js):
        out.append(make_finding(
            ctx, "prototype_pollution", {"prototype_pollution", "client_proto"},
            type_="Sink prototype pollution sisi klien dengan source URL",
            severity="medium",
            evidence="JavaScript menggabungkan input URL ke objek (merge/Object.assign) — kandidat prototype pollution.",
            risk="Menambahkan properti ke Object.prototype dapat mengubah perilaku aplikasi hingga XSS.",
            recommendation="Gunakan Object.create(null), blokir key __proto__/constructor, dan validasi skema.",
            verification="deterministic_client_proto_source_sink",
            confidence="candidate",
        ))
    if re.search(r"(JSON\.parse\([^)]*body|req\.body)", ctx.html or "") and \
       re.search(r"(Object\.assign|merge|extend|\.\.\.)", ctx.html or ""):
        out.append(make_finding(
            ctx, "prototype_pollution", {"prototype_pollution", "server_proto"},
            type_="Penggabungan body JSON di server (kandidat server-side prototype pollution)",
            severity="medium",
            evidence="Pola merge objek dari body permintaan terdeteksi pada kode yang terekspos.",
            risk="Payload __proto__ pada body dapat mencemari Object.prototype di server.",
            recommendation="Gunakan allowlist field, hapus key __proto__/constructor/prototype sebelum merge.",
            verification="deterministic_server_proto_merge",
            confidence="candidate",
        ))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# File upload
# ══════════════════════════════════════════════════════════════════════════════
@passive("file_upload")
def p_file_upload_surface(ctx):
    out = []
    soup = ctx.soup or BeautifulSoup(ctx.html or "", "html.parser")
    for form in soup.find_all("form"):
        file_inputs = form.find_all("input", {"type": "file"})
        if not file_inputs:
            continue
        enctype = (form.get("enctype") or "").lower()
        accept = " ".join((i.get("accept") or "") for i in file_inputs)
        if not enctype.startswith("multipart"):
            out.append(make_finding(
                ctx, "file_upload", {"file_upload"},
                type_="Form upload tanpa enctype multipart/form-data",
                severity="low",
                evidence=f"Form upload action={form.get('action') or '(self)'} enctype={enctype or 'kosong'}.",
                risk="Konfigurasi upload tidak standar; validasi server perlu diperiksa.",
                recommendation="Gunakan multipart/form-data dan validasi tipe/ukuran di server.",
                verification="deterministic_upload_form",
                confidence="candidate",
            ))
        if accept and "image" in accept:
            out.append(make_finding(
                ctx, "file_upload", {"file_upload", "webshell", "content_type_bypass"},
                type_="Pembatasan upload hanya di sisi klien (accept)",
                severity="medium",
                evidence=f"Input file memakai accept=\"{accept}\" tanpa bukti validasi server.",
                risk="Pembatasan tipe file di browser mudah dilewati (Content-Type/ekstensi) menuju web shell.",
                recommendation="Validasi tipe sebenarnya (magic bytes), simpan di luar document root, ganti nama file.",
                verification="deterministic_client_side_upload_restriction",
                confidence="candidate",
            ))
            break
    return out


# ══════════════════════════════════════════════════════════════════════════════
# API testing
# ══════════════════════════════════════════════════════════════════════════════
@passive("api")
def p_api_surface(ctx):
    out = []
    m = re.search(r"(https?://[^\s'\"<>]*(swagger|openapi)[^\s'\"<>]*)", ctx.html or "", re.I)
    if m:
        out.append(make_finding(
            ctx, "api", {"api", "api_docs"},
            type_="Dokumentasi API terekspos",
            severity="low",
            evidence=f"Referensi dokumentasi API: {m.group(1)[:160]}",
            risk="Dokumentasi API membuka daftar endpoint, parameter, dan skema data.",
            recommendation="Batasi akses dokumentasi API ke lingkungan internal/terautentikasi.",
            verification="deterministic_api_docs_reference",
        ))
    if re.search(r"(\"role\"|\"isAdmin\"|\"price\"|\"balance\")\s*:", ctx.html or ""):
        out.append(make_finding(
            ctx, "api", {"api", "mass_assignment"},
            type_="Objek JSON memuat field sensitif yang bisa di-mass-assign",
            severity="medium",
            evidence="Body/JSON memuat field seperti role/isAdmin/price/balance.",
            risk="Jika field ini diterima dari klien, pengguna dapat menaikkan hak atau mengubah harga.",
            recommendation="Gunakan allowlist field yang boleh diubah per peran.",
            verification="deterministic_mass_assignment_field",
            confidence="candidate",
        ))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Web LLM
# ══════════════════════════════════════════════════════════════════════════════
@passive("llm")
def p_llm_surface(ctx):
    if not re.search(r"(chat|assistant|prompt|llm|openai|message)", ctx.html or "", re.I):
        return []
    return [make_finding(
        ctx, "llm", {"llm"},
        type_="Antarmuka LLM/chat terdeteksi",
        severity="info",
        evidence="Halaman memuat antarmuka chat/LLM.",
        risk="Input pengguna dapat memengaruhi tool-calling LLM (prompt injection / excessive agency).",
        recommendation="Batasi tool yang tersedia, validasi output, dan jangan beri akses data sensitif ke LLM.",
        verification="deterministic_llm_interface",
        confidence="candidate",
    )]


# ══════════════════════════════════════════════════════════════════════════════
# Business logic
# ══════════════════════════════════════════════════════════════════════════════
@passive("business_logic")
def p_business_logic_surface(ctx):
    out = []
    low = ctx.body_lower
    if re.search(r"type=[\"']?hidden[^>]*name=[\"']?(price|amount|total|quantity|qty)", ctx.html or "", re.I):
        out.append(make_finding(
            ctx, "business_logic", {"business_logic", "client_side_trust"},
            type_="Harga/jumlah dikirim sebagai field tersembunyi",
            severity="medium",
            evidence="Field harga/jumlah tersembunyi ditemukan pada form.",
            risk="Jika server mempercayai nilai dari klien, harga dapat dimanipulasi.",
            recommendation="Hitung ulang harga di server dari data katalog.",
            verification="deterministic_hidden_price_field",
            confidence="candidate",
        ))
    if re.search(r"(coupon|discount|gift[-_ ]?card|redeem)", low):
        out.append(make_finding(
            ctx, "business_logic", {"business_logic"},
            type_="Fitur kupon/diskon tersedia",
            severity="info",
            evidence="Endpoint/field kupon atau redeem terdeteksi.",
            risk="Logika kupon sering dapat disalahgunakan berulang atau paralel (race).",
            recommendation="Validasi sekali-pakai secara atomik di server.",
            verification="deterministic_coupon_surface",
            confidence="candidate",
        ))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# SSRF / XXE / smuggling / race / essential / OAuth
# ══════════════════════════════════════════════════════════════════════════════
@passive("ssrf")
def p_ssrf_surface(ctx):
    names = {n.lower() for n in ctx.all_param_names()}
    url_like = sorted(names & {"url", "uri", "dest", "destination", "host", "image", "img",
                               "src", "source", "feed", "webhook", "callback", "proxy", "site",
                               "link", "stockapi"})
    if not url_like:
        return []
    tags = {"ssrf"}
    if url_like & {"url", "uri", "dest", "destination", "next", "return"}:
        tags.add("open_redirect")
    return [make_finding(
        ctx, "ssrf", tags,
        type_="Parameter menerima URL/host dari klien",
        severity="medium",
        evidence=f"Parameter berbentuk URL: {', '.join(url_like)}.",
        risk="Jika server mengambil URL tersebut, terbuka SSRF ke jaringan internal.",
        recommendation="Validasi allowlist host, blokir IP privat, dan pisahkan layanan pengambil konten.",
        verification="deterministic_ssrf_param",
        confidence="candidate",
    )]


@passive("xxe")
def p_xxe_surface(ctx):
    return [make_finding(
        ctx, "xxe", {"xxe"},
        type_="Permukaan parsing XML/SOAP terdeteksi",
        severity="medium",
        evidence="Halaman menerima/mengirim XML (application/xml, SOAP, atau xmlns pada form).",
        risk="Parser XML tanpa disable external entities memungkinkan pembacaan file dan SSRF.",
        recommendation="Nonaktifkan DTD/external entities pada parser dan gunakan format JSON bila memungkinkan.",
        verification="deterministic_xml_surface",
        confidence="candidate",
    )]


@passive("smuggling")
def p_smuggling_surface(ctx):
    hints = {k: v for k, v in ctx.headers.items()
             if k in ("server", "via", "x-cache", "cf-ray", "x-forwarded-server", "content-length")}
    if not (ctx.header("via") or "cloudflare" in ctx.header("server").lower()
            or ctx.header("akamai") or ctx.header("x-cache")):
        return []
    return [make_finding(
        ctx, "smuggling", {"smuggling"},
        type_="Arsitektur front-end/proxy terdeteksi",
        severity="info",
        evidence=f"Header proxy/CDN: {hints}",
        risk="Perbedaan parsing CL/TE antara front-end dan back-end memungkinkan request smuggling.",
        recommendation="Gunakan satu standar parsing, tolak request ambigu, dan normalisasi header.",
        verification="deterministic_proxy_surface",
        confidence="candidate",
    )]


@passive("race")
def p_race_surface(ctx):
    if not re.search(r"(coupon|redeem|claim|withdraw|transfer|checkout|limit|vote)", ctx.html or "", re.I):
        return []
    return [make_finding(
        ctx, "race", {"race"},
        type_="Endpoint transaksional/berbatas terdeteksi",
        severity="info",
        evidence="Fitur transaksi/kupon/limit ditemukan pada halaman.",
        risk="Operasi non-atomik dapat dieksploitasi paralel (limit overrun / double spend).",
        recommendation="Gunakan transaksi atomik, locking, dan idempotency key.",
        verification="deterministic_race_surface",
        confidence="candidate",
    )]


@passive("essential")
def p_essential_surface(ctx):
    return [make_finding(
        ctx, "essential", {"essential"},
        type_="Permukaan pemindaian terarah tersedia",
        severity="info",
        evidence=f"Target {ctx.url} memiliki parameter/form yang bisa dipetakan untuk uji cepat.",
        risk="Tanpa pemetaan terarah, waktu uji habis pada endpoint tidak relevan.",
        recommendation="Gunakan pemindaian terarah (Burp Scanner/targeted scan) pada endpoint berparameter.",
        verification="deterministic_targeted_scan_surface",
        confidence="candidate",
    )]


@passive("oauth")
def p_oauth_surface(ctx):
    out = []
    html = ctx.html or ""
    if re.search(r"response_type=token|#access_token=", html, re.I):
        out.append(make_finding(
            ctx, "oauth", {"oauth", "oauth_implicit"},
            type_="OAuth implicit flow terdeteksi",
            severity="medium",
            evidence="Parameter response_type=token / access_token pada fragment URL.",
            risk="Token terekspos ke JavaScript dan riwayat browser.",
            recommendation="Gunakan authorization code + PKCE.",
            verification="deterministic_oauth_implicit",
            confidence="candidate",
        ))
    if re.search(r"redirect_uri=", html, re.I):
        out.append(make_finding(
            ctx, "oauth", {"oauth", "oauth_redirect"},
            type_="Parameter redirect_uri OAuth dapat diuji",
            severity="medium",
            evidence="Alur OAuth memakai redirect_uri yang dikendalikan permintaan.",
            risk="Validasi longgar memungkinkan pencurian kode/token.",
            recommendation="Whitelist redirect_uri secara ketat dan tolak wildcard.",
            verification="deterministic_oauth_redirect_uri",
            confidence="candidate",
        ))
    return out


"""Probe AKTIF — hanya dijalankan bila operator sudah memberi izin (ctx.authorized).

Setiap probe mengirim payload minimal, membandingkan dengan baseline, dan hanya
menghasilkan temuan `confirmed` bila sinyalnya konsisten. Tidak ada payload
destruktif; payload yang mengubah data tidak dipakai.
"""

import base64
import hashlib
import hmac
import json
import re
import socket
import ssl
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

ACTIVE_PROBES: dict[str, list] = {}
if "passive" not in globals():
    def passive(key: str):
        def deco(fn):
            return fn
        return deco

UA = "DefensiveSecurityAudit/1.0 (+authorized lab verification)"
ACTIVE_TIMEOUT = 8
CANARY = "pswx9q7"


def active(key: str):
    def deco(fn):
        ACTIVE_PROBES.setdefault(key, []).append(fn)
        return fn
    return deco


# ── transport ────────────────────────────────────────────────────────────────
def _request(ctx, url, method="GET", **kw):
    try:
        resp = requests.request(
            method, url, timeout=ACTIVE_TIMEOUT, allow_redirects=False,
            headers={"User-Agent": UA, **kw.pop("headers", {})}, **kw,
        )
        ctx.http_log.append({"method": method, "url": url, "status": resp.status_code,
                             "len": len(resp.content)})
        return resp
    except Exception as exc:
        ctx.http_log.append({"method": method, "url": url, "error": str(exc)[:120]})
        return None


def _with_param(url, name, value):
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    q[name] = [value]
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def _baseline(ctx):
    resp = _request(ctx, ctx.url)
    if resp is None:
        return None, 0, ""
    return resp, len(resp.content), resp.text or ""


def _sig(resp):
    return (resp.status_code, len(resp.content)) if resp is not None else (0, 0)


# ══════════════════════════════════════════════════════════════════════════════
# XSS reflection (canary)
# ══════════════════════════════════════════════════════════════════════════════
@active("xss")
def a_reflection(ctx):
    out = []
    payload = f"<{CANARY}>"
    for name in list(ctx.params)[:11]:
        resp = _request(ctx, _with_param(ctx.url, name, payload))
        if resp is None or resp.status_code >= 500:
            continue
        body = resp.text or ""
        if payload in body or f"&lt;{CANARY}&gt;" not in body and CANARY in body:
            idx = body.find(CANARY)
            window = body[max(0, idx - 120): idx + 120].lower()
            tags = {"xss", "reflected"}
            if "<script" in window:
                tags.add("javascript_context")
                ctx_label = "konteks JavaScript"
            elif re.search(r"=\s*[\"'][^\"']*$", body[max(0, idx - 80): idx]):
                tags.add("attribute_context")
                ctx_label = "nilai atribut"
            else:
                ctx_label = "konteks HTML"
            unencoded = payload in body
            out.append(make_finding(
                ctx, "xss", tags,
                type_=f"Reflected XSS terkonfirmasi pada parameter '{name}' ({ctx_label})",
                severity="high" if unencoded else "medium",
                evidence=(f"Payload canary {payload!r} muncul {('apa adanya' if unencoded else 'setelah encoding')} "
                          f"di respons untuk parameter '{name}'. Cuplikan: \"{_snip(body, CANARY)}\""),
                risk="Payload HTML/JS dari URL dieksekusi di browser korban.",
                recommendation="Encode output per konteks dan terapkan CSP nonce.",
                verification="active_reflection_canary",
            ))
            break
    return out


# ══════════════════════════════════════════════════════════════════════════════
# SQL injection
# ══════════════════════════════════════════════════════════════════════════════
@active("sqli")
def a_sqli_error(ctx):
    base, base_len, _ = _baseline(ctx)
    if base is None:
        return []
    for name in list(ctx.params)[:8]:
        for payload in ("'", "\"", "')", "'-- -"):
            resp = _request(ctx, _with_param(ctx.url, name, payload))
            if resp is None:
                continue
            low = (resp.text or "").lower()
            for dbms, sig in SQL_ERROR_SIGNATURES:
                if sig in low:
                    return [make_finding(
                        ctx, "sqli", {"sql_injection", "error_based"},
                        type_=f"Error-based SQL injection pada parameter '{name}'",
                        severity="high",
                        evidence=(f"Payload {payload!r} memicu error SQL ({dbms}) pada respons "
                                  f"HTTP {resp.status_code}: \"{_snip(resp.text, sig)}\""),
                        risk="Input masuk ke query SQL; data dapat dibaca/diubah.",
                        recommendation="Gunakan parameterized query dan matikan detail error.",
                        verification="active_sqli_error_signature",
                    )]
    return []


@active("sqli")
def a_sqli_boolean(ctx):
    base, base_len, base_text = _baseline(ctx)
    if base is None:
        return []
    for name in list(ctx.params)[:8]:
        pairs = [("' AND '1'='1", "' AND '1'='2"),
                 ("1 AND 1=1", "1 AND 1=2")]
        for true_p, false_p in pairs:
            r_true = _request(ctx, _with_param(ctx.url, name, true_p))
            r_false = _request(ctx, _with_param(ctx.url, name, false_p))
            if not r_true or not r_false:
                continue
            if r_true.status_code != r_false.status_code:
                continue
            diff = abs(len(r_true.content) - len(r_false.content))
            if diff >= max(20, int(base_len * 0.10)) and b"error" not in r_false.content.lower():
                return [make_finding(
                    ctx, "sqli", {"sql_injection", "blind"},
                    type_=f"Blind SQL injection (boolean) pada parameter '{name}'",
                    severity="high",
                    evidence=(f"Kondisi TRUE menghasilkan {len(r_true.content)} byte, FALSE "
                              f"{len(r_false.content)} byte (selisih {diff} byte) pada parameter '{name}'."),
                    risk="Penyerang dapat mengekstrak data bit-per-bit lewat perbedaan respons.",
                    recommendation="Gunakan parameterized query dan samakan respons error.",
                    verification="active_sqli_boolean_differential",
                )]
    return []


@active("sqli")
def a_sqli_time(ctx):
    base, _, _ = _baseline(ctx)
    if base is None:
        return []
    for name in list(ctx.params)[:6]:
        t0 = time.time()
        r0 = _request(ctx, _with_param(ctx.url, name, "1"))
        baseline = time.time() - t0
        if r0 is None:
            continue
        for payload in ("'||(SELECT pg_sleep(4))||'", "1' AND (SELECT 1 FROM pg_sleep(4))-- -",
                        "1' AND SLEEP(4)-- -", "';WAITFOR DELAY '0:0:4'-- -"):
            t0 = time.time()
            resp = _request(ctx, _with_param(ctx.url, name, payload))
            elapsed = time.time() - t0
            if resp is not None and elapsed >= baseline + 3.0:
                return [make_finding(
                    ctx, "sqli", {"sql_injection", "blind", "time_based"},
                    type_=f"Blind SQL injection berbasis waktu pada parameter '{name}'",
                    severity="high",
                    evidence=(f"Payload {payload!r} menambah waktu respons menjadi {elapsed:.1f}s "
                              f"(baseline {baseline:.1f}s)."),
                    risk="Data dapat diekstrak lewat delay terkontrol.",
                    recommendation="Gunakan parameterized query; batasi waktu eksekusi query.",
                    verification="active_sqli_time_delay",
                )]
    return []


@active("sqli")
def a_sqli_union(ctx):
    base, base_len, _ = _baseline(ctx)
    if base is None:
        return []
    for name in list(ctx.params)[:6]:
        columns = 0
        for n in range(1, 7):
            resp = _request(ctx, _with_param(ctx.url, name, f"1' ORDER BY {n}-- -"))
            if resp is None:
                break
            if resp.status_code >= 500 or len(resp.content) < base_len * 0.5:
                columns = n - 1
                break
        if columns <= 0:
            continue
        payload = "1' UNION SELECT " + ",".join([f"'{CANARY}{i}'" for i in range(1, columns + 1)]) + "-- -"
        resp = _request(ctx, _with_param(ctx.url, name, payload))
        if resp is not None and CANARY in (resp.text or ""):
            return [make_finding(
                ctx, "sqli", {"sql_injection", "union"},
                type_=f"UNION-based SQL injection terkonfirmasi ({columns} kolom)",
                severity="high",
                evidence=(f"ORDER BY menentukan {columns} kolom; payload UNION menempatkan canary "
                          f"{CANARY} ke respons."),
                risk="Penyerang dapat membaca tabel lain lewat UNION SELECT.",
                recommendation="Gunakan parameterized query dan batasi hak akses DB.",
                verification="active_sqli_union_canary",
            )]
    return []


# ══════════════════════════════════════════════════════════════════════════════
# SSTI / OS command / path traversal
# ══════════════════════════════════════════════════════════════════════════════
@active("ssti")
def a_ssti(ctx):
    base, base_len, base_text = _baseline(ctx)
    if base is None:
        return []
    probes = [("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49"),
              ("#{7*7}", "49"), ("*{7*7}", "49"), ("{{7*'7'}}", "7777777")]
    for name in list(ctx.params)[:8]:
        for payload, expect in probes:
            if expect in base_text:
                continue
            resp = _request(ctx, _with_param(ctx.url, name, payload))
            if resp is None:
                continue
            if expect in (resp.text or ""):
                return [make_finding(
                    ctx, "ssti", {"ssti"},
                    type_=f"Server-side template injection pada parameter '{name}'",
                    severity="critical",
                    evidence=(f"Payload {payload!r} dievaluasi menjadi {expect!r} pada respons "
                              f"(parameter '{name}')."),
                    risk="Eksekusi ekspresi template dapat berujung RCE dan pembacaan data server.",
                    recommendation="Jangan render input pengguna sebagai template; gunakan variabel ter-escape.",
                    verification="active_ssti_arithmetic",
                )]
    return []


@active("os_command")
def a_os_command(ctx):
    base, _, base_text = _baseline(ctx)
    if base is None:
        return []
    for name in list(ctx.params)[:6]:
        for payload in (";id", "|id", "$(id)", "&& id", "`id`"):
            resp = _request(ctx, _with_param(ctx.url, name, payload))
            if resp is None:
                continue
            m = re.search(r"uid=\d+\([^)]+\)\s+gid=\d+", resp.text or "")
            if m:
                return [make_finding(
                    ctx, "os_command", {"os_command"},
                    type_=f"OS command injection pada parameter '{name}'",
                    severity="critical",
                    evidence=f"Payload {payload!r} mengembalikan output perintah: \"{m.group(0)}\"",
                    risk="Penyerang dapat menjalankan perintah sistem operasi.",
                    recommendation="Hindari shell; gunakan API dan allowlist argumen.",
                    verification="active_os_command_output",
                )]
    return []


@active("path_traversal")
def a_path_traversal(ctx):
    base, _, base_text = _baseline(ctx)
    if base is None:
        return []
    names = [n for n in ctx.all_param_names()
             if n.lower() in ("file", "filename", "path", "page", "img", "image", "download", "template")]
    for name in names[:6]:
        for payload in ("../../../../etc/passwd", "....//....//....//etc/passwd",
                        "..%2f..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd"):
            resp = _request(ctx, _with_param(ctx.url, name, payload))
            if resp is None:
                continue
            if re.search(r"root:[x*]?:0:0:", resp.text or ""):
                return [make_finding(
                    ctx, "path_traversal", {"path_traversal"},
                    type_=f"Path traversal pada parameter '{name}'",
                    severity="critical",
                    evidence=f"Payload {payload!r} mengembalikan isi /etc/passwd.",
                    risk="File di luar direktori publik dapat dibaca (kredensial, source code).",
                    recommendation="Normalisasi path, gunakan allowlist file, dan chroot direktori konten.",
                    verification="active_path_traversal_passwd",
                )]
    return []


# ══════════════════════════════════════════════════════════════════════════════
# CORS / host header / cache
# ══════════════════════════════════════════════════════════════════════════════
@active("cors")
def a_cors(ctx):
    out = []
    evil = "https://evil.pswx9.example"
    r = _request(ctx, ctx.url, headers={"Origin": evil})
    if r is not None:
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == evil:
            tags = {"cors", "origin_reflection"}
            out.append(make_finding(
                ctx, "cors", tags,
                type_="CORS origin reflection terkonfirmasi",
                severity="high" if acac == "true" else "medium",
                evidence=f"Origin {evil} direfleksikan (ACAO={acao}, ACAC={acac or '-'}).",
                risk="Situs penyerang dapat membaca respons berautentikasi.",
                recommendation="Validasi Origin terhadap allowlist ketat.",
                verification="active_cors_origin_reflection",
            ))
    r_null = _request(ctx, ctx.url, headers={"Origin": "null"})
    if r_null is not None and r_null.headers.get("Access-Control-Allow-Origin", "") == "null":
        out.append(make_finding(
            ctx, "cors", {"cors", "null_origin"},
            type_="CORS mempercayai origin 'null'",
            severity="high",
            evidence="Header ACAO bernilai 'null' untuk Origin: null.",
            risk="Iframe sandbox/data URI dapat membaca data berautentikasi.",
            recommendation="Jangan izinkan origin null.",
            verification="active_cors_null_origin",
        ))
    p = urlparse(ctx.url)
    if p.scheme == "https":
        insecure = f"http://{p.hostname}"
        r_http = _request(ctx, ctx.url, headers={"Origin": insecure})
        if r_http is not None and r_http.headers.get("Access-Control-Allow-Origin", "") == insecure:
            out.append(make_finding(
                ctx, "cors", {"cors", "protocol_confusion"},
                type_="CORS mempercayai skema HTTP tidak aman",
                severity="high",
                evidence=f"Origin {insecure} diterima sebagai ACAO.",
                risk="MITM pada HTTP dapat membaca data HTTPS.",
                recommendation="Hanya izinkan origin https yang eksplisit.",
                verification="active_cors_insecure_scheme",
            ))
    return out


@active("host_header")
def a_host_header(ctx):
    out = []
    for header in ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server"):
        canary = f"{CANARY}.pswx9.example"
        r = _request(ctx, ctx.url, headers={header: canary})
        if r is None:
            continue
        if canary in (r.text or "") or canary in r.headers.get("Location", ""):
            tags = {"host_header"}
            if re.search(r"(reset|forgot)", ctx.html or "", re.I):
                tags.add("password_reset")
            out.append(make_finding(
                ctx, "host_header", tags,
                type_=f"Header {header} tercermin pada respons",
                severity="high",
                evidence=f"Nilai {header}: {canary} muncul pada body/Location respons.",
                risk="Penyerang dapat mengarahkan tautan (mis. reset password) ke domainnya.",
                recommendation="Gunakan URL dari konfigurasi tetap; abaikan header host dari klien.",
                verification="active_host_header_reflection",
            ))
            break
    return out


@active("cache_poisoning")
def a_cache_poison(ctx):
    canary = f"{CANARY}.pswx9.example"
    r1 = _request(ctx, ctx.url, headers={"X-Forwarded-Host": canary})
    if r1 is None or canary not in (r1.text or ""):
        return []
    cache_state = " ".join(f"{k}={v}" for k, v in r1.headers.items()
                           if k.lower() in ("x-cache", "cf-cache-status", "age"))
    if not cache_state:
        return []
    return [make_finding(
        ctx, "cache_poisoning", {"cache_poisoning", "unkeyed_header"},
        type_="Header tidak ter-key tercermin pada respons yang di-cache",
        severity="high",
        evidence=f"X-Forwarded-Host={canary} tercermin; status cache: {cache_state}.",
        risk="Respons beracun dapat disajikan ke pengguna lain dari cache.",
        recommendation="Masukkan seluruh header yang memengaruhi output ke cache key atau abaikan header tersebut.",
        verification="active_cache_unkeyed_header",
    )]


@active("cache_deception")
def a_cache_deception(ctx):
    p = urlparse(ctx.url)
    probe_url = urlunparse(p._replace(path=p.path.rstrip("/") + f"/{CANARY}.css"))
    r = _request(ctx, probe_url, headers={"Cookie": "; ".join(
        f"{c['name']}={c.get('value','')}" for c in ctx.cookies if c.get("name"))} if ctx.cookies else {})
    if r is None:
        return []
    cache_state = " ".join(f"{k}={v}" for k, v in r.headers.items()
                           if k.lower() in ("x-cache", "cf-cache-status", "age"))
    if cache_state and ctx.cookies:
        return [make_finding(
            ctx, "cache_deception", {"cache_deception", "path_mapping"},
            type_="Respons berautentikasi di-cache pada path berakhiran statis",
            severity="high",
            evidence=f"GET {probe_url} dengan cookie sesi menghasilkan {cache_state}.",
            risk="Isi halaman privat dapat diambil dari cache oleh penyerang.",
            recommendation="Set Cache-Control: private, no-store untuk respons berautentikasi.",
            verification="active_cache_deception_path",
        )]
    return []


# ══════════════════════════════════════════════════════════════════════════════
# GraphQL / NoSQL / IDOR / admin / JWT
# ══════════════════════════════════════════════════════════════════════════════
@active("graphql")
def a_graphql(ctx):
    base = ctx.base
    for path in ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1"):
        r = _request(ctx, base + path, method="POST",
                     json={"query": "{__typename}"},
                     headers={"Content-Type": "application/json"})
        if r is None or r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        if not isinstance(data, dict) or ("data" not in data and "errors" not in data):
            continue
        intr = _request(ctx, base + path, method="POST",
                        json={"query": "{__schema{queryType{name} types{name}}}"},
                        headers={"Content-Type": "application/json"})
        introspection = False
        if intr is not None and intr.status_code == 200:
            try:
                introspection = isinstance(intr.json().get("data", {}).get("__schema"), dict)
            except Exception:
                introspection = False
        return [make_finding(
            ctx, "graphql", {"graphql", "graphql_endpoint"},
            type_="Endpoint GraphQL aktif" + (" dengan introspection" if introspection else ""),
            severity="high" if introspection else "medium",
            evidence=f"POST {base + path} merespons GraphQL; introspection={introspection}.",
            risk="Schema/field privat dapat dienumerasi dan diuji untuk akses tidak sah.",
            recommendation="Nonaktifkan introspection di production dan batasi endpoint.",
            verification="active_graphql_introspection",
        )]
    return []


@active("nosql")
def a_nosql(ctx):
    soup = ctx.soup
    if soup is None:
        return []
    for form in soup.find_all("form"):
        if not form.find_all("input", {"type": "password"}):
            continue
        action = form.get("action") or ctx.url
        target = ctx.abs_url(action)
        payload = {"username": {"$ne": None}, "password": {"$ne": None}}
        r = _request(ctx, target, method="POST", json=payload,
                     headers={"Content-Type": "application/json"})
        if r is None:
            continue
        if r.status_code in (200, 302) and r.status_code != 500:
            base = _request(ctx, target, method="POST",
                            json={"username": "nouser_pswx9", "password": "wrong"},
                            headers={"Content-Type": "application/json"})
            if base is not None and len(r.content) != len(base.content):
                return [make_finding(
                    ctx, "nosql", {"nosql", "nosql_auth", "login_bypass", "nosql_detect"},
                    type_="NoSQL operator injection melewati autentikasi",
                    severity="critical",
                    evidence=(f"Body JSON {{\"$ne\": null}} pada {target} menghasilkan respons berbeda "
                              f"({len(r.content)} vs {len(base.content)} byte)."),
                    risk="Autentikasi dapat dilewati tanpa kredensial valid.",
                    recommendation="Cast input ke string dan tolak key operator ($gt/$ne) di body.",
                    verification="active_nosql_operator_bypass",
                )]
    return []


@active("access_control")
def a_access_control(ctx):
    out = []
    for path in ("/admin", "/admin/", "/administrator", "/admin/users"):
        r = _request(ctx, ctx.base + path)
        if r is None:
            continue
        if r.status_code == 200 and "login" not in (r.text or "").lower()[:2000]:
            out.append(make_finding(
                ctx, "access_control", {"access_control", "admin_panel"},
                type_="Panel admin dapat diakses tanpa autentikasi",
                severity="critical",
                evidence=f"GET {ctx.base + path} mengembalikan HTTP 200 tanpa tantangan login.",
                risk="Fungsi administratif terekspos ke publik.",
                recommendation="Terapkan autentikasi dan otorisasi per-peran di server.",
                verification="active_admin_unauthenticated",
            ))
            break
    id_names = [n for n in ctx.all_param_names() if n.lower() in ("id", "userid", "user_id", "account", "uid")]
    for name in id_names[:3]:
        current = ctx.params.get(name, ["1"])[0]
        if not str(current).isdigit():
            continue
        other = str(int(current) + 1)
        r = _request(ctx, _with_param(ctx.url, name, other))
        base = _request(ctx, ctx.url)
        if r is not None and base is not None and r.status_code == 200:
            if abs(len(r.content) - len(base.content)) > 40 and b"error" not in r.content.lower():
                out.append(make_finding(
                    ctx, "access_control", {"access_control", "idor"},
                    type_=f"IDOR: parameter '{name}' mengembalikan objek berbeda",
                    severity="high",
                    evidence=(f"Mengubah {name}={current} menjadi {other} mengubah konten "
                              f"({len(base.content)} → {len(r.content)} byte)."),
                    risk="Data milik pengguna lain dapat dibaca/diubah.",
                    recommendation="Verifikasi kepemilikan objek di server untuk setiap akses.",
                    verification="active_idor_increment",
                ))
                break
    return out


JWT_WEAK_SECRETS = ["secret", "password", "admin", "key", "changeme", "jwt", "test",
                    "s3cr3t", "supersecret", "123456"]


@active("jwt")
def a_jwt_weak_key(ctx):
    for token in _find_jwts(ctx):
        parts = token.split(".")
        if len(parts) < 3:
            continue
        header = _b64url_json(parts[0])
        if str(header.get("alg", "")).lower() not in ("hs256", "hs384", "hs512"):
            continue
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig = parts[2]
        for secret in JWT_WEAK_SECRETS:
            digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
                      "hs512": hashlib.sha512}[str(header["alg"]).lower()]
            calc = hmac.new(secret.encode(), signing_input, digest).digest()
            if base64.urlsafe_b64encode(calc).decode().rstrip("=") == sig:
                return [make_finding(
                    ctx, "jwt", {"jwt", "jwt_weak_key"},
                    type_="JWT HMAC dapat dipalsukan dengan secret lemah",
                    severity="critical",
                    evidence=f"Signature token cocok dengan secret umum {secret!r} (alg={header.get('alg')}).",
                    risk="Penyerang dapat membuat token dengan klaim apa pun (mis. admin).",
                    recommendation="Ganti dengan secret acak >=256-bit dan rotasi token.",
                    verification="active_jwt_weak_secret",
                )]
    return []


@active("websocket")
def a_websocket_origin(ctx):
    m = re.search(r"wss?://[^\s'\"<>]+", ctx.html or "", re.I)
    if not m:
        return []
    ws_url = m.group(0)
    p = urlparse(ws_url)
    host = p.hostname or ctx.host
    port = p.port or (443 if p.scheme == "wss" else 80)
    path = p.path or "/"
    try:
        sock = socket.create_connection((host, port), timeout=ACTIVE_TIMEOUT)
        if p.scheme == "wss":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {base64.b64encode(b'pswx9canary12345').decode()}\r\n"
               f"Sec-WebSocket-Version: 13\r\nOrigin: https://evil.pswx9.example\r\n\r\n")
        sock.sendall(req.encode())
        data = sock.recv(4096).decode("latin-1", "ignore")
        sock.close()
    except Exception:
        return []
    if "101" in data.split("\r\n")[0]:
        return [make_finding(
            ctx, "websocket", {"websockets", "websocket_hijack"},
            type_="WebSocket handshake menerima Origin lintas situs",
            severity="high",
            evidence=f"Handshake ke {ws_url} dengan Origin palsu dijawab 101 Switching Protocols.",
            risk="Halaman penyerang dapat membuka koneksi WebSocket dengan sesi korban.",
            recommendation="Validasi header Origin pada handshake dan gunakan token sekali-pakai.",
            verification="active_websocket_origin",
        )]
    return []


@active("ssrf")
def a_open_redirect(ctx):
    names = [n for n in ctx.all_param_names()
             if n.lower() in ("redirect", "redirect_uri", "next", "return", "returnurl", "dest", "url")]
    for name in names[:4]:
        r = _request(ctx, _with_param(ctx.url, name, "https://pswx9.example/"))
        if r is None:
            continue
        loc = r.headers.get("Location", "")
        if "pswx9.example" in loc:
            return [make_finding(
                ctx, "ssrf", {"ssrf", "open_redirect"},
                type_=f"Open redirect pada parameter '{name}'",
                severity="medium",
                evidence=f"Location mengarah ke domain uji: {loc[:160]}",
                risk="Redirect dapat dipakai phishing atau membypass filter SSRF.",
                recommendation="Allowlist tujuan redirect relatif terhadap domain aplikasi.",
                verification="active_open_redirect",
            )]
    return []


"""Mesin pemindaian lab ber-scope.

Alur:
  1. applicability() menentukan keluarga probe yang relevan untuk target ini.
  2. Probe pasif selalu jalan; probe aktif hanya bila diotorisasi.
  3. Setiap temuan wajib lolos scope guard (target & host harus sama).
  4. Atribusi lab: lab hanya 'detected' bila SEMUA tag lab terbukti pada temuan.
     Lab tanpa ciri teknis yang bisa dibedakan TIDAK pernah diklaim detected.

Inilah yang mencegah hasil "memindai satu lab tetapi muncul lab lain".
"""

import json
from typing import Any, Optional

STATUS_DETECTED = "detected"
STATUS_CANDIDATE = "candidate"
STATUS_NOT_VERIFIED = "not_verified"
STATUS_NOT_APPLICABLE = "not_applicable"

STATUS_LABEL = {
    STATUS_DETECTED: "TERDETEKSI",
    STATUS_CANDIDATE: "KANDIDAT (butuh verifikasi)",
    STATUS_NOT_VERIFIED: "BELUM TERBUKTI",
    STATUS_NOT_APPLICABLE: "TIDAK RELEVAN",
}


# ══════════════════════════════════════════════════════════════════════════════
# SCOPE GUARD
# ══════════════════════════════════════════════════════════════════════════════
def _scope_ok(finding: dict, ctx) -> bool:
    """Temuan hanya sah bila berasal dari target yang sedang dipindai."""
    return (str(finding.get("target", "")) == str(ctx.url)
            and str(finding.get("host", "")).lower() == str(ctx.host).lower())


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in findings:
        key = (f.get("type", ""), tuple(f.get("tags", [])))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# ══════════════════════════════════════════════════════════════════════════════
# EKSEKUSI PROBE
# ══════════════════════════════════════════════════════════════════════════════
def _run_probes(ctx, app: dict[str, tuple[bool, str]]) -> tuple[list[dict], list[dict], dict]:
    confirmed: list[dict] = []
    candidates: list[dict] = []
    stats = {"passive_runs": 0, "active_runs": 0, "errors": [], "skipped_probes": []}

    for probe, (ok, reason) in app.items():
        if not ok:
            stats["skipped_probes"].append({"probe": probe, "reason": reason})
            continue

        for fn in PASSIVE_PROBES.get(probe, []):
            try:
                stats["passive_runs"] += 1
                for f in fn(ctx) or []:
                    if not isinstance(f, dict):
                        continue
                    if not _scope_ok(f, ctx):
                        stats["errors"].append(
                            f"scope guard menolak temuan dari {f.get('target')} pada probe {probe}")
                        continue
                    (confirmed if f.get("confidence") == "confirmed" else candidates).append(f)
            except Exception as exc:
                stats["errors"].append(f"passive:{probe}:{fn.__name__}: {exc}")

        if ctx.authorized:
            for fn in ACTIVE_PROBES.get(probe, []):
                try:
                    stats["active_runs"] += 1
                    for f in fn(ctx) or []:
                        if not isinstance(f, dict):
                            continue
                        if not _scope_ok(f, ctx):
                            stats["errors"].append(
                                f"scope guard menolak temuan dari {f.get('target')} pada probe {probe}")
                            continue
                        (confirmed if f.get("confidence") == "confirmed" else candidates).append(f)
                except Exception as exc:
                    stats["errors"].append(f"active:{probe}:{fn.__name__}: {exc}")

    return _dedupe_findings(confirmed), _dedupe_findings(candidates), stats


# ══════════════════════════════════════════════════════════════════════════════
# ATRIBUSI LAB
# ══════════════════════════════════════════════════════════════════════════════
def attribute_labs(ctx, confirmed: list[dict], candidates: list[dict],
                   app: dict[str, tuple[bool, str]]) -> list[dict]:
    """Petakan temuan ke lab. Lab hanya 'detected' bila SELURUH tag-nya terbukti."""
    rows: list[dict] = []
    for cat_key, cat in LAB_DB.items():
        probe = cat["probe"]
        applicable, reason = app.get(probe, (False, "probe tidak dikenali"))
        cat_conf = [f for f in confirmed if f.get("probe") == probe]
        cat_cand = [f for f in candidates if f.get("probe") == probe]

        for lab in cat["labs"]:
            required = set(lab["tags"])
            row = {
                "lab_id": lab["id"],
                "category": cat_key,
                "category_title": cat["title"],
                "level": lab["level"],
                "title": lab["title"],
                "tags": sorted(required),
                "signature": sorted(required),
                "status": STATUS_NOT_VERIFIED,
                "evidence": "",
                "matched_finding": "",
            }

            hits = [f for f in cat_conf if required <= set(f["tags"])]
            if hits:
                row["status"] = STATUS_DETECTED
                row["evidence"] = hits[0]["evidence"]
                row["matched_finding"] = hits[0]["type"]
                rows.append(row)
                continue

            near = [f for f in cat_cand if required <= set(f["tags"])]
            if near:
                row["status"] = STATUS_CANDIDATE
                row["evidence"] = near[0]["evidence"]
                row["matched_finding"] = near[0]["type"]
                rows.append(row)
                continue

            if not applicable:
                row["status"] = STATUS_NOT_APPLICABLE
                row["evidence"] = reason or "prasyarat teknis tidak ada pada target"
            else:
                distinctive = required - {cat_key}
                row["evidence"] = (
                    "tidak ada sinyal bertag lengkap "
                    f"({', '.join(sorted(distinctive))}) pada target ini"
                    if distinctive else
                    "permukaan terkait ada, tetapi tidak ada bukti yang cocok untuk lab ini"
                )
            rows.append(row)
    return rows


def group_detected(rows: list[dict]) -> list[dict]:
    """Gabungkan lab yang berbagi tag identik agar tidak ada klaim lab tunggal yang arbitrer."""
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault((r["category"], tuple(r["signature"])), []).append(r)

    out: list[dict] = []
    for _sig, items in groups.items():
        first = dict(items[0])
        names = [i["title"] for i in items]
        first["titles"] = names
        first["lab_ids"] = [i["lab_id"] for i in items]
        first["group_size"] = len(items)
        if len(items) > 1:
            first["title"] = f"{names[0]} (+{len(items) - 1} lab dengan ciri identik)"
        out.append(first)
    out.sort(key=lambda r: (r["category"], -r["group_size"]))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# ORKESTRATOR LAB
# ══════════════════════════════════════════════════════════════════════════════
def _discover_same_origin_contexts(root_ctx: TargetContext, max_pages: int = 80) -> list[TargetContext]:
    """Crawl halaman, form GET, dan endpoint yang dirujuk JavaScript pada origin sama.

    Discovery hanya memakai GET dan tidak mengirim form POST atau aksi mutasi.
    Script eksternal dibatasi, redirect lintas-origin ditolak, dan endpoint
    destruktif/asset statis dikecualikan. Ini memperluas attack-surface mapping,
    bukan jaminan eksploitasi seluruh skenario lab.
    """
    from collections import deque
    from urllib.parse import urldefrag, urljoin, urlparse

    root = urlparse(root_ctx.url)
    origin = (root.scheme.lower(), root.netloc.lower())
    queue = deque([root_ctx.url])
    seen: set[str] = set()
    contexts: list[TargetContext] = [root_ctx]
    scripts_seen: set[str] = set()
    max_pages = max(1, min(int(os.getenv("SATRIA_MAX_DISCOVERY_PAGES", str(max_pages))), 120))
    max_scripts = max(0, min(int(os.getenv("SATRIA_MAX_DISCOVERY_SCRIPTS", "24")), 40))
    blocked = re.compile(r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|unsubscribe|deactivate|purchase|checkout|transfer|payment)(?:/|$)", re.I)
    static_ext = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp[34]|pdf|zip)(?:$|\?)", re.I)
    endpoint_pattern = re.compile(
        r"(?ix)(?:fetch\s*\(|axios\.(?:get|post|put|patch|delete)\s*\(|\$\.ajax\s*\(|\burl\s*[:=])\s*['\"]([^'\"]{1,500})['\"]"
        r"|['\"]((?:/|\./|\.\./)(?:api|graphql|rest|ajax|account|admin|user|product|search|login|auth|cart|order|comment|upload)[^'\"\s]{0,300})['\"]",
        re.I,
    )

    def enqueue_candidate(raw: str, base: str) -> None:
        raw = (raw or "").strip()
        if not raw or raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "blob:", "#")):
            return
        candidate = urldefrag(urljoin(base, raw)).url
        cp = urlparse(candidate)
        if (cp.scheme.lower(), cp.netloc.lower()) != origin:
            return
        if blocked.search(cp.path) or static_ext.search(cp.path + ("?" + cp.query if cp.query else "")):
            return
        if candidate not in seen and len(seen) + len(queue) < max_pages * 3:
            queue.append(candidate)

    def parse_js_for_endpoints(js_text: str, base: str) -> None:
        if not js_text:
            return
        for match in endpoint_pattern.finditer(js_text[:1_500_000]):
            raw = match.group(1) or match.group(2) or ""
            # Do not infer arbitrary third-party URLs from bundled/minified JS.
            if raw.startswith(("/", "./", "../")):
                enqueue_candidate(raw, base)

    while queue and len(seen) < max_pages:
        current = urldefrag(queue.popleft()).url
        if current in seen:
            continue
        seen.add(current)
        parsed = urlparse(current)
        if (parsed.scheme.lower(), parsed.netloc.lower()) != origin:
            continue
        if blocked.search(parsed.path) or static_ext.search(parsed.path + ("?" + parsed.query if parsed.query else "")):
            continue

        if current == root_ctx.url:
            page_ctx = root_ctx
            page_html = root_ctx.html or ""
        else:
            try:
                response = requests.get(
                    current, timeout=min(ACTIVE_TIMEOUT, 8), allow_redirects=False,
                    headers={"User-Agent": UA},
                )
                root_ctx.http_log.append({"method": "GET", "url": current,
                                          "status": response.status_code,
                                          "len": len(response.content), "phase": "discovery"})
                if response.status_code not in (200, 203) or not response.text:
                    continue
                final = urlparse(response.url)
                if (final.scheme.lower(), final.netloc.lower()) != origin:
                    continue
                content_type = str(response.headers.get("Content-Type", "")).lower()
                if content_type and not any(x in content_type for x in ("text/html", "application/xhtml")):
                    continue
                page_html = response.text[:MAX_PARSED_CHARS]
                page_ctx = build_target_context(
                    current, page_html,
                    {"status_code": response.status_code,
                     "headers": dict(response.headers), "cookies": []},
                    authorized=root_ctx.authorized,
                )
            except Exception as exc:
                root_ctx.http_log.append({"method": "GET", "url": current,
                                          "error": str(exc)[:160], "phase": "discovery"})
                continue

        if page_ctx is not root_ctx:
            contexts.append(page_ctx)
        soup = page_ctx.soup
        if soup is None:
            continue

        # Links and form actions: GET forms are navigable; POST actions are
        # recorded as attack-surface metadata but are never submitted here.
        for tag in soup.find_all(["a", "area", "form"]):
            raw = tag.get("href") if tag.name in ("a", "area") else tag.get("action")
            if tag.name == "form" and str(tag.get("method", "get")).lower() != "get":
                if raw:
                    root_ctx.http_log.append({"method": str(tag.get("method", "post")).upper(),
                                              "url": urljoin(current, str(raw)),
                                              "phase": "form_endpoint_discovered",
                                              "submitted": False})
                continue
            enqueue_candidate(str(raw or ""), current)

        # Inline JavaScript and same-origin external scripts.
        for script in soup.find_all("script"):
            if script.get("src"):
                script_url = urljoin(current, str(script.get("src")))
                sp = urlparse(script_url)
                if ((sp.scheme.lower(), sp.netloc.lower()) != origin or
                        script_url in scripts_seen or len(scripts_seen) >= max_scripts):
                    continue
                scripts_seen.add(script_url)
                try:
                    sr = requests.get(script_url, timeout=min(ACTIVE_TIMEOUT, 8),
                                      allow_redirects=False, headers={"User-Agent": UA})
                    root_ctx.http_log.append({"method": "GET", "url": script_url,
                                              "status": sr.status_code,
                                              "len": len(sr.content), "phase": "script_discovery"})
                    if sr.status_code == 200 and (urlparse(sr.url).scheme, urlparse(sr.url).netloc) == origin:
                        script_text = sr.text[:1_500_000]
                        # Masukkan source eksternal ke konteks halaman agar detektor
                        # DOM-XSS/prototype-pollution dapat menganalisis source/sink,
                        # bukan hanya mengetahui nama file JavaScript.
                        page_ctx.js_text = (page_ctx.js_text + "\n" + script_text)[:MAX_PARSED_CHARS]
                        parse_js_for_endpoints(script_text, current)
                except Exception as exc:
                    root_ctx.http_log.append({"method": "GET", "url": script_url,
                                              "error": str(exc)[:120], "phase": "script_discovery"})
            else:
                parse_js_for_endpoints(script.string or script.get_text(" ", strip=False), current)

    root_ctx.http_log.append({"phase": "discovery_summary", "pages": len(contexts),
                              "scripts": len(scripts_seen), "queued_pages_limit": max_pages})
    return contexts


def run_lab_scan(ctx) -> dict[str, Any]:
    # Cakupan bukan hanya halaman awal: jelajahi tautan, halaman, dan form GET
    # pada origin yang sama, lalu jalankan keluarga probe pada setiap konteks.
    page_contexts = _discover_same_origin_contexts(ctx)
    aggregate_app: dict[str, tuple[bool, str]] = {}
    confirmed_all: list[dict] = []
    candidates_all: list[dict] = []
    categories_without_detector = [
        key for key, cat in LAB_DB.items()
        if not PASSIVE_PROBES.get(cat["probe"]) and not ACTIVE_PROBES.get(cat["probe"])
    ]
    stats = {"passive_runs": 0, "active_runs": 0, "errors": [],
             "skipped_probes": [], "pages_discovered": len(page_contexts),
             "discovery_requests": max(0, len(page_contexts) - 1),
             "catalog_categories": len(LAB_DB),
             "catalog_labs": TOTAL_LABS,
             "passive_probe_families": sorted(PASSIVE_PROBES),
             "active_probe_families": sorted(ACTIVE_PROBES),
             "categories_without_detector": categories_without_detector}

    for page_ctx in page_contexts:
        page_app = applicability(page_ctx)
        for probe, (ok, reason) in page_app.items():
            previous = aggregate_app.get(probe, (False, ""))
            if ok:
                aggregate_app[probe] = (True, "")
            elif probe not in aggregate_app:
                aggregate_app[probe] = (False, reason)
        confirmed, candidates, page_stats = _run_probes(page_ctx, page_app)
        confirmed_all.extend(confirmed)
        candidates_all.extend(candidates)
        stats["passive_runs"] += page_stats.get("passive_runs", 0)
        stats["active_runs"] += page_stats.get("active_runs", 0)
        stats["errors"].extend(page_stats.get("errors", []))
        stats["skipped_probes"].extend(page_stats.get("skipped_probes", []))

    confirmed = _dedupe_findings(confirmed_all)
    candidates = _dedupe_findings(candidates_all)
    rows = attribute_labs(ctx, confirmed, candidates, aggregate_app)

    detected_rows = [r for r in rows if r["status"] == STATUS_DETECTED]
    detected = group_detected(detected_rows)
    cand_rows = [r for r in rows if r["status"] == STATUS_CANDIDATE]
    not_verified = [r for r in rows if r["status"] == STATUS_NOT_VERIFIED]
    not_applicable = [r for r in rows if r["status"] == STATUS_NOT_APPLICABLE]

    applicable_categories = sorted({k for k, (ok, _) in aggregate_app.items() if ok})
    category_summary = []
    for cat_key, cat in LAB_DB.items():
        cat_rows = [r for r in rows if r["category"] == cat_key]
        category_summary.append({
            "category": cat_key, "title": cat["title"], "total": len(cat_rows),
            "detected": sum(1 for r in cat_rows if r["status"] == STATUS_DETECTED),
            "candidate": sum(1 for r in cat_rows if r["status"] == STATUS_CANDIDATE),
            "not_verified": sum(1 for r in cat_rows if r["status"] == STATUS_NOT_VERIFIED),
            "not_applicable": sum(1 for r in cat_rows if r["status"] == STATUS_NOT_APPLICABLE),
            "applicable": aggregate_app.get(cat["probe"], (False, ""))[0],
        })

    print(f"\n[PortSwigger] Target      : {ctx.url}")
    print(f"[PortSwigger] Halaman     : {len(page_contexts)} dalam origin yang sama")
    print(f"[PortSwigger] Lab katalog : {TOTAL_LABS}")
    print(f"[PortSwigger] Probe pasif : {stats['passive_runs']} | aktif: {stats['active_runs']} "
          f"({'diizinkan' if ctx.authorized else 'tidak diizinkan'})")
    print(f"[PortSwigger] Terdeteksi  : {len(detected_rows)} lab / {len(detected)} kelompok | "
          f"kandidat: {len(cand_rows)} | tidak relevan: {len(not_applicable)} | "
          f"belum terbukti: {len(not_verified)}")
    if stats["errors"]:
        print(f"[PortSwigger] Catatan     : {len(stats['errors'])} error/penolakan (lihat report['errors'])")

    return {
        "target": ctx.url, "host": ctx.host, "authorized": ctx.authorized,
        "labs_total": TOTAL_LABS, "pages_discovered": len(page_contexts),
        "applicable_probes": applicable_categories, "detected": detected,
        "detected_lab_count": len(detected_rows), "candidates": cand_rows,
        "not_verified": not_verified, "not_applicable": not_applicable,
        "per_lab": rows, "category_summary": category_summary,
        "findings": confirmed, "candidate_findings": candidates,
        "stats": stats, "http_requests": len(ctx.http_log),
    }


def scan_labs(url: str, html: str, http_result: Optional[dict] = None,
              authorized: Optional[bool] = None) -> dict[str, Any]:
    """Entry point: bangun konteks dari SATU target lalu pindai."""
    if authorized is None:
        authorized = active_probe_enabled()
    ctx = build_target_context(url, html, http_result or {}, authorized=bool(authorized))
    return run_lab_scan(ctx)


# ══════════════════════════════════════════════════════════════════════════════
# RENDER RINGKASAN
# ══════════════════════════════════════════════════════════════════════════════
def render_lab_report(report: dict, max_rows: int = 40) -> str:
    lines = [
        f"## PortSwigger lab scan — {report['target']}",
        "",
        f"- Total lab dalam katalog: **{report['labs_total']}**",
        f"- Halaman yang dianalisis pada origin yang sama: **{report.get('pages_discovered', 1)}**",
        f"- Terdeteksi: **{report.get('detected_lab_count', len(report['detected']))} lab** "
        f"(dalam {len(report['detected'])} kelompok ciri)",
        f"- Kandidat (butuh verifikasi): **{len(report['candidates'])}**",
        f"- Tidak relevan untuk target ini: **{len(report['not_applicable'])}**",
        f"- Belum terbukti: **{len(report['not_verified'])}**",
        "",
    ]
    if report["detected"]:
        lines.append("### Lab terdeteksi (bukti cocok)")
        lines.append("")
        lines.append("| Lab | Level | Bukti |")
        lines.append("|---|---|---|")
        for r in report["detected"][:max_rows]:
            label = r["title"].replace("|", "/")
            lines.append(f"| {label} | {r['level']} | {r['evidence'][:200].replace('|', '/')} |")
        lines.append("")
    if report["candidates"]:
        lines.append("### Kandidat (perlu satu langkah verifikasi)")
        lines.append("")
        lines.append("| Lab | Level | Indikasi |")
        lines.append("|---|---|---|")
        for r in report["candidates"][:max_rows]:
            lines.append(f"| {r['title']} | {r['level']} | {r['evidence'][:160]} |")
        lines.append("")
    lines.append("### Ringkasan per kategori")
    lines.append("")
    lines.append("| Kategori | Lab | Terdeteksi | Kandidat | Tidak relevan |")
    lines.append("|---|---|---|---|---|")
    for c in report["category_summary"]:
        lines.append(f"| {c['title']} | {c['total']} | {c['detected']} | {c['candidate']} | "
                     f"{c['not_applicable']} |")
    return "\n".join(lines)


"""Orkestrator akhir: run_pipeline() dan render_pdf() — API publik dipertahankan."""

import html as html_lib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
def _resolve_inputs(scrape_data: Optional[dict] = None, url: Optional[str] = None,
                    html: Optional[str] = None) -> tuple[str, str]:
    target_url = normalize_url(url) if url else ""
    page_html = html or ""
    if scrape_data:
        paths = persist_scrape_artifacts(scrape_data)
        page_html, scraped_url = load_scrape_html(paths["html"])
        if not target_url:
            target_url = scraped_url
    if not page_html:
        raise RuntimeError("Tidak ada HTML untuk dianalisis. Berikan scrape_data atau html.")
    if not target_url or target_url == "unknown":
        raise RuntimeError("URL target tidak diketahui; analisis lab butuh URL.")
    return target_url, page_html


def _run_pipeline_impl(scrape_data: Optional[dict] = None, *, url: Optional[str] = None,
                       html: Optional[str] = None, authorized: Optional[bool] = None,
                       http_result: Optional[dict] = None) -> dict[str, Any]:
    """Jalankan seluruh pipeline SATRIA untuk SATU target.

    Parameter
    ---------
    scrape_data : dict hasil scraper (cara lama, tetap didukung)
    url, html   : jalur alternatif tanpa scraper
    authorized  : izin probe aktif; default mengikuti gate global
    http_result : hasil analyze_http_security bila sudah ada (menghindari request ulang)
    """
    started = datetime.now(timezone.utc)
    target_url, page_html = _resolve_inputs(scrape_data, url, html)
    if authorized is None:
        authorized = active_probe_enabled()

    print(f"\n[*] Target: {target_url}")
    print(f"[*] Mode  : {'PASIF + AKTIF (diizinkan)' if authorized else 'PASIF saja'}")

    # ── Section 1: HTTP ──────────────────────────────────────────────────────
    if http_result is None:
        try:
            http_result = analyze_http_security(target_url)
        except Exception as exc:
            http_result = {"errors": [str(exc)], "headers": {}, "cookies": [],
                           "findings": [], "status_code": None}
    http_findings = list(http_result.get("findings") or [])

    # ── Section 2: temuan kode deterministik ─────────────────────────────────
    code_findings = detect_code_findings_deterministic(page_html, target_url)

    # ── Section 3: PortSwigger lab scan ──────────────────────────────────────
    lab_report = scan_labs(target_url, page_html, http_result, authorized=authorized)
    lab_findings = lab_report["findings"]

    # ── Section 4: teknologi & CVE (opsional) ────────────────────────────────
    technologies = extract_tech_versions_deterministic(page_html)
    cves: list[dict] = []
    if RUN_NVD or RUN_CENSYS:
        for tech in technologies[:10]:
            try:
                cves.extend(search_nvd_verified(tech["name"], tech["version"]))
                cves.extend(search_osv_verified(tech["name"], tech["version"]))
            except Exception as exc:
                print(f"      [CVE] dilewati untuk {tech['name']}: {exc}")

    # ── Gabung, dedup, ringkas ───────────────────────────────────────────────
    combined = dedup_and_merge_findings(http_findings + code_findings + lab_findings)
    summary = summarize(combined)

    result: dict[str, Any] = {
        "target": target_url,
        "generated_at": started.isoformat(),
        "mode": "active" if authorized else "passive",
        "findings": combined,
        "summary": summary,
        "sections": {
            "http": http_findings,
            "code": code_findings,
            "portswigger": lab_findings,
        },
        "portswigger": lab_report,
        "technologies": technologies,
        "cves": cves,
        "http": {
            "status_code": http_result.get("status_code"),
            "final_url": http_result.get("final_url"),
            "headers": http_result.get("headers"),
            "errors": http_result.get("errors"),
        },
        "errors": lab_report["stats"]["errors"],
    }

    try:
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        Path(FINDINGS_PATH).write_text(json.dumps(result, indent=2, ensure_ascii=False),
                                       encoding="utf-8")
        print(f"[*] Temuan disimpan: {FINDINGS_PATH}")
    except Exception as exc:
        print(f"[!] Gagal menyimpan {FINDINGS_PATH}: {exc}")

    print(f"[*] Selesai: {summary['total']} temuan "
          f"({', '.join(f'{k}={v}' for k, v in summary['by_severity'].items() if v)})")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# PDF
# ══════════════════════════════════════════════════════════════════════════════
PDF_CSS = """
@page { size: A4; margin: 16mm 14mm; }
body { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 10pt; color: #1b1b1b; }
h1 { font-size: 18pt; margin: 0 0 4mm 0; }
h2 { font-size: 13pt; margin: 6mm 0 2mm 0; border-bottom: 1px solid #ccc; padding-bottom: 1mm; }
h3 { font-size: 11pt; margin: 4mm 0 1mm 0; }
.meta { color: #555; font-size: 9pt; margin-bottom: 4mm; }
table { width: 100%; border-collapse: collapse; margin: 2mm 0 4mm 0; }
th, td { border: 1px solid #d0d0d0; padding: 1.4mm; vertical-align: top; font-size: 8.6pt; }
th { background: #f0f2f5; text-align: left; }
.sev-critical { color: #7a0000; font-weight: bold; }
.sev-high { color: #a30000; font-weight: bold; }
.sev-medium { color: #8a5a00; font-weight: bold; }
.sev-low { color: #2f5d8a; }
.sev-info { color: #555; }
.small { font-size: 8.5pt; color: #444; }
"""


def _esc(value: Any) -> str:
    return html_lib.escape(str(value if value is not None else ""))


def _build_pdf_html(result: dict) -> str:
    summary = result.get("summary") or {}
    by = summary.get("by_severity") or {}
    lab = result.get("portswigger") or {}
    rows = []
    for f in result.get("findings") or []:
        sev = str(f.get("severity", "info")).lower()
        rows.append(
            "<tr>"
            f"<td class='sev-{_esc(sev)}'>{_esc(sev.upper())}</td>"
            f"<td>{_esc(f.get('type', ''))}</td>"
            f"<td>{_esc(f.get('evidence', ''))}</td>"
            f"<td>{_esc(f.get('risk', ''))}</td>"
            f"<td>{_esc(f.get('recommendation', ''))}</td>"
            "</tr>"
        )
    def _lab_cell(r: dict) -> str:
        if r.get("group_size", 1) > 1 and r.get("titles"):
            items = "<br>".join(f"&bull; {_esc(t)}" for t in r["titles"])
            return f"<strong>{_esc(r['title'])}</strong><br><span class='small'>{items}</span>"
        return _esc(r["title"])

    detected_rows = "".join(
        "<tr>"
        f"<td>{_lab_cell(r)}</td><td>{_esc(r['level'])}</td>"
        f"<td>{_esc(r['category_title'])}</td><td>{_esc(r['evidence'])}</td>"
        "</tr>"
        for r in (lab.get("detected") or [])
    ) or "<tr><td colspan='4'>Tidak ada lab yang terdeteksi pada target ini.</td></tr>"
    candidate_rows = "".join(
        "<tr>"
        f"<td>{_esc(r['title'])}</td><td>{_esc(r['level'])}</td><td>{_esc(r['evidence'])}</td>"
        "</tr>"
        for r in (lab.get("candidates") or [])[:40]
    ) or "<tr><td colspan='3'>Tidak ada kandidat.</td></tr>"
    coverage_rows = "".join(
        "<tr>"
        f"<td>{_esc(c['title'])}</td><td>{c['total']}</td><td>{c['detected']}</td>"
        f"<td>{c['candidate']}</td><td>{c['not_applicable']}</td>"
        "</tr>"
        for c in (lab.get("category_summary") or [])
    )

    status_label = {
        "detected": "TERDETEKSI", "candidate": "KANDIDAT",
        "not_verified": "BELUM TERBUKTI", "not_applicable": "TIDAK RELEVAN",
    }
    appendix_rows = "".join(
        "<tr>"
        f"<td>{_esc(r.get('category_title', ''))}</td>"
        f"<td>{_esc(r.get('title', ''))}</td>"
        f"<td>{_esc(r.get('level', ''))}</td>"
        f"<td>{_esc(status_label.get(str(r.get('status', '')), str(r.get('status', ''))))}</td>"
        "</tr>"
        for r in (lab.get("per_lab") or [])
    )
    appendix_html = ""
    if appendix_rows:
        appendix_html = (
            "<h2>Lampiran &#8212; inventaris " + str(lab.get("labs_total", 0))
            + " lab PortSwigger</h2>\n<table>\n"
            "<tr><th>Kategori</th><th>Lab</th><th>Level</th><th>Status</th></tr>\n"
            + appendix_rows + "</table>\n"
        )
    return f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"><title>Laporan Kerentanan</title>
<style>{PDF_CSS}</style></head><body>
<h1>Laporan Pemindaian Keamanan Web</h1>
<div class="meta">
  Target: <strong>{_esc(result.get('target'))}</strong><br>
  Dibuat: {_esc(result.get('generated_at'))} &middot; Mode: {_esc(result.get('mode'))}
</div>

<h2>Ringkasan</h2>
<table>
<tr><th>Total temuan</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>
<tr>
  <td>{summary.get('total', 0)}</td>
  <td>{by.get('critical', 0)}</td><td>{by.get('high', 0)}</td>
  <td>{by.get('medium', 0)}</td><td>{by.get('low', 0)}</td><td>{by.get('info', 0)}</td>
</tr>
</table>

<h2>Temuan</h2>
<table>
<tr><th>Severity</th><th>Jenis</th><th>Bukti</th><th>Risiko</th><th>Rekomendasi</th></tr>
{''.join(rows) or "<tr><td colspan='5'>Tidak ada temuan.</td></tr>"}
</table>

<h2>PortSwigger lab — terdeteksi ({len(lab.get('detected') or [])} dari {lab.get('labs_total', 0)})</h2>
<table>
<tr><th>Lab</th><th>Level</th><th>Kategori</th><th>Bukti</th></tr>
{detected_rows}
</table>

<h2>Kandidat (butuh verifikasi)</h2>
<table>
<tr><th>Lab</th><th>Level</th><th>Indikasi</th></tr>
{candidate_rows}
</table>

<h2>Cakupan katalog per kategori</h2>
<table>
<tr><th>Kategori</th><th>Lab</th><th>Terdeteksi</th><th>Kandidat</th><th>Tidak relevan</th></tr>
{coverage_rows}
</table>
<p class="small">Temuan hanya diatribusikan ke lab yang seluruh ciri teknisnya terbukti pada target ini.
Lab yang tidak relevan tidak dilaporkan sebagai temuan.</p>
{appendix_html}
</body></html>"""


def run_pipeline(scrape_data: Optional[dict] = None, *, url: Optional[str] = None,
                 html: Optional[str] = None, authorized: Optional[bool] = None,
                 http_result: Optional[dict] = None,
                 allow_partial_tools: Optional[bool] = None,
                 enable_llm: Optional[bool] = None,
                 run_censys: Optional[bool] = None,
                 run_nvd: Optional[bool] = None,
                 **runtime_options: Any) -> dict[str, Any]:
    """API publik SATRIA; membuat PDF sebelum kembali dan mempertahankan path final.

    Nilai konfigurasi analisis yang bersifat sementara dipulihkan setelah pipeline,
    tetapi path artefak final sengaja dipertahankan agar app.py membaca file yang
    benar setelah fungsi selesai.
    """
    overrides: dict[str, Any] = dict(runtime_options)
    for name, value in (("allow_partial_tools", allow_partial_tools),
                        ("enable_llm", enable_llm), ("run_censys", run_censys),
                        ("run_nvd", run_nvd), ("authorized", authorized)):
        if value is not None:
            overrides[name] = value

    saved = get_runtime_config() if overrides else None
    final_pdf: Optional[Path] = None
    active_artifacts: Optional[Path] = None
    try:
        if overrides:
            configure_runtime(**overrides)

        # Snapshot path sesudah semua konfigurasi diterapkan. Pakai absolute path
        # agar perubahan working directory Streamlit tidak menggeser lokasi.
        active_artifacts = Path(ARTIFACTS_DIR).expanduser().resolve()
        requested_pdf = Path(OUTPUT_PDF).expanduser()
        if not requested_pdf.is_absolute():
            requested_pdf = (Path.cwd() / requested_pdf).resolve()
        requested_pdf.parent.mkdir(parents=True, exist_ok=True)

        result = _run_pipeline_impl(
            scrape_data=scrape_data, url=url, html=html,
            authorized=authorized, http_result=http_result
        )

        # Tulis ke nama sementara di direktori yang sama, validasi signature PDF,
        # lalu atomik-replace ke nama final. Tidak ada PDF parsial yang terlihat.
        temp_pdf = requested_pdf.with_name(requested_pdf.stem + ".satria_tmp.pdf")
        try:
            if temp_pdf.exists():
                temp_pdf.unlink()
            rendered = render_pdf(result, str(temp_pdf))
            rendered = Path(rendered)
            if (not rendered.is_file() or rendered.stat().st_size < 1000 or
                    rendered.read_bytes()[:5] != b"%PDF-"):
                raise RuntimeError(
                    f"Renderer tidak menghasilkan PDF valid: {rendered}; "
                    f"size={rendered.stat().st_size if rendered.exists() else 0}"
                )
            os.replace(str(rendered), str(requested_pdf))
        finally:
            try:
                if temp_pdf.exists():
                    temp_pdf.unlink()
            except Exception:
                pass

        if (not requested_pdf.is_file() or requested_pdf.stat().st_size < 1000 or
                requested_pdf.read_bytes()[:5] != b"%PDF-"):
            raise RuntimeError(f"PDF final tidak valid setelah penulisan: {requested_pdf}")
        final_pdf = requested_pdf.resolve()
        globals()["OUTPUT_PDF"] = str(final_pdf)
        return result
    finally:
        if saved is not None:
            configure_runtime(**saved)
        # Jangan pulihkan OUTPUT_PDF ke path default lama. app.py memeriksa
        # engine.OUTPUT_PDF setelah run_pipeline() selesai.
        if final_pdf is not None and final_pdf.is_file():
            globals()["OUTPUT_PDF"] = str(final_pdf)
            # ARTIFACTS_DIR juga diselaraskan dengan direktori artefak job.
            globals()["ARTIFACTS_DIR"] = final_pdf.parent


_PDF_PAGE_W = 595
_PDF_PAGE_H = 842
_PDF_MARGIN_X = 45
_PDF_MARGIN_TOP = 800
_PDF_MARGIN_BOTTOM = 55


def _pdf_escape(text: str) -> str:
    """Escape teks agar aman sebagai string literal PDF (WinAnsi/latin-1)."""
    out = []
    for ch in text:
        code = ord(ch)
        if ch in "\\()":
            out.append("\\" + ch)
        elif code == 9:
            out.append(" ")
        elif 32 <= code <= 126:
            out.append(ch)
        elif 160 <= code <= 255:
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def _report_text_items(doc_html: str) -> list[tuple[str, str]]:
    """Ubah HTML laporan menjadi daftar (gaya, baris teks)."""
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", doc_html)
    text = re.sub(r"(?i)<h1[^>]*>", "\n\x01", text)
    text = re.sub(r"(?i)<h2[^>]*>", "\n\x02", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</t[dh]>", "  |  ", text)
    text = re.sub(r"(?i)</(tr|table|p|div|li|h[1-6])>", "\n", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = _html_unescape(text)

    items: list[tuple[str, str]] = []
    for raw in text.splitlines():
        style = "body"
        if raw.startswith("\x01"):
            style, raw = "h1", raw[1:]
        elif raw.startswith("\x02"):
            style, raw = "h2", raw[2:] if raw[1:2] == "\x02" else raw[1:]
        line = re.sub(r"\s+", " ", raw).strip(" |")
        if not line:
            if items and items[-1][0] != "blank":
                items.append(("blank", ""))
            continue
        items.append((style, line))
    return items


def _write_builtin_pdf(doc_html: str, out: Path, target: str = "") -> Path:
    """Tulis PDF valid tanpa dependensi eksternal (Helvetica base-14)."""
    specs = {"h1": ("/F2", 15.0, 62), "h2": ("/F2", 11.5, 80), "body": ("/F1", 9.2, 106)}
    lines: list[tuple[str, float, str, float]] = []
    for style, text in _report_text_items(doc_html):
        if style == "blank":
            lines.append(("/F1", 6.0, "", 6.0))
            continue
        font, size, width = specs[style]
        extra = 8.0 if style == "h1" else 5.0 if style == "h2" else 0.0
        for idx, seg in enumerate(textwrap.wrap(text, width=width) or [""]):
            lines.append((font, size, seg, extra if idx == 0 else 0.0))

    pages: list[list[tuple[str, float, float, str]]] = []
    page: list[tuple[str, float, float, str]] = []
    y = float(_PDF_MARGIN_TOP)
    for font, size, text, extra in lines:
        step = size + 3.6
        if page and (y - step - extra) < _PDF_MARGIN_BOTTOM:
            pages.append(page)
            page = []
            y = float(_PDF_MARGIN_TOP)
        y -= extra
        page.append((font, size, y, text))
        y -= step
    pages.append(page)
    total = len(pages)

    footer_left = "SATRIA WebSec - " + target if target else "SATRIA WebSec"
    footer_left = footer_left[:70]
    streams: list[bytes] = []
    for idx, page in enumerate(pages, start=1):
        cmds = []
        for font, size, pos_y, text in page:
            if not text:
                continue
            cmds.append(
                "BT %s %.2f Tf 1 0 0 1 %.2f %.2f Tm (%s) Tj ET"
                % (font, size, _PDF_MARGIN_X, pos_y, _pdf_escape(text))
            )
        cmds.append(
            "BT /F1 8 Tf 1 0 0 1 %.2f 30 Tm (%s) Tj ET"
            % (_PDF_MARGIN_X, _pdf_escape(footer_left))
        )
        cmds.append(
            "BT /F1 8 Tf 1 0 0 1 %.2f 30 Tm (%s) Tj ET"
            % (_PDF_PAGE_W - _PDF_MARGIN_X - 62,
               _pdf_escape("Halaman %d dari %d" % (idx, total)))
        )
        streams.append("\n".join(cmds).encode("latin-1", "replace"))

    objects: dict[int, bytes] = {}
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join("%d 0 R" % (6 + 2 * i) for i in range(total))
    objects[2] = (
        "<< /Type /Pages /Count %d /Kids [%s] >>" % (total, kids)
    ).encode("latin-1")
    objects[3] = (
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>"
    )
    objects[4] = (
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
        b"/Encoding /WinAnsiEncoding >>"
    )
    objects[5] = (
        "<< /Title (Laporan Pemindaian Keamanan Web) "
        "/Producer (SATRIA WebSec Engine) /Creator (SATRIA WebSec Engine) >>"
    ).encode("latin-1")
    for i in range(total):
        page_id = 6 + 2 * i
        content_id = 7 + 2 * i
        objects[page_id] = (
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] "
            "/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>"
            % (_PDF_PAGE_W, _PDF_PAGE_H, content_id)
        ).encode("latin-1")
        stream = streams[i]
        objects[content_id] = (
            ("<< /Length %d >>\nstream\n" % len(stream)).encode("latin-1")
            + stream
            + b"\nendstream"
        )

    buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for num in sorted(objects):
        offsets[num] = len(buf)
        buf += ("%d 0 obj\n" % num).encode("latin-1")
        buf += objects[num]
        buf += b"\nendobj\n"
    max_num = max(objects)
    xref_at = len(buf)
    buf += ("xref\n0 %d\n" % (max_num + 1)).encode("latin-1")
    buf += b"0000000000 65535 f \n"
    for num in range(1, max_num + 1):
        buf += ("%010d 00000 n \n" % offsets.get(num, 0)).encode("latin-1")
    buf += (
        "trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % (max_num + 1, xref_at)
    ).encode("latin-1")

    out.write_bytes(bytes(buf))
    return out


def render_pdf(result: dict, path: str = OUTPUT_PDF) -> Path:
    """Render laporan PDF dan SELALU hasilkan file .pdf.

    WeasyPrint dipakai bila tersedia (tata letak penuh). Bila tidak tersedia
    atau gagal, laporan ditulis sebagai PDF valid memakai penulis PDF bawaan
    (tanpa dependensi tambahan) sehingga app.py selalu menemukan PDF final.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = _build_pdf_html(result)

    if HTML is not None:
        try:
            HTML(string=doc).write_pdf(str(out))
            if out.exists() and out.stat().st_size >= 1000 and out.read_bytes()[:5] == b"%PDF-":
                print(f"[*] PDF ditulis (WeasyPrint): {out} ({out.stat().st_size:,} bytes)")
                return out
        except Exception as exc:
            print(f"[!] WeasyPrint gagal ({type(exc).__name__}: {exc}); memakai PDF bawaan.")

    try:
        _write_builtin_pdf(doc, out, target=str(result.get("target") or ""))
        if not out.is_file() or out.stat().st_size < 1000 or out.read_bytes()[:5] != b"%PDF-":
            raise RuntimeError("Renderer bawaan menghasilkan berkas yang bukan PDF valid.")
        print(f"[*] PDF ditulis (built-in): {out} ({out.stat().st_size:,} bytes)")
        return out
    except Exception as exc:
        # Jangan mengembalikan file .html seolah-olah laporan PDF berhasil.
        # Biarkan pemanggil menerima exception yang jelas dan dapat ditangani UI.
        raise RuntimeError(
            f"Gagal membuat PDF dengan WeasyPrint maupun renderer bawaan: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════
def main(argv: Optional[list[str]] = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv:
        print("Pemakaian: python -m vuln_pipeline <url> [--html file.html] [--active] [--pdf out.pdf]")
        return 2
    url = argv[0]
    html_file = None
    want_active = False
    pdf_out = OUTPUT_PDF
    i = 1
    while i < len(argv):
        if argv[i] == "--html" and i + 1 < len(argv):
            html_file = argv[i + 1]; i += 2
        elif argv[i] == "--active":
            want_active = True; i += 1
        elif argv[i] == "--pdf" and i + 1 < len(argv):
            pdf_out = argv[i + 1]; i += 2
        else:
            i += 1

    if html_file:
        page_html = Path(html_file).read_text(encoding="utf-8")
    else:
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT,
                                headers={"User-Agent": "DefensiveSecurityAudit/1.0"})
            page_html = resp.text
        except Exception as exc:
            print(f"[!] Gagal mengambil {url}: {exc}")
            return 1

    if want_active:
        confirm_active_scan_authorization()

    result = run_pipeline(url=url, html=page_html)
    print(render_lab_report(result["portswigger"]).split("\n### Ringkasan")[0])
    render_pdf(result, pdf_out)
    return 0


# ══════════════════════════════════════════════════════════════════════════════
# KONFIGURASI RUNTIME — dipakai app.py sebelum pemindaian dijalankan
# ══════════════════════════════════════════════════════════════════════════════

_RUNTIME_TRUE = {"1", "true", "yes", "on", "y", "ya", "aktif", "enabled", "enable"}
_RUNTIME_FALSE = {"0", "false", "no", "off", "n", "tidak", "nonaktif", "disabled", "disable", ""}

_BOOL_TARGETS = (
    "ENABLE_LLM", "RUN_CENSYS", "RUN_NVD", "RUN_ACTIVE_TOOLS",
    "ACTIVE_SCAN_AUTHORIZED", "ALLOW_PARTIAL_TOOLS",
)
_INT_TARGETS = (
    "REQUEST_TIMEOUT", "MAX_AGENT_ITERATIONS", "MAX_TOKENS_LLM",
    "KIOSAPI_MAX_OUTPUT_TOKENS", "KIOSAPI_MAX_PROMPT_CHARS",
    "MAX_PARSED_CHARS", "MAX_RAW_HTML_FOR_VERIFICATION",
)
_FLOAT_TARGETS = ("SLEEP_BETWEEN_NVD", "CENSYS_RATE_SLEEP")
_PATH_TARGETS = ("ARTIFACTS_DIR",)

# target global  ->  nama alternatif yang mungkin dipakai app.py / notebook
_RUNTIME_ALIASES: dict[str, tuple[str, ...]] = {
    "ENABLE_LLM": ("llm", "use_llm", "enable_ai", "ai", "llm_enabled",
                   "enable_llm_analysis", "aktifkan_llm"),
    "RUN_CENSYS": ("censys", "use_censys", "enable_censys", "censys_enabled"),
    "RUN_NVD": ("nvd", "use_nvd", "enable_nvd", "nvd_enabled"),
    "RUN_ACTIVE_TOOLS": ("active_tools", "use_active_tools", "use_tools",
                         "run_tools", "enable_tools"),
    "ACTIVE_SCAN_AUTHORIZED": ("authorized", "is_authorized", "authorization",
                               "active_authorized", "user_authorized",
                               "confirm_active", "confirm_active_scan",
                               "izin", "sudah_diizinkan"),
    "ALLOW_PARTIAL_TOOLS": ("partial_tools", "allow_partial", "tolerate_partial"),
    "REQUEST_TIMEOUT": ("timeout", "http_timeout", "request_timeout_s",
                        "timeout_seconds"),
    "MAX_AGENT_ITERATIONS": ("max_iterations", "agent_iterations",
                             "max_agent_steps", "iterations"),
    "MAX_TOKENS_LLM": ("max_tokens", "max_tokens_llm"),
    "KIOSAPI_MAX_OUTPUT_TOKENS": ("max_output_tokens",),
    "KIOSAPI_MAX_PROMPT_CHARS": ("max_prompt_chars",),
    "MAX_PARSED_CHARS": ("max_parsed_chars",),
    "MAX_RAW_HTML_FOR_VERIFICATION": ("max_raw_html", "max_html_chars"),
    "MODEL_PRIMARY": ("model", "llm_model", "kiosapi_model", "model_primary",
                      "nama_model"),
    "MODEL_FALLBACKS": ("fallback_models", "model_fallback", "model_fallbacks"),
    "KIOSAPI_BASE_URL": ("base_url", "api_base", "api_base_url", "kiosapi_url"),
    "KIOSAPI_API_KEY": ("api_key", "llm_api_key", "kiosapi_key", "kiosapi_api_key"),
    "CENSYS_PAT": ("censys_token", "censys_api_key", "censys_secret", "censys_pat"),
    "NVD_API_KEY": ("nvd_key", "nvd_api_key"),
    "ARTIFACTS_DIR": ("output_dir", "artifact_dir", "artifacts", "folder_output"),
    "SCRAPE_PATH": ("scrape_path", "scrape_result_path"),
    "FINDINGS_PATH": ("findings_path", "findings_json_path"),
    "OUTPUT_PDF": ("pdf_path", "report_path", "output_report"),
    "SLEEP_BETWEEN_NVD": ("nvd_sleep", "sleep_nvd"),
    "CENSYS_RATE_SLEEP": ("censys_sleep", "sleep_censys"),
}

_POSITIONAL_FLAGS = (
    "ENABLE_LLM", "RUN_CENSYS", "RUN_NVD", "RUN_ACTIVE_TOOLS",
    "ACTIVE_SCAN_AUTHORIZED",
)

_RUNTIME_CONFIG: dict[str, Any] = {name: globals().get(name) for name in _RUNTIME_ALIASES}


def _runtime_key_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for target, aliases in _RUNTIME_ALIASES.items():
        mapping[target.lower()] = target
        for alias in aliases:
            mapping[alias] = target
    return mapping


_RUNTIME_KEYS = _runtime_key_map()


def _normalize_runtime_key(raw: Any) -> str:
    return str(raw).strip().lower().replace("-", "_").replace(" ", "_").replace(".", "_")


def _coerce_runtime_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in _RUNTIME_TRUE:
        return True
    if text in _RUNTIME_FALSE:
        return False
    return bool(text)


def _coerce_runtime_value(target: str, value: Any) -> Any:
    if target in _BOOL_TARGETS:
        return _coerce_runtime_bool(value)
    if target in _INT_TARGETS:
        try:
            return int(value)
        except (TypeError, ValueError):
            return globals().get(target)
    if target in _FLOAT_TARGETS:
        try:
            return float(value)
        except (TypeError, ValueError):
            return globals().get(target)
    if target in _PATH_TARGETS:
        return Path(str(value))
    if target == "MODEL_FALLBACKS":
        if isinstance(value, str):
            parts = value.replace(";", ",").split(",")
        elif isinstance(value, (list, tuple, set)):
            parts = list(value)
        else:
            parts = [value]
        return [str(v).strip() for v in parts if str(v).strip()]
    return value


def configure_runtime(*args: Any, **overrides: Any) -> dict[str, Any]:
    """Terapkan konfigurasi runtime dari app.py / notebook.

    Menerima mapping, objek namespace (mis. hasil argparse), atau keyword apa pun.
    Nama yang tidak dikenal diabaikan tanpa melempar error, sehingga UI bebas
    menambah opsi baru. Nilai boolean menerima "1"/"true"/"yes"/"on".

    Contoh:
        configure_runtime(enable_llm=False, run_censys=True,
                          authorized=True, timeout=30)
        configure_runtime({"model": "qwen/qwen3-30b", "max_tokens": 4096})
    """
    incoming: dict[str, Any] = {}

    for idx, arg in enumerate(args):
        if arg is None:
            continue
        # app.py memanggil configure_runtime(work_dir, ...). Path/string
        # direktori pada posisi pertama harus diperlakukan sebagai output_dir,
        # bukan sebagai flag boolean.
        if idx == 0 and isinstance(arg, (Path, os.PathLike)):
            incoming["ARTIFACTS_DIR"] = arg
            continue
        if idx == 0 and isinstance(arg, str) and arg.strip() and not arg.strip().lower() in _RUNTIME_TRUE | _RUNTIME_FALSE:
            incoming["ARTIFACTS_DIR"] = arg
            continue
        if isinstance(arg, (bool, int, float, str)):
            if idx < len(_POSITIONAL_FLAGS):
                incoming[_POSITIONAL_FLAGS[idx]] = arg
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

    incoming.update(overrides)

    applied: dict[str, Any] = {}
    ignored: list[str] = []
    for raw_key, value in incoming.items():
        key = _normalize_runtime_key(raw_key)
        target = _RUNTIME_KEYS.get(key)
        if target is None:
            ignored.append(str(raw_key))
            continue
        new_value = _coerce_runtime_value(target, value)
        globals()[target] = new_value
        applied[target] = new_value

    # Saat app memberikan ARTIFACTS_DIR, arahkan seluruh artefak ke folder
    # job yang sama. Nilai eksplisit untuk masing-masing path tetap dihormati.
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

    # samakan env agar kode yang membaca os.getenv ikut konsisten
    for name, env_key in (("ENABLE_LLM", "SATRIA_ENABLE_LLM"),
                          ("RUN_CENSYS", "SATRIA_RUN_CENSYS"),
                          ("RUN_NVD", "SATRIA_RUN_NVD")):
        if name in applied:
            os.environ[env_key] = "1" if applied[name] else "0"

    # model utama tidak boleh muncul lagi di daftar fallback
    if "MODEL_PRIMARY" in applied:
        globals()["MODEL_FALLBACKS"] = [
            m for m in globals().get("MODEL_FALLBACKS", []) if m != globals()["MODEL_PRIMARY"]
        ]

    _RUNTIME_CONFIG.update({name: globals().get(name) for name in _RUNTIME_ALIASES})
    _RUNTIME_CONFIG["_ignored"] = ignored
    return dict(_RUNTIME_CONFIG)


def get_runtime_config() -> dict[str, Any]:
    """Snapshot konfigurasi runtime yang sedang aktif."""
    return {name: globals().get(name) for name in _RUNTIME_ALIASES}


if __name__ == "__main__":
    raise SystemExit(main())
