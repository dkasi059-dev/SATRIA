from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import ipaddress
import os
import re
import socket
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

_GLOBAL_SCAN_LOCK = threading.Lock()

import requests
import streamlit as st
from bs4 import BeautifulSoup


# -----------------------------------------------------------------------------
# Streamlit page and styling
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SATRIA | Web Security Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
      html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
      .stApp { background: #08111f; color: #e5edf7; }
      [data-testid="stHeader"] { background: rgba(8,17,31,0.92); }
      [data-testid="stSidebar"] { background: #0c1929; border-right: 1px solid #1d3047; }
      .satria-hero { padding: 1.5rem 1.6rem; border: 1px solid #24415c; border-radius: 18px;
        background: linear-gradient(125deg, #10243a 0%, #102c42 55%, #14243b 100%);
        box-shadow: 0 16px 45px rgba(0,0,0,.18); margin-bottom: 1.2rem; }
      .satria-eyebrow { color: #70d6d0; font-weight: 700; font-size: .75rem; letter-spacing: .20em; }
      .satria-title { font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 2.55rem;
        letter-spacing: .10em; line-height: 1.05; color: #f8fbff; margin: .35rem 0 .4rem 0; }
      .satria-subtitle { color: #b7c8d9; font-size: 1rem; margin: 0; }
      .satria-tag { display:inline-block; border:1px solid #35617b; background:#102f43; color:#a7e6df;
        border-radius:999px; padding:.25rem .7rem; font-size:.72rem; font-weight:700; margin:.8rem .35rem 0 0; }
      .section-label { color:#9cb6ca; font-size:.75rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
      .panel { border:1px solid #20364d; border-radius:14px; padding:1rem 1.1rem; background:#0c1a2a; }
      .muted { color:#9bb0c3; font-size:.88rem; }
      .stButton > button[kind="primary"] { background:linear-gradient(90deg,#0e8f94,#176b9d); border:0; color:white; font-weight:700; }
      .stButton > button, .stDownloadButton > button { border-radius:10px; min-height:2.8rem; }
      div[data-testid="stProgressBar"] > div > div { background:linear-gradient(90deg,#20b8a8,#3186c8); }
      .small-note { color:#91a6b8; font-size:.78rem; }
      div[data-testid="stMetric"] { background:#0d1d30; border:1px solid #223c54; padding:.8rem; border-radius:12px; }
      div[data-testid="stMetricLabel"] { color:#a7bacb; }
      div[data-testid="stMetricValue"] { color:#f1f7fc; }
      .stTextInput input { background:#091625; color:#eef6ff; border-color:#29445d; }
      [data-testid="stMarkdownContainer"] a { color:#70d6d0; }
    </style>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# Secrets and lightweight access gate
# -----------------------------------------------------------------------------
def _secret(name: str, default: str = "") -> str:
    try:
        value = st.secrets.get(name, default)
        if value is not None and str(value).strip():
            return str(value).strip()
    except Exception:
        pass
    return os.getenv(name, default).strip()


APP_ACCESS_PASSWORD = _secret("SATRIA_ACCESS_PASSWORD")
if APP_ACCESS_PASSWORD:
    if not st.session_state.get("satria_authenticated", False):
        st.markdown("## Akses SATRIA")
        access_input = st.text_input("Password akses", type="password", key="satria_access_input")
        if st.button("Masuk", type="primary"):
            if hmac.compare_digest(access_input, APP_ACCESS_PASSWORD):
                st.session_state["satria_authenticated"] = True
                st.rerun()
            else:
                st.error("Password tidak sesuai.")
        st.stop()


# -----------------------------------------------------------------------------
# Target validation: reject local/private/reserved addresses to reduce SSRF risk.
# -----------------------------------------------------------------------------
def normalize_target_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ValueError("Alamat website wajib diisi.")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Gunakan alamat website HTTP atau HTTPS yang valid.")
    if parts.username or parts.password:
        raise ValueError("URL tidak boleh memuat username atau password.")
    if parts.fragment:
        parts = parts._replace(fragment="")
    host = (parts.hostname or "").rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
        raise ValueError("Hostname lokal/internal tidak diizinkan.")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Port pada URL tidak valid.") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Port pada URL tidak valid.")
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def validate_public_target(url: str) -> list[str]:
    """Resolve the hostname and reject non-global IPs before contacting it."""
    parts = urlsplit(normalize_target_url(url))
    host = parts.hostname or ""
    resolved: set[str] = set()
    try:
        literal = ipaddress.ip_address(host)
        resolved.add(str(literal))
    except ValueError:
        try:
            records = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"Hostname tidak dapat di-resolve: {host}") from exc
        for record in records:
            resolved.add(record[4][0].split("%", 1)[0])
    if not resolved:
        raise ValueError("Hostname tidak menghasilkan alamat IP.")
    blocked = []
    for raw_ip in resolved:
        ip = ipaddress.ip_address(raw_ip)
        if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            blocked.append(raw_ip)
    if blocked:
        raise ValueError("Target mengarah ke IP nonpublik/khusus; pemindaian dihentikan.")
    return sorted(resolved)


# -----------------------------------------------------------------------------
# Scraping: Geekflare (rendered HTML) first, safe HTTP-only fallback second.
# -----------------------------------------------------------------------------
def _safe_direct_fetch(start_url: str, max_redirects: int = 4, max_bytes: int = 5_000_000) -> tuple[str, str, int]:
    current = start_url
    headers = {"User-Agent": "SATRIA-WebSec/1.0 (+authorized security assessment)"}
    for _ in range(max_redirects + 1):
        validate_public_target(current)
        response = requests.get(current, headers=headers, timeout=(8, 25), allow_redirects=False, stream=True)
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise RuntimeError("Redirect tidak memiliki header Location.")
            current = normalize_target_url(urljoin(current, location))
            continue
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "").lower()
        if content_type and not any(x in content_type for x in ("text/html", "application/xhtml+xml", "text/plain")):
            response.close()
            raise RuntimeError(f"Respons target bukan HTML (Content-Type: {content_type[:100]}).")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=64_000):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                response.close()
                raise RuntimeError(f"HTML melebihi batas {max_bytes:,} byte.")
            chunks.append(chunk)
        status = response.status_code
        response.close()
        encoding = response.encoding or "utf-8"
        html = b"".join(chunks).decode(encoding, errors="replace")
        return html, current, status
    raise RuntimeError("Terlalu banyak redirect.")


def _object_to_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    for method_name in ("to_dict", "model_dump", "dict"):
        method = getattr(obj, method_name, None)
        if callable(method):
            try:
                result = method()
                if isinstance(result, dict):
                    return result
            except Exception:
                continue
    import json
    try:
        return json.loads(json.dumps(obj, default=str))
    except Exception:
        raise RuntimeError("Format respons scraper tidak dapat dibaca.")


def scrape_target(url: str, geekflare_key: str) -> tuple[dict[str, Any], str]:
    """Return pipeline-compatible scrape dictionary and source-mode label."""
    if geekflare_key:
        try:
            from geekflare_api.client import GeekflareClient
            from geekflare_api.models import WebScrapeDto, WebScrapeDtoProxyMode
            dto = WebScrapeDto(
                url=url,
                format=["markdown", "html"],
                proxy_mode=WebScrapeDtoProxyMode("auto"),
            )
            with GeekflareClient(api_key=geekflare_key) as client:
                raw = client.web_scrape(dto)
            data = _object_to_dict(raw)
            payload = data.get("data", data)
            html = payload.get("html") or payload.get("html-llm") or ""
            if isinstance(html, str) and html.strip():
                meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
                # Keep the user-entered hostname as the assessment scope anchor.
                meta = dict(meta)
                meta["returned_url"] = meta.get("url", "")
                meta["url"] = url
                meta["scrape_mode"] = "geekflare"
                data["meta"] = meta
                return data, "Geekflare rendered HTML snapshot"
        except Exception as exc:
            st.warning(f"Geekflare tidak tersedia; beralih ke pengambilan HTML HTTP biasa. Detail: {str(exc)[:220]}")

    html, final_url, status = _safe_direct_fetch(url)
    md = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
    scrape = {
        "data": {"html": html, "markdown": md},
        "meta": {
            "url": url,
            "final_url": final_url,
            "http_status": status,
            "scrape_mode": "direct_http_static",
            "scraped_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    return scrape, "Raw HTTP HTML (static; JavaScript rendering tidak dijalankan)"


# -----------------------------------------------------------------------------
# Progress capture for the existing pipeline's step messages.
# -----------------------------------------------------------------------------
class StreamlitLogCapture(io.TextIOBase):
    STEP_RE = re.compile(r"\[(\d+)/10\]")
    # Progress per kerentanan/probe dari engine: "[PROGRESS i/n] label".
    # Dulu hanya [x/10] yang dibaca, padahal engine tidak pernah mencetaknya
    # untuk probe -- progress tampak terhenti pada satu angka selama scan.
    PROGRESS_RE = re.compile(r"\[PROGRESS\s+(\d+)/(\d+)\]\s*(.*)")

    def __init__(self, progress_bar, status_box, log_box):
        self.progress_bar = progress_bar
        self.status_box = status_box
        self.log_box = log_box
        self.buffer = ""
        self.lines: list[str] = []
        self.last_progress = 0.18

    def write(self, text: str) -> int:
        if not text:
            return 0
        self.buffer += text
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            line = line.rstrip()
            if not line:
                continue
            self.lines.append(line)
            self.lines = self.lines[-70:]
            progress_match = self.PROGRESS_RE.search(line)
            if progress_match:
                done, total = int(progress_match.group(1)), int(progress_match.group(2))
                label = progress_match.group(3).strip() or line.strip()
                frac = (done / total) if total else 0.0
                self.last_progress = min(0.94, 0.20 + frac * 0.72)
                self.progress_bar.progress(self.last_progress)
                # Tampilkan kerentanan yang SEDANG dipindai, bukan angka diam.
                self.status_box.info(f"[{done}/{total}] {label[:220]}")
                self.log_box.code("\n".join(self.lines[-55:]), language="text")
                continue
            match = self.STEP_RE.search(line)
            if match:
                step = int(match.group(1))
                self.last_progress = min(0.94, 0.20 + (step / 10.0) * 0.72)
                self.progress_bar.progress(self.last_progress)
                self.status_box.info(line.strip())
                self.log_box.code("\n".join(self.lines[-55:]), language="text")
            elif line.startswith(("      [", "[", "      ✓", "✓", "[!]")):
                # Increment gently for sub-steps without pretending that every request is progress.
                self.last_progress = min(0.94, self.last_progress + 0.003)
                self.progress_bar.progress(self.last_progress)
                if any(token in line.lower() for token in ("gagal", "error", "warning", "dilewati")):
                    self.status_box.warning(line.strip()[:240])
                self.log_box.code("\n".join(self.lines[-55:]), language="text")
        return len(text)

    def flush(self) -> None:
        if self.buffer.strip():
            self.lines.append(self.buffer.rstrip())
            self.buffer = ""
            self.log_box.code("\n".join(self.lines[-55:]), language="text")


# -----------------------------------------------------------------------------
# UI
# -----------------------------------------------------------------------------
st.markdown(
    """
    <div class="satria-hero">
      <div class="satria-eyebrow">CYBERSECURITY INTELLIGENCE PLATFORM</div>
      <div class="satria-title">S A T R I A</div>
      <p class="satria-subtitle">Sistem Agen Terpadu Reconnaissance, Intelijen, dan Analisis Ancaman</p>
      <span class="satria-tag">PASSIVE RECON</span>
      <span class="satria-tag">ACTIVE RECON</span>
      <span class="satria-tag">TECHNOLOGY FINGERPRINTING</span>
      <span class="satria-tag">CVE INTELLIGENCE</span>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("## 🛡️ SATRIA WebSec")
    st.caption("Evidence-driven website security assessment")
    st.markdown("---")
    st.markdown("**Integrasi layanan**")
    geekflare_key = _secret("GEEKFLARE_API_KEY")
    kiosapi_key = _secret("KIOSAPI_API_KEY")
    censys_token = _secret("CENSYS_API_TOKEN")
    nvd_key = _secret("NVD_API_KEY")
    st.write(f"Geekflare: {'Terhubung' if geekflare_key else 'Fallback HTTP statis'}")
    st.write(f"KiosAPI: {'Aktif' if kiosapi_key else 'Tidak dikonfigurasi (opsional)'}")
    st.write(f"Censys: {'Aktif' if censys_token else 'Tidak dikonfigurasi (opsional)'}")
    st.write(f"NVD API key: {'Tersedia' if nvd_key else 'Tidak ada (public rate limit)'}")
    st.markdown("---")
    st.markdown("**Mode pemeriksaan**")
    st.write("Passive reconnaissance: ON")
    st.write("Technology & CVE lookup: ON")
    st.write("Active scanning: ON setelah persetujuan")
    st.caption("Tool CLI eksternal hanya berjalan jika tersedia pada host deployment.")
    st.markdown("---")
    st.markdown("<div class='small-note'>Jangan mengunggah API key ke GitHub. Simpan di Streamlit Secrets.</div>", unsafe_allow_html=True)
    if not APP_ACCESS_PASSWORD:
        st.warning("SATRIA_ACCESS_PASSWORD belum diatur. Atur password sebelum membagikan aplikasi ke publik.")

st.markdown("### Mulai penilaian keamanan")
st.markdown(
    "Masukkan alamat website yang menjadi tanggung jawab Anda. SATRIA akan mengumpulkan bukti, "
    "menjalankan pemeriksaan yang tersedia, menyusun prioritas triase, dan membuat laporan PDF."
)

with st.form("satria_scan_form", clear_on_submit=False):
    target_input = st.text_input(
        "Alamat website",
        placeholder="https://contoh-domain.com",
        help="Gunakan domain publik yang Anda miliki atau yang telah memberikan izin pengujian tertulis.",
    )
    authorized = st.checkbox(
        "Saya pemilik website ini atau memiliki izin eksplisit untuk melakukan passive dan active security assessment, termasuk crawling, directory probing, pengujian parameter, dan pemindaian tool yang tersedia.",
        value=False,
    )
    submitted = st.form_submit_button("Jalankan", type="primary", use_container_width=True)

st.markdown(
    "<p class='small-note'>Pengamanan: target localhost, jaringan privat, link-local, dan IP khusus ditolak. "
    "Active scan hanya berjalan setelah persetujuan otorisasi eksplisit.</p>",
    unsafe_allow_html=True,
)

# Session state prevents an automatic download and preserves the result after Streamlit reruns.
for key, default in {
    "satria_report_bytes": None,
    "satria_report_name": None,
    "satria_result_summary": None,
    "satria_target": None,
    "satria_completed_at": None,
    "satria_source_mode": None,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


if submitted:
    if not target_input.strip():
        st.error("Masukkan alamat website terlebih dahulu.")
    elif not authorized:
        st.error("Konfirmasi kepemilikan/izin pengujian wajib diberikan sebelum SATRIA dijalankan.")
    else:
        try:
            target_url = normalize_target_url(target_input)
            resolved_ips = validate_public_target(target_url)
        except Exception as exc:
            st.error(f"Target tidak memenuhi validasi keamanan: {exc}")
            st.stop()

        # Single-process concurrency guard. For multiple replicas, use an external job queue.
        if not _GLOBAL_SCAN_LOCK.acquire(blocking=False):
            st.error("SATRIA sedang menjalankan pemindaian lain. Silakan coba kembali setelah proses tersebut selesai.")
            st.stop()

        st.session_state["satria_report_bytes"] = None
        st.session_state["satria_report_name"] = None
        st.session_state["satria_result_summary"] = None
        st.session_state["satria_target"] = target_url
        st.session_state["satria_source_mode"] = None

        st.markdown("### Progres pemindaian")
        progress_bar = st.progress(0.03)
        status_box = st.empty()
        log_box = st.empty()
        started = time.time()
        work_dir = tempfile.mkdtemp(prefix="satria_job_")

        try:
            status_box.info(
                f"Memvalidasi target publik dan menyiapkan scraper ... "
                f"(batas scan: {float(os.getenv('SATRIA_SCAN_DEADLINE_SECONDS', '600') or 600):.0f} detik)")
            progress_bar.progress(0.08)
            scrape_data, source_mode = scrape_target(target_url, geekflare_key)
            st.session_state["satria_source_mode"] = source_mode
            progress_bar.progress(0.17)
            status_box.info(f"Sumber HTML: {source_mode}. Memulai pipeline analisis ...")

            # Import only after Streamlit Secrets have been read; credentials are not embedded in files.
            kiosapi_model = _secret("KIOSAPI_MODEL")
            if kiosapi_model:
                os.environ["KIOSAPI_MODEL"] = kiosapi_model
            import satria_engine as engine

            engine.configure_runtime(
                work_dir,
                kiosapi_key=kiosapi_key,
                censys_token=censys_token,
                nvd_api_key=nvd_key,
                authorized=True,
            )
            engine.KIOSAPI_BASE_URL = "https://kiosapi.com/v1"
            engine.RUN_ACTIVE_TOOLS = True
            engine.RUN_DIR_BRUTE = True
            engine.RUN_CENSYS = True
            engine.RUN_NVD = True
            engine.ENABLE_LLM = True
            engine.ALLOW_PARTIAL_TOOLS = True
            engine.ACTIVE_SCAN_AUTHORIZED = True
            # Batas waktu scan global (detik). 0 = tanpa batas (tidak disarankan:
            # scan bisa berjalan puluhan menit tanpa progres yang terlihat).
            try:
                engine.SCAN_DEADLINE_SECONDS = float(
                    os.getenv("SATRIA_SCAN_DEADLINE_SECONDS", "600") or 600)
            except ValueError:
                engine.SCAN_DEADLINE_SECONDS = 600.0
            engine._load_kiosapi_api_key = lambda: kiosapi_key

            # Retain source-fidelity metadata when the static direct-fetch fallback is used.
            original_persist = engine.persist_scrape_artifacts
            def persist_with_source_quality(payload):
                paths = original_persist(payload)
                try:
                    meta_path = paths["meta"]
                    import json
                    meta = json.loads(Path(meta_path).read_text(encoding="utf-8"))
                    original_meta = payload.get("meta", {}) if isinstance(payload, dict) else {}
                    if isinstance(original_meta, dict) and original_meta.get("scrape_mode") == "direct_http_static":
                        meta["html_source_field"] = "html-static"
                        meta["html_source_is_full_dom"] = False
                        meta["html_source_note"] = (
                            "HTML mentah dari satu respons HTTP; bukan rendered DOM dan tidak mencakup perubahan "
                            "yang memerlukan JavaScript. Temuan berbasis DOM/runtime harus dianggap terbatas."
                        )
                        Path(meta_path).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
                except Exception:
                    pass
                return paths
            engine.persist_scrape_artifacts = persist_with_source_quality

            capture = StreamlitLogCapture(progress_bar, status_box, log_box)
            with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
                result = engine.run_pipeline(
                    scrape_data=scrape_data,
                    allow_partial_tools=True,
                    enable_llm=bool(kiosapi_key),
                )
            capture.flush()

            pdf_path = Path(engine.OUTPUT_PDF)
            if not pdf_path.exists() or pdf_path.stat().st_size < 1000:
                raise RuntimeError("Pipeline selesai tetapi PDF final tidak ditemukan atau terlalu kecil.")
            pdf_bytes = pdf_path.read_bytes()
            summary = result.get("summary", {}) if isinstance(result, dict) else {}
            st.session_state["satria_report_bytes"] = pdf_bytes
            st.session_state["satria_report_name"] = f"SATRIA_Report_{urlsplit(target_url).hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            st.session_state["satria_result_summary"] = summary
            st.session_state["satria_completed_at"] = datetime.now(timezone.utc).isoformat()
            progress_bar.progress(1.0)
            status_box.success(f"Pemindaian selesai dalam {time.time() - started:.1f} detik. Laporan siap diunduh.")
            st.success("Laporan berhasil dibuat. File tidak diunduh otomatis; tekan tombol Unduh di bawah untuk mengambil PDF.")
        except Exception as exc:
            status_box.error("Pemindaian tidak berhasil diselesaikan.")
            st.exception(exc)
        finally:
            # Keep only report bytes in session state; remove transient evidence and raw scrape files.
            try:
                import shutil
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception:
                pass
            _GLOBAL_SCAN_LOCK.release()


# -----------------------------------------------------------------------------
# Results and manual download action (no automatic download)
# -----------------------------------------------------------------------------
if st.session_state.get("satria_report_bytes"):
    st.markdown("---")
    st.markdown("### Hasil penilaian")
    st.markdown(f"**Target:** `{st.session_state.get('satria_target', '-')}`")
    st.caption(f"Sumber HTML: {st.session_state.get('satria_source_mode') or '-'}")
    summary = st.session_state.get("satria_result_summary") or {}
    triage = summary.get("triage_by_severity", {}) or summary.get("by_severity", {}) or {}
    metrics = st.columns(5)
    for col, severity in zip(metrics, ("critical", "high", "medium", "low", "info")):
        col.metric(severity.upper(), int(triage.get(severity, 0) or 0))
    c1, c2, c3 = st.columns(3)
    c1.metric("Terkonfirmasi manual", int(summary.get("confirmed_manual", 0) or 0))
    c2.metric("Kandidat / indikasi", int(summary.get("candidates_total", 0) or 0))
    c3.metric("Observasi", int(summary.get("observations_total", 0) or 0))
    st.info("Distribusi severity di atas adalah prioritas triase otomatis, bukan klaim bahwa seluruh item telah terbukti dapat dieksploitasi.")
    st.download_button(
        label="Unduh laporan PDF",
        data=st.session_state["satria_report_bytes"],
        file_name=st.session_state["satria_report_name"],
        mime="application/pdf",
        use_container_width=True,
    )
    st.caption("Unduhan hanya dimulai setelah tombol **Unduh laporan PDF** ditekan.")
elif st.session_state.get("satria_target") and not submitted:
    st.caption("Pemindaian sebelumnya belum menghasilkan laporan pada sesi ini.")

st.markdown("---")
st.markdown(
    "<div class='small-note'>SATRIA · Evidence-driven assessment · Gunakan hanya pada aset yang Anda miliki atau memiliki izin tertulis untuk diuji. "
    "Hasil otomatis tetap memerlukan tinjauan profesional sebelum dijadikan dasar keputusan keamanan.</div>",
    unsafe_allow_html=True,
)
