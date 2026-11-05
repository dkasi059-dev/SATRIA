#!/usr/bin/env python3
"""
apply_ssrf_fix.py — Surgical SSRF detection fix for satria_engine.py

Hanya mengubah 11 baris dalam run_ssrf_open_redirect_chain_analyzer.
TIDAK menulis ulang fungsi, TIDAK menghapus apapun.
Verifikasi configure_runtime + run_pipeline tetap ada sebelum dan sesudah.
Auto-restore dari backup jika ada kegagalan.

Usage:
  python apply_ssrf_fix.py "satria_engine (6).py"
  python apply_ssrf_fix.py "satria_engine (6).py" --restore
"""
import sys
import shutil
import py_compile
from pathlib import Path

OLD_BLOCK = '''            admin_markers = {
                "admin_heading": bool(re.search(r"<h[1-6][^>]*>[^<]*admin|<title[^>]*>[^<]*admin", body, re.I)),
                "carlos_user": bool(re.search(r"\\bcarlos\\b", body, re.I)),
                "delete_route": bool(re.search(r"/admin/delete(?:\\?|['\\" ])", body, re.I)),
            }
            admin_page_signal = bool(admin_markers["admin_heading"] and (admin_markers["carlos_user"] or admin_markers["delete_route"]))'''

NEW_BLOCK = '''            admin_markers = {
                "admin_heading": bool(re.search(r"<h[1-6][^>]*>[^<]*admin|<title[^>]*>[^<]*admin", body, re.I)),
                "carlos_user": bool(re.search(r"\\bcarlos\\b", body, re.I)),
                "wiener_user": bool(re.search(r"\\bwiener\\b", body, re.I)),
                "delete_route": bool(re.search(r"/admin/delete(?:\\?|['\\"\\s>]|$)", body, re.I)),
                "users_heading": bool(re.search(r"<h[1-6][^>]*>\\s*users\\s*</h[1-6]>", body, re.I)),
                "user_table": bool(re.search(r"<table[\\s\\S]{0,800}?(?:carlos|wiener|/admin/delete)", body, re.I)),
            }
            admin_page_signal = bool(
                (admin_markers["carlos_user"] and admin_markers["delete_route"])
                or (admin_markers["wiener_user"] and admin_markers["delete_route"])
                or (admin_markers["users_heading"] and admin_markers["carlos_user"])
                or admin_markers["admin_heading"]
                or (admin_markers["user_table"] and admin_markers["carlos_user"])
            )'''

REQUIRED_SYMBOLS = [
    "def configure_runtime(",
    "def run_pipeline(",
    "def run_ssrf_open_redirect_chain_analyzer(",
    "def feature_param_fuzzing(",
    "def _satria_ps_scenario_profile(",
]


def check_integrity(source, label):
    missing = [s for s in REQUIRED_SYMBOLS if s not in source]
    if missing:
        print(f"[{label}] MISSING: {missing}")
        return False
    print(f"[{label}] OK: all {len(REQUIRED_SYMBOLS)} required symbols present")
    return True


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python apply_ssrf_fix.py <engine.py> [--restore]")
    engine = Path(sys.argv[1]).resolve()
    if not engine.exists():
        sys.exit(f"File not found: {engine}")
    backup = engine.with_suffix(engine.suffix + ".bak")

    if "--restore" in sys.argv:
        if not backup.exists():
            sys.exit(f"No backup at {backup}")
        shutil.copy2(backup, engine)
        print(f"[restore] {engine} <- {backup}")
        return

    source = engine.read_text(encoding="utf-8")

    # Pre-check
    print(f"[pre] {len(source):,} chars")
    if not check_integrity(source, "pre"):
        if backup.exists():
            print(f"Restore first: python {sys.argv[0]} {sys.argv[1]} --restore")
        sys.exit(1)

    # Idempotency
    if NEW_BLOCK in source and OLD_BLOCK not in source:
        print("[idempotent] Already patched. No changes.")
        return
    if OLD_BLOCK not in source:
        sys.exit("[error] Target block not found — file version mismatch.")

    # Backup
    if not backup.exists():
        shutil.copy2(engine, backup)
        print(f"[backup] {backup}")

    # Patch
    new_source = source.replace(OLD_BLOCK, NEW_BLOCK, 1)
    if new_source == source:
        sys.exit("[error] Replacement had no effect")

    # Post-check
    if not check_integrity(new_source, "post"):
        print(f"[error] Restoring from {backup}")
        shutil.copy2(backup, engine)
        sys.exit(1)

    # Syntax check
    try:
        py_compile.compile(str(engine), doraise=True)  # sanity on original path
        compile(new_source, str(engine), "exec")
        print("[syntax] OK")
    except SyntaxError as e:
        print(f"[error] Syntax error: {e}")
        shutil.copy2(backup, engine)
        sys.exit(1)

    engine.write_text(new_source, encoding="utf-8")
    print(f"[done] {engine}: {len(source):,} -> {len(new_source):,} chars")

    # Final: import + attribute check
    print("\n[verify] Importing module ...")
    import subprocess
    code = (
        f"import importlib.util\n"
        f"spec = importlib.util.spec_from_file_location('m', {str(engine)!r})\n"
        f"m = importlib.util.module_from_spec(spec)\n"
        f"spec.loader.exec_module(m)\n"
        f"for n in ('configure_runtime','run_pipeline','run_ssrf_open_redirect_chain_analyzer'):\n"
        f"    assert hasattr(m, n), f'missing {{n}}'\n"
        f"print('OK: configure_runtime / run_pipeline / run_ssrf all accessible')\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=180)
    print(r.stdout.strip())
    if r.returncode != 0:
        print(r.stderr.strip()[-600:])
        print("\n[WARN] Import failed. Restoring backup ...")
        shutil.copy2(backup, engine)
        sys.exit(1)
    print("\n== SUCCESS ==")


if __name__ == "__main__":
    main()
