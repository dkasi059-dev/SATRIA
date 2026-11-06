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
