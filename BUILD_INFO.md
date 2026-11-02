# Build information

- Project: SATRIA WebSec
- Streamlit entrypoint: `app.py`
- Engine: `satria_engine.py`
- Engine source: final notebook `Scan_web_report_severity_kiosapi_fixed.ipynb`, implementation cells 3–11.
- Notebook-only trigger was removed so importing the module does not immediately scan a target.
- Notebook-only interactive prompts were bypassed through the Streamlit consent UI and server-side secrets.
- Pipeline paths are redirected into a per-run temporary working directory.
- The existing HTML/WeasyPrint report renderer is retained.
- KiosAPI base URL remains `https://kiosapi.com/v1`.
- PDF download is a user-initiated Streamlit download button shown only after successful report generation.

The package has passed Python syntax compilation, engine import, default-flag assertions, and a synthetic PDF smoke test in the build environment. A live Streamlit session, external Geekflare/KiosAPI/Censys/NVD connectivity, and a real target scan were not executed during packaging.
