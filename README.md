# SATRIA WebSec

**SATRIA — Sistem Agen Terpadu Reconnaissance, Intelijen, dan Analisis Ancaman**  
*Evidence-driven website security assessment*

Aplikasi Streamlit untuk menjalankan passive reconnaissance, technology fingerprinting, pemeriksaan konfigurasi aplikasi, dependency/CVE intelligence, serta pemeriksaan aktif yang dibatasi scope dan memerlukan persetujuan eksplisit.

## Fitur aplikasi

- Input alamat website melalui antarmuka Streamlit.
- Tombol **Jalankan** untuk memulai proses.
- Progress bar dan log tahapan pipeline.
- Scraping menggunakan Geekflare API jika `GEEKFLARE_API_KEY` tersedia; jika tidak, SATRIA menggunakan pengambilan HTML HTTP biasa dan menandai hasilnya sebagai snapshot statis (bukan rendered DOM).
- Technology fingerprinting, HTTP/security posture, DNS/email reconnaissance, dependency dan pencarian CVE dari sumber publik yang tersedia pada engine.
- Enrichment KiosAPI jika `KIOSAPI_API_KEY` tersedia.
- Lookup Censys jika `CENSYS_API_TOKEN` tersedia.
- Pembuatan laporan PDF.
- Tombol **Unduh laporan PDF** baru muncul setelah proses berhasil. File tidak diunduh otomatis.
- File sementara hasil scraping dan JSON dihapus setelah pipeline selesai; hanya byte PDF disimpan pada sesi Streamlit.

## Struktur proyek

```text
SATRIA_WebSec/
├── app.py                         # Entry point Streamlit
├── satria_engine.py               # Pipeline inti hasil adaptasi notebook final
├── requirements.txt               # Dependensi Python
├── packages.txt                   # Dependensi sistem untuk WeasyPrint
├── Dockerfile                     # Opsi deploy container dengan Nuclei/jsluice
├── .streamlit/
│   ├── config.toml
│   └── secrets.toml.example
├── .github/workflows/
│   └── validate.yml
├── scripts/
│   └── smoke_test.py
└── README.md
```

## Deploy ke GitHub dan Streamlit Community Cloud

1. Ekstrak ZIP ini.
2. Buat repository baru di GitHub.
3. Unggah **isi folder `SATRIA_WebSec`** ke root repository (jangan mengunggah file rahasia atau `.streamlit/secrets.toml` sungguhan).
4. Buka Streamlit Community Cloud dan pilih **Create app**.
5. Pilih repository, branch, dan entrypoint `app.py`.
6. Pada **Advanced settings**, pilih Python 3.12.
7. Pada bagian **Secrets**, masukkan isi `.streamlit/secrets.toml.example`, lalu isi API key yang Anda miliki.
8. Deploy aplikasi.

Dokumentasi resmi: [Deploy Streamlit Community Cloud](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy), [app dependencies](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/app-dependencies), dan [file organization](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/file-organization).

### Secrets yang didukung

| Secret | Status | Fungsi |
|---|---|---|
| `GEEKFLARE_API_KEY` | Opsional | Scraping HTML/Markdown melalui Geekflare. Tanpa key, fallback HTTP statis digunakan. |
| `KIOSAPI_API_KEY` | Opsional | Enrichment melalui KiosAPI. Tanpa key, pipeline deterministik tetap berjalan. |
| `KIOSAPI_MODEL` | Opsional | Mengganti model KiosAPI. Default berasal dari engine. |
| `CENSYS_API_TOKEN` | Opsional | Lookup Censys. Tanpa token, lookup dilewati dan dicatat. |
| `NVD_API_KEY` | Opsional | Mengurangi pembatasan request NVD. |
| `SATRIA_ACCESS_PASSWORD` | Sangat disarankan untuk publik | Password bersama untuk membatasi akses aplikasi. |

**Jangan** memasukkan API key ke `app.py`, `satria_engine.py`, atau repository GitHub. Gunakan menu Secrets di Streamlit Community Cloud.

## Menjalankan secara lokal

Disarankan Python 3.11 atau 3.12.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
streamlit run app.py
```

Simpan secrets lokal di `.streamlit/secrets.toml` (file ini diabaikan Git):

```toml
GEEKFLARE_API_KEY = "isi-key-anda"
KIOSAPI_API_KEY = "isi-key-anda"
CENSYS_API_TOKEN = ""
NVD_API_KEY = ""
SATRIA_ACCESS_PASSWORD = "ganti-dengan-password-kuat"
```

## Pemindaian aktif dan batasan keamanan

SATRIA mengaktifkan modul operasional secara default pada pipeline, tetapi **active scanning hanya berjalan setelah pengguna mencentang pernyataan bahwa ia pemilik aset atau memiliki izin eksplisit**. Gunakan hanya pada domain yang Anda miliki atau yang telah memberikan izin tertulis. Pengakuan pengguna bukan pengganti tata kelola otorisasi organisasi.

Aplikasi menolak hostname lokal serta alamat IP private, loopback, link-local, reserved, dan non-global sebelum proses awal. Ini mengurangi risiko SSRF, tetapi bukan jaminan keamanan jaringan absolut. Untuk deployment publik/produksi:

- Set `SATRIA_ACCESS_PASSWORD` dan batasi akses melalui authentication/proxy atau allow-list organisasi.
- Jalankan di lingkungan terisolasi dengan egress firewall; jangan berikan akses ke jaringan internal, metadata cloud, atau control plane.
- Terapkan pembatasan request, CPU, memori, waktu, dan jumlah pemindaian per pengguna pada reverse proxy/job worker.
- Pertimbangkan antrean pekerjaan terpisah untuk deployment multi-replica; lock pada aplikasi ini hanya melindungi satu proses.
- Nuclei dan jsluice adalah tool eksternal opsional. Mereka dijalankan hanya jika binary tersedia pada host. Wapiti/TLS scanner juga dapat tidak tersedia pada beberapa host Streamlit Cloud; kekurangan tool harus dibaca sebagai cakupan tidak lengkap, bukan hasil negatif.

### Privasi data

Jika Geekflare digunakan, URL dan permintaan scraping diproses oleh layanan Geekflare. Jika KiosAPI diaktifkan, konteks hasil analisis dapat dikirim ke KiosAPI untuk enrichment. Pastikan Anda memiliki izin dan dasar pemrosesan yang sesuai sebelum menganalisis website atau mengirim kontennya ke layanan pihak ketiga. Jangan scan halaman yang membutuhkan kredensial atau mengandung data pribadi tanpa kebijakan dan izin yang tepat.

## Uji smoke test

Setelah dependensi terpasang:

```bash
python scripts/smoke_test.py
```

Uji ini memeriksa import engine, konfigurasi flag, dan pembuatan PDF sintetis. Ini bukan pemindaian terhadap target nyata dan bukan jaminan bahwa semua API eksternal sedang tersedia.

## Interpretasi laporan

- Prioritas triase otomatis tidak sama dengan kerentanan yang telah dikonfirmasi.
- Hasil kosong atau API yang gagal tidak berarti website aman.
- CVE hanya boleh diperlakukan sebagai temuan website setelah identitas produk, versi/rentang terdampak, konteks deployment, dan bukti yang relevan diverifikasi.
- Hasil scanner perlu direproduksi dan ditinjau oleh analis sebelum menjadi dasar keputusan keamanan formal.
