# 🛡️ GhostShare: Deniable Covert Data Vault & Anti-Censorship System

GhostShare adalah sistem brankas data tersembunyi (*covert data vault*) tingkat produksi (*production-grade*) berbasis steganografi dan kriptografi modern. Dirancang untuk jurnalis investigasi, pelapor pelanggaran (*whistleblowers*), peneliti keamanan, dan aktivis di bawah pengawasan siber ketat (*surveillance / deep packet inspection*).

---

## 🌟 Fitur Utama

1. **Plausible Deniability (Multi-Passphrase / Decoy Mode)**:
   - **Real Passphrase**: Membuka berkas rahasia utama (dokumen classified, database `.kdbx`, kunci PGP).
   - **Decoy Passphrase**: Membuka berkas tipuan yang tampak wajar (catatan belanja, foto keluarga, resep) jika pengguna dipaksa menyerahkan kata sandi.
   - Partisi ruang koordinat dijamin bebas-tabrakan ($I_{\text{real}} \cap I_{\text{decoy}} = \emptyset$). Lawan tidak dapat membuktikan secara matematis keberadaan berkas rahasia kedua.
2. **Zero-Auxiliary Footprint (100% Self-Contained Carrier)**:
   - Tidak memerlukan file kunci `.key` atau metadata eksternal terpisah. Citra pembawa (`carrier.png`) adalah satu-satunya file yang dibutuhkan untuk mengekstrak data.
3. **Arbitrary Binary Payload Support**:
   - Mendukung semua jenis file biner (PDF, ZIP, DOCX, TXT, KDBX, audio, gambar) dengan preservasi otomatis nama file asli dan *MIME-type*.
4. **Anti-Steganalysis & Forensic Audit**:
   - Algoritma **PRNG-LSB Matching ($\pm 1$)** menjaga simetri histogram nilai pasangan (*Pairs of Values*) sehingga lolos dari uji **Chi-Square ($\chi^2$)** Westfeld.
   - Fidelitas visual tinggi: **PSNR > 80 dB**, **SSIM 1.0000** (sama sekali tidak kasat mata).
5. **Antarmuka Web Modern & Siap Dideploy (Docker-Ready)**:
   - Antarmuka web bertema *Cyber Defense Vault* (Dark theme) dengan 3 tab interaktif.
   - Disertai `Dockerfile` dan `docker-compose.yml` tingkat produksi dengan keamanan *non-root user* dan *healthcheck endpoint*.

---

## 📂 Struktur Direktori Proyek

```
steganwatermark/
├── core/                                # CORE CRYPTO & STEGANOGRAPHY ENGINE
│   ├── envelope.py                      # Binary envelope serialization & MIME detection
│   ├── deniable.py                      # Collision-free PRNG coordinate partitioning
│   ├── vault.py                         # High-level GhostShare Vault orchestrator
│   ├── crypto.py                        # AES-256-GCM + PBKDF2-HMAC-SHA256
│   ├── steganography.py                 # PRNG-LSB Matching (±1 embedding)
│   ├── anti_steganalysis.py             # Chi-Square PoV & Forensic audit suite
│   ├── watermark.py                     # DWT-SVD Frequency Engine
│   ├── pipeline.py                      # Dual-Domain Pipeline Orchestrator
│   └── metrics.py                       # PSNR, SSIM, MSE, NC, BER
│
├── tests/
│   ├── test_ghostshare.py               # Unit tests untuk GhostShare (7 tests)
│   └── test_core.py                     # Unit tests untuk core engine (11 tests)
│
├── ghostshare_cli.py                    # Production CLI interface
├── app.py                               # Production Streamlit Web Vault interface
├── Dockerfile                           # Production container definition
├── docker-compose.yml                   # Container orchestration
├── requirements.txt                     # Dependensi Python
└── output/                              # Folder hasil carrier & berkas terekstraksi
```

---

## 🚀 Panduan Penggunaan CLI (`ghostshare_cli.py`)

### 1. Memeriksa Kapasitas Citra Pembawa
```bash
python ghostshare_cli.py capacity --cover input/cover.png
```

### 2. Menyembunyikan Berkas Rahasia (Single Payload Mode)
```bash
python ghostshare_cli.py pack \
  --cover input/cover.png \
  --secret secret_document.pdf \
  --secret-pass "MySecretPassphrase2026!" \
  --output output/carrier.png
```

### 3. Menyembunyikan Berkas dengan Plausible Deniability (Dual Mode)
```bash
python ghostshare_cli.py pack \
  --cover input/cover.png \
  --secret secret_document.pdf \
  --secret-pass "RealSecretKey2026!" \
  --decoy innocent_notes.txt \
  --decoy-pass "InnocentDecoyPass123!" \
  --output output/covert_carrier.png
```

### 4. Membuka & Mengekstrak Berkas
Gunakan sandi apa pun yang Anda miliki (sandi tipuan akan mengekstrak berkas tipuan; sandi asli akan mengekstrak berkas rahasia):
```bash
# Ekstrak berkas tipuan:
python ghostshare_cli.py unpack \
  --carrier output/covert_carrier.png \
  --passphrase "InnocentDecoyPass123!" \
  --out-dir output/recovered/

# Ekstrak berkas rahasia utama:
python ghostshare_cli.py unpack \
  --carrier output/covert_carrier.png \
  --passphrase "RealSecretKey2026!" \
  --out-dir output/recovered/
```

### 5. Audit Forensik & Steganalisis
```bash
python ghostshare_cli.py audit \
  --carrier output/covert_carrier.png \
  --cover input/cover.png
```

---

## 🌐 Menjalankan Web Vault Lokal

```bash
streamlit run app.py
```
Buka browser di `http://localhost:8501`.

---

## 🐳 Deployment via Docker / Docker Compose

### Menggunakan Docker Compose (Direkomendasikan):
```bash
docker compose up -d
```
Cek status container:
```bash
docker compose ps
```

### Menggunakan Docker Langsung:
```bash
# Build image
docker build -t ghostshare-vault:latest .

# Run container
docker run -d -p 8501:8501 --name ghostshare ghostshare-vault:latest
```

---

## 🧪 Menjalankan Pengujian Otomatis (Unit Tests)

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```
*Seluruh 18 pengujian terverifikasi lulus 100%.*
