# 🛡️ Sistem Terintegrasi Steganografi & Digital Watermarking Citra Digital

Implementasi lengkap dalam bahasa Python untuk penggabungan dua teknik *information hiding*:
1. **Digital Watermarking (Tanda Kepemilikan)** berbasis domain frekuensi **DWT-SVD** (Discrete Wavelet Transform + Singular Value Decomposition) untuk perlindungan hak cipta yang tahan terhadap manipulasi citra (*robustness*).
2. **Steganografi (Data Tersembunyi)** berbasis domain spasial **Adaptive PRNG-LSB Matching** dengan enkripsi **AES-256-GCM** untuk menyembunyikan data rahasia berkapasitas tinggi tanpa distorsi kasat mata (*high capacity & imperceptibility*).

---

## 📂 Struktur Direktori Proyek

```
steganwatermark/
├── input/                           # FOLDER INPUT PENGGUNA
│   ├── cover.png                    # Citra cover utama (512x512 RGB)
│   ├── watermark.png                # 1 Foto logo watermark yang dimau
│   └── payloads/                    # 10 Foto payload yang dimau (ukuran bertingkat)
│       ├── photo_payload_01_micro.png (~107 B)
│       ├── photo_payload_02_tiny.jpg  (~812 B)
│       ├── photo_payload_03_badge.png (~1.8 KB)
│       ├── photo_payload_04_icon.png  (~3.1 KB)
│       ├── photo_payload_05_stamp.png (~5.4 KB)
│       ├── photo_payload_06_avatar.png (~8.2 KB)
│       ├── photo_payload_07_emblem.png (~12.4 KB)
│       ├── photo_payload_08_seal.png  (~18.3 KB)
│       ├── photo_payload_09_thumbnail.png (~25.5 KB)
│       └── photo_payload_10_large_photo.png (~32.6 KB)
│
├── output/                          # FOLDER FOTO HASIL PROSES & FILE KUNCINYA
│   ├── stego_watermarked_payload_01..10.png   # 10 Foto hasil proses
│   ├── watermark_key_payload_01..10.key       # 10 File kunci metadata
│   ├── latest_stego_watermarked.png           # Foto hasil proses terbaru
│   ├── latest_key.key                         # Kunci watermark terbaru
│   └── sample_extracted_watermark.png         # Logo watermark terekstraksi
│
├── metric_result/                   # FOLDER METRIK LENGKAP & GRAFIK HASIL EVALUASI
│   ├── benchmark_metrics.csv        # Tabel metrik 10 payload (PSNR, SSIM, NC, BER, dll)
│   ├── robustness_attacks.csv       # Tabel uji ketahanan terhadap 6 jenis serangan
│   ├── summary_report.md            # Laporan ringkasan format Markdown
│   ├── plot1_quality_psnr_ssim.png  # Grafik 1: PSNR & SSIM vs Ukuran Payload (.png)
│   ├── plot2_interference_analysis.png # Grafik 2: Analisis Interferensi NC & Delta NC (.png)
│   ├── plot3_efficiency_complexity.png # Grafik 3: Waktu Komputasi & Penggunaan RAM (.png)
│   ├── plot4_robustness_attacks.png # Grafik 4: Diagram Ketahanan Watermark (.png)
│   └── plot5_visual_comparison.png  # Grafik 5: Visual Side-by-Side & Amplified Residual (.png)
│
├── core/                            # ENGINE LOGIKA DASAR
│   ├── crypto.py                    # Enkripsi AES-256-GCM & PBKDF2
│   ├── watermark.py                 # DWT-SVD Watermark Engine & Serialisasi Key
│   ├── steganography.py             # PRNG-LSB Matching Steganography
│   ├── pipeline.py                  # Dual-Domain Pipeline & Tracker Interferensi
│   ├── metrics.py                   # PSNR, SSIM, MSE, SNR, BER, NC, Kapasitas
│   ├── attacks.py                   # 6 Jenis Serangan (JPEG, Noise, Crop, Filter, Blur)
│   └── steganalysis.py              # Steganalisis Chi-Square (χ²) Pairs of Values
│
├── scripts/
│   └── generate_sample_inputs.py    # Script utilitas untuk reset 10 foto payload sampel
├── run_evaluation.py                # Command CLI untuk running evaluasi metrik lengkap
├── extract.py                       # Command CLI untuk ekstraksi mandiri dari citra mana pun
├── app.py                           # Web UI Interaktif (Streamlit 3 Tab)
├── tests/
│   └── test_core.py                 # Suite 11 unit test otomatis
└── requirements.txt                 # Dependensi pustaka Python
```

---

## 🚀 Panduan Eksekusi

### 1. Menjalankan Evaluasi Metrik Lengkap via CLI (Sesuai Permintaan)
Cukup jalankan satu perintah berikut:
```bash
python run_evaluation.py
```
Perintah ini akan membaca:
- Citra cover dari `input/cover.png`
- 1 foto watermark dari `input/watermark.png`
- 10 foto payload dari `input/payloads/`

Lalu menghasilkan:
- **Foto hasil proses & kuncinya** ditaruh di folder **`output/`** (`stego_watermarked_payload_*.png` & `watermark_key_payload_*.key`).
- **Metrik lengkap & 5 grafik resolusi tinggi (`.png`)** ditaruh di folder **`metric_result/`** (`benchmark_metrics.csv`, `plot1` s/d `plot5`, dll).

### 2. Mengganti dengan Foto Payload & Watermark Anda Sendiri
1. Taruh 1 foto watermark hak cipta Anda di: `input/watermark.png`.
2. Taruh 10 foto/file payload rahasia Anda di: `input/payloads/`.
3. (Opsional) Ganti foto cover di: `input/cover.png`.
4. Jalankan kembali:
   ```bash
   python run_evaluation.py
   ```
*Jika sewaktu-waktu ingin mengembalikan 10 foto payload sampel default:*
```bash
python scripts/generate_sample_inputs.py
```

### 3. Ekstraksi Mandiri via CLI (`extract.py`)
Mengekstrak pesan rahasia dan/atau logo watermark dari foto hasil proses di `output/`:
```bash
# Ekstraksi foto hasil proses payload 07:
python extract.py --image output/stego_watermarked_payload_07.png \
                  --key-file output/watermark_key_payload_07.key \
                  --watermark-ref input/watermark.png \
                  --passphrase "Aria2026SecureKey!"
```

### 4. Menjalankan Web GUI Streamlit Interaktif
Antarmuka web telah disederhanakan menjadi 3 tab interaktif (tanpa tab benchmark yang telah dipindah ke CLI):
```bash
streamlit run app.py
```
- **Tab 1: Penyisipan Ganda**: Upload foto sendiri (PNG/JPG), pilih logo watermark, ketik/upload payload, dan unduh foto hasil serta kuncinya.
- **Tab 2: Ekstraksi & Verifikasi**: Upload foto hasil steganografi dan file `.key` untuk ekstraksi instan.
- **Tab 3: Simulator Uji Serangan**: Uji ketahanan citra terhadap kompresi JPEG, noise, cropping, dan filter.

### 5. Menjalankan Unit Tests
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📊 Hasil Evaluasi Terverifikasi (10 Foto Payload)

| No | Payload File | Ukuran (Bytes) | PSNR (dB) | SSIM | Watermark NC | Delta NC (Interferensi) | Stego BER (%) | Waktu Total (ms) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| 1  | `photo_payload_01_micro.png`       | 107 B    | **49.96** | 0.9987 | 0.9813 | **0.0000** | **0.0%** | 378 ms |
| 2  | `photo_payload_02_tiny.jpg`        | 812 B    | **49.93** | 0.9987 | 0.9813 | **0.0000** | **0.0%** | 314 ms |
| 3  | `photo_payload_03_badge.png`       | 1,820 B  | **49.90** | 0.9987 | 0.9814 | **0.0000** | **0.0%** | 311 ms |
| 4  | `photo_payload_04_icon.png`        | 3,172 B  | **49.85** | 0.9986 | 0.9814 | **0.0000** | **0.0%** | 809 ms |
| 5  | `photo_payload_05_stamp.png`       | 5,402 B  | **49.78** | 0.9985 | 0.9814 | **0.0000** | **0.0%** | 729 ms |
| 6  | `photo_payload_06_avatar.png`      | 8,232 B  | **49.69** | 0.9984 | 0.9813 | **0.0000** | **0.0%** | 711 ms |
| 7  | `photo_payload_07_emblem.png`      | 12,420 B | **49.56** | 0.9981 | 0.9814 | **0.0000** | **0.0%** | 909 ms |
| 8  | `photo_payload_08_seal.png`        | 18,398 B | **49.38** | 0.9978 | 0.9814 | **0.0000** | **0.0%** | 1,116 ms |
| 9  | `photo_payload_09_thumbnail.png`   | 25,552 B | **49.18** | 0.9974 | 0.9814 | **0.0000** | **0.0%** | 1,347 ms |
| 10 | `photo_payload_10_large_photo.png` | 32,620 B | **48.99** | 0.9970 | 0.9814 | **0.0000** | **0.0%** | 1,697 ms |

- **PSNR**: Konsisten **~49 - 50 dB** (jauh melampaui ambang batas 38 dB).
- **Interferensi $\Delta NC$**: **0.0000** (ketiadaan degradasi watermark akibat penyisipan stego).
- **Stego BER**: **0.0%** (seluruh data terekstraksi 100% identik *byte-for-byte*).
- **Ketahanan Watermark**: $NC > 0.970$ pada seluruh serangan kompresi JPEG $Q=50..90$, Gaussian Noise, Salt & Pepper, Cropping 20%, Filter, dan Blur.
