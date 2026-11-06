"""
Interactive Web Application for Steganography + Watermarking System.
Built with Streamlit for live demonstration, parameter tuning, and academic presentation.
Includes full support for custom photo upload for both embedding and extraction.
"""

import os
import io
import numpy as np
from PIL import Image
import streamlit as st
import pandas as pd

from core.watermark import WatermarkKey, DwtSvdWatermarker
from core.pipeline import DualDomainPipeline
from core.metrics import (
    calculate_psnr,
    calculate_ssim,
    calculate_nc,
    calculate_ber,
    calculate_capacity,
)
from core.attacks import (
    attack_jpeg_compression,
    attack_gaussian_noise,
    attack_salt_pepper,
    attack_cropping,
    attack_median_filter,
    attack_gaussian_blur,
)


st.set_page_config(
    page_title="Dual-Domain Stego-Watermark System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ Dual-Domain Steganography & Digital Watermarking System")
st.markdown(
    """
    **Sistem Integrasi Domain Ganda (Frequency DWT-SVD + Spatial PRNG-LSB AES-256-GCM)**
    Mendukung penuh upload foto mandiri untuk penyisipan (*embedding*) maupun ekstraksi (*extraction*).
    """
)

# ---------------------------------------------------------
# Sidebar Configuration
# ---------------------------------------------------------
st.sidebar.header("⚙️ Konfigurasi Sistem")

standard_covers = {
    "Lena (512x512)": "data/covers/lena.png",
    "Peppers (512x512)": "data/covers/peppers.png",
    "Baboon (512x512)": "data/covers/baboon.png",
    "Airplane (512x512)": "data/covers/airplane.png",
}

standard_watermarks = {
    "Copyright Logo (64x64)": "data/watermarks/copyright_64.png",
    "Security Text (64x64)": "data/watermarks/watermark_text_64.png",
    "Compact Logo (32x32)": "data/watermarks/copyright_32.png",
}

alpha_val = st.sidebar.slider(
    "Watermark Strength Factor (α)", min_value=0.01, max_value=0.15, value=0.05, step=0.01,
    help="Nilai α mengontrol keseimbangan antara imperceptibility citra (PSNR) dan robustness watermark."
)

subband_choice = st.sidebar.selectbox(
    "DWT Subband Target", ["HL", "LH", "HH", "LL"], index=0,
    help="HL/LH direkomendasikan untuk stabilitas frekuensi menengah terhadap kompresi."
)

default_passphrase = st.sidebar.text_input(
    "Secret Passphrase (AES-256-GCM)", value="Aria2026SecureKey!", type="password"
)

# Ensure keys backup directory exists
os.makedirs("output/keys", exist_ok=True)
backup_key_path = "output/keys/latest_key.key"

# Initialize Session State
if "last_stego_wm" not in st.session_state:
    st.session_state.last_stego_wm = None
if "last_key" not in st.session_state:
    st.session_state.last_key = None
if "last_wm_logo" not in st.session_state:
    st.session_state.last_wm_logo = None
if "last_cover" not in st.session_state:
    st.session_state.last_cover = None
if "last_payload" not in st.session_state:
    st.session_state.last_payload = None

tabs = st.tabs([
    "📥 1. Penyisipan Ganda (Dual Embed)",
    "📤 2. Ekstraksi & Verifikasi",
    "⚡ 3. Simulator Uji Serangan (Robustness)",
])

# =========================================================
# TAB 1: DUAL EMBEDDING (Penyisipan Mandiri)
# =========================================================
with tabs[0]:
    st.subheader("1. Penyisipan Ganda: Watermark (DWT-SVD) + Steganografi (PRNG-LSB)")

    col_cov, col_wm = st.columns(2)
    with col_cov:
        st.markdown("#### 📷 A. Pilih / Upload Foto Cover")
        cover_source = st.radio(
            "Sumber Citra Cover:",
            ["Upload Foto Mandiri (Bebas)", "Citra Standar Benchmark"],
            horizontal=True,
            key="cov_src_choice"
        )

        cover_img_raw = None
        if cover_source == "Upload Foto Mandiri (Bebas)":
            uploaded_cov = st.file_uploader(
                "Unggah Foto Anda (PNG, JPG, JPEG, WEBP, BMP):",
                type=["png", "jpg", "jpeg", "webp", "bmp"],
                key="cov_uploader"
            )
            if uploaded_cov is not None:
                cover_img_raw = Image.open(uploaded_cov).convert("RGB")
                st.caption(f"📁 Foto diunggah: `{uploaded_cov.name}` | Resolusi Asli: `{cover_img_raw.size[0]}×{cover_img_raw.size[1]}`")
            else:
                # Default fallback
                cover_img_raw = Image.open(standard_covers["Lena (512x512)"]).convert("RGB")
                st.info("ℹ️ Belum ada foto diunggah, menampilkan preview citra default.")

            res_option = st.selectbox(
                "Penanganan Resolusi Foto:",
                [
                    "Auto-Resize 512×512 (Rekomendasi / Cepat)",
                    "Auto-Resize 1024×1024 (Resolusi Tinggi)",
                    "Pertahankan Resolusi Asli Foto",
                ],
                index=0,
                key="res_option_select"
            )
            if "512×512" in res_option:
                cover_img_proc = cover_img_raw.resize((512, 512), Image.Resampling.LANCZOS)
            elif "1024×1024" in res_option:
                cover_img_proc = cover_img_raw.resize((1024, 1024), Image.Resampling.LANCZOS)
            else:
                # Ensure even width and height for DWT
                w, h = cover_img_raw.size
                w_even = w - (w % 2)
                h_even = h - (h % 2)
                if w != w_even or h != h_even:
                    cover_img_proc = cover_img_raw.crop((0, 0, w_even, h_even))
                else:
                    cover_img_proc = cover_img_raw
        else:
            selected_cov = st.selectbox("Pilih Citra Benchmark:", list(standard_covers.keys()), key="bench_cov_sel")
            cover_img_raw = Image.open(standard_covers[selected_cov]).convert("RGB")
            cover_img_proc = cover_img_raw.resize((512, 512))

        st.image(
            cover_img_proc,
            caption=f"Cover Siap Diproses: {cover_img_proc.size[0]}×{cover_img_proc.size[1]} piksel (RGB)",
            use_container_width=True
        )

    with col_wm:
        st.markdown("#### 🛡️ B. Pilih / Upload Logo Watermark")
        wm_source = st.radio(
            "Sumber Logo Watermark:",
            ["Logo Standar", "Upload Logo Mandiri (PNG/JPG)"],
            horizontal=True,
            key="wm_src_choice"
        )
        if wm_source == "Logo Standar":
            selected_wm = st.selectbox("Pilih Logo Hak Cipta:", list(standard_watermarks.keys()), key="std_wm_sel")
            wm_img_proc = Image.open(standard_watermarks[selected_wm]).convert("L")
        else:
            uploaded_wm = st.file_uploader("Upload Logo Hak Cipta (PNG/JPG):", type=["png", "jpg", "jpeg"], key="custom_wm_up")
            if uploaded_wm is not None:
                wm_img_proc = Image.open(uploaded_wm).convert("L")
                st.caption(f"📁 Logo diunggah: `{uploaded_wm.name}` ({wm_img_proc.size[0]}×{wm_img_proc.size[1]})")
            else:
                wm_img_proc = Image.open(standard_watermarks["Copyright Logo (64x64)"]).convert("L")

        st.image(wm_img_proc, caption=f"Logo Watermark: {wm_img_proc.size[0]}×{wm_img_proc.size[1]}", width=128)

    st.markdown("#### 🔒 C. Data Rahasia (Steganografi Payload)")
    payload_mode = st.radio("Metode Input Payload:", ["Teks Langsung", "Upload File (TXT, JSON, PDF, dll)"], horizontal=True, key="pl_mode_radio")
    if payload_mode == "Teks Langsung":
        payload_text = st.text_area(
            "Pesan Rahasia:",
            value="OPERASI RAHASIA 2026: Sistem integrasi steganografi dan watermarking berhasil disisipkan dengan enkripsi AES-256-GCM pada citra kustom.",
            height=90,
            key="pl_text_input"
        )
        payload_bytes = payload_text.encode("utf-8")
    else:
        uploaded_pl = st.file_uploader("Upload File Payload Bebas:", type=None, key="custom_pl_file")
        if uploaded_pl is not None:
            payload_bytes = uploaded_pl.read()
        else:
            payload_bytes = b"Contoh payload default berukuran ringkas."

    # Dynamic Capacity calculation based on actual image dimensions
    w_p, h_p = cover_img_proc.size
    cap_info = calculate_capacity((h_p, w_p, 3))
    st.info(
        f"ℹ️ Dimensi Citra: **{w_p}×{h_p} px** | Ukuran Payload: **{len(payload_bytes):,} bytes** | "
        f"Kapasitas Maksimum Carrier: **{cap_info['max_bytes']:,} bytes** (~{cap_info['bpp']} bpp)"
    )

    if st.button("🚀 Jalankan Penyisipan Ganda", type="primary", key="btn_run_embed"):
        with st.spinner("Memproses penyisipan DWT-SVD (Frekuensi) dan PRNG-LSB AES-256 (Spasial)..."):
            pipeline = DualDomainPipeline(watermark_alpha=alpha_val, watermark_subband=subband_choice)
            cover_np = np.array(cover_img_proc)
            wm_np = np.array(wm_img_proc)

            try:
                embed_res = pipeline.run_dual_embedding(
                    cover_image=cover_np,
                    watermark_logo=wm_np,
                    stego_payload=payload_bytes,
                    stego_passphrase=default_passphrase,
                )

                # Store in session state
                st.session_state.last_stego_wm = embed_res.stego_watermarked_image
                st.session_state.last_key = embed_res.watermark_key
                st.session_state.last_wm_logo = wm_np
                st.session_state.last_cover = cover_np
                st.session_state.last_payload = payload_bytes

                # Backup key to disk
                embed_res.watermark_key.save_to_file(backup_key_path)

                st.success("✅ Penyisipan Ganda Berhasil Sempurna!")

                # Display Metric Badges
                m = embed_res.metrics
                c1, c2, c3, c4, c5 = st.columns(5)
                c1.metric("PSNR (Kualitas)", f"{m['psnr']:.2f} dB", delta=f"{m['delta_psnr']:+.2f} dB vs WM")
                c2.metric("SSIM (Struktur)", f"{m['ssim']:.4f}")
                c3.metric("Watermark NC", f"{m['post_stego_wm_nc']:.4f}", delta=f"{m['delta_nc']:+.5f} ΔNC")
                c4.metric("Waktu Proses", f"{embed_res.embed_time_ms:.1f} ms")
                c5.metric("Peak RAM", f"{embed_res.peak_memory_kb:.1f} KB")

                # Visual Comparisons
                col_res1, col_res2, col_res3 = st.columns(3)
                with col_res1:
                    st.image(embed_res.watermarked_image, caption="1. Watermarked Only (DWT-SVD)", use_container_width=True)
                with col_res2:
                    st.image(embed_res.stego_watermarked_image, caption="2. Stego-Watermarked (Final)", use_container_width=True)
                with col_res3:
                    diff = np.abs(cover_np.astype(float) - embed_res.stego_watermarked_image.astype(float)) * 20.0
                    st.image(np.clip(diff, 0, 255).astype(np.uint8), caption="3. Amplified Residual (x20)", use_container_width=True)

                # Download Buttons
                st.markdown("### 💾 Unduh Berkas Hasil Penyisipan")
                col_dl1, col_dl2 = st.columns(2)
                
                with col_dl1:
                    buf_img = io.BytesIO()
                    Image.fromarray(embed_res.stego_watermarked_image).save(buf_img, format="PNG")
                    st.download_button(
                        label="⬇️ Unduh Foto Stego-Watermark (.png)",
                        data=buf_img.getvalue(),
                        file_name="stego_watermarked_output.png",
                        mime="image/png",
                        key="btn_dl_stego_img"
                    )

                with col_dl2:
                    key_bytes = embed_res.watermark_key.to_bytes()
                    st.download_button(
                        label="⬇️ Unduh File Kunci Watermark (watermark_key.key)",
                        data=key_bytes,
                        file_name="watermark_key.key",
                        mime="application/octet-stream",
                        help="File ini berisi metadata nilai singular untuk merekonstruksi logo hak cipta saat ekstraksi.",
                        key="btn_dl_wm_key"
                    )

            except Exception as ex:
                st.error(f"❌ Terjadi kesalahan selama penyisipan: {ex}")


# =========================================================
# TAB 2: EXTRACTION & VERIFICATION (Ekstraksi Mandiri)
# =========================================================
with tabs[1]:
    st.subheader("2. Ekstraksi Mandiri & Verifikasi Integritas Data")
    st.markdown(
        "Unggah foto apa pun hasil steganografi dan watermarking untuk memulihkan pesan rahasia terenkripsi "
        "serta membuktikan tanda kepemilikan hak cipta."
    )

    col_ext_img, col_ext_key = st.columns(2)

    with col_ext_img:
        st.markdown("#### 📷 A. Sumber Foto yang Ingin Diekstrak")
        img_source_choice = st.radio(
            "Pilih Sumber Foto:",
            ["Upload Foto Mandiri (PNG/JPG)", "Gunakan Foto dari Sesi Terakhir (di Memori)"],
            horizontal=True,
            key="img_source_ext"
        )

        target_ext_img = None
        if img_source_choice == "Upload Foto Mandiri (PNG/JPG)":
            uploaded_ext_file = st.file_uploader(
                "Upload File Foto Stego-Watermark (PNG/JPG):",
                type=["png", "jpg", "jpeg", "webp", "bmp"],
                key="ext_img_uploader"
            )
            if uploaded_ext_file is not None:
                pil_target = Image.open(uploaded_ext_file).convert("RGB")
                target_ext_img = np.array(pil_target)
                st.caption(f"📁 Foto siap diekstrak: `{uploaded_ext_file.name}` ({target_ext_img.shape[1]}×{target_ext_img.shape[0]} px)")
                st.image(target_ext_img, caption="Citra Target Ekstraksi", use_container_width=True)
            else:
                st.info("ℹ️ Silakan upload file foto hasil steganografi/watermarking di atas.")
        else:
            if st.session_state.last_stego_wm is not None:
                target_ext_img = st.session_state.last_stego_wm
                st.caption(f"📁 Menggunakan foto dari sesi memori aktif ({target_ext_img.shape[1]}×{target_ext_img.shape[0]} px)")
                st.image(target_ext_img, caption="Citra dari Sesi Terakhir", use_container_width=True)
            else:
                st.warning("⚠️ Tidak ada citra di memori aktif. Silakan pilih 'Upload Foto Mandiri'.")

    with col_ext_key:
        st.markdown("#### 🔑 B. Sumber File Kunci Watermark (.key)")
        key_source_choice = st.radio(
            "Pilih Sumber Kunci Watermark:",
            ["Upload File Kunci (.key)", "Gunakan Kunci Sesi Terakhir / File Backup", "Lewati Ekstraksi Watermark (Hanya Steganografi)"],
            key="key_source_ext"
        )

        loaded_wm_key = None
        if key_source_choice == "Upload File Kunci (.key)":
            uploaded_key_file = st.file_uploader(
                "Upload File Kunci Watermark (`.key`):",
                type=["key", "dat", "bin"],
                key="ext_key_uploader"
            )
            if uploaded_key_file is not None:
                try:
                    loaded_wm_key = WatermarkKey.from_bytes(uploaded_key_file.read())
                    st.success(f"✅ Kunci Watermark Valid! (Subband: `{loaded_wm_key.subband}`, α: `{loaded_wm_key.alpha}`)")
                except Exception as e:
                    st.error(f"❌ File kunci tidak valid: {e}")
            else:
                st.info("ℹ️ Upload file `.key` yang Anda unduh saat penyisipan.")
        elif key_source_choice == "Gunakan Kunci Sesi Terakhir / File Backup":
            if st.session_state.last_key is not None:
                loaded_wm_key = st.session_state.last_key
                st.success("✅ Menggunakan kunci dari sesi aktif.")
            elif os.path.exists(backup_key_path):
                try:
                    loaded_wm_key = WatermarkKey.load_from_file(backup_key_path)
                    st.success("✅ Menggunakan file kunci cadangan lokal (`output/keys/latest_key.key`).")
                except Exception:
                    st.warning("⚠️ Gagal membaca file cadangan lokal.")
            else:
                st.warning("⚠️ Tidak ditemukan kunci di memori maupun disk cadangan.")
        else:
            st.info("ℹ️ Ekstraksi watermark akan dilewati. Sistem hanya akan memulihkan data rahasia steganografi.")

    st.markdown("#### 🔐 C. Kunci Dekripsi Steganografi (Passphrase)")
    extract_pass = st.text_input(
        "Masukkan Secret Passphrase:",
        value=default_passphrase,
        type="password",
        key="ext_passphrase_input"
    )

    # Optional reference logo for NC calculation
    ref_logo_choice = st.selectbox(
        "Logo Acuan untuk Menghitung Korelasi NC (Opsional):",
        ["Tidak Menggunakan Acuan (Hanya Tampilkan Logo)", "Copyright Logo (64x64)", "Security Text (64x64)", "Compact Logo (32x32)"],
        index=1,
        key="ref_logo_sel"
    )

    if st.button("🔍 Jalankan Ekstraksi & Verifikasi", type="primary", key="btn_run_extract"):
        if target_ext_img is None:
            st.error("❌ Silakan sediakan citra target terlebih dahulu (upload atau gunakan sesi aktif).")
        else:
            with st.spinner("Mengekstraksi data rahasia dan merekonstruksi tanda kepemilikan..."):
                col_res_stego, col_res_wm = st.columns(2)

                # 1. Ekstraksi Steganografi (Blind)
                with col_res_stego:
                    st.markdown("### 🔒 1. Hasil Ekstraksi Steganografi")
                    stego_engine = DualDomainPipeline().steganographer
                    try:
                        decrypted_data = stego_engine.extract(target_ext_img, extract_pass)
                        st.success("✅ Dekripsi AES-256-GCM Sukses! Tag Autentikasi Valid.")
                        st.caption(f"Ukuran payload terpulihkan: **{len(decrypted_data)} bytes**")

                        # Text or Binary handling
                        try:
                            decoded_text = decrypted_data.decode("utf-8")
                            st.text_area("Plaintext Rahasia Terpulihkan:", value=decoded_text, height=130)
                            
                            # Download Text
                            st.download_button(
                                label="⬇️ Unduh Pesan Terpulihkan (.txt)",
                                data=decoded_text,
                                file_name="recovered_secret.txt",
                                mime="text/plain",
                                key="btn_dl_rec_txt"
                            )
                        except UnicodeDecodeError:
                            st.info("Data terpulihkan adalah file biner.")
                            st.download_button(
                                label="⬇️ Unduh Berkas Biner Terpulihkan (.bin)",
                                data=decrypted_data,
                                file_name="recovered_secret.bin",
                                mime="application/octet-stream",
                                key="btn_dl_rec_bin"
                            )
                    except Exception as e:
                        st.error(f"❌ Gagal Dekripsi Steganografi: {e}")
                        st.caption("Penyebab: Passphrase salah, atau citra telah termodifikasi/rusak oleh serangan kompresi/noise.")

                # 2. Ekstraksi Watermark (Semi-Blind)
                with col_res_wm:
                    st.markdown("### 🛡️ 2. Hasil Ekstraksi Watermark Hak Cipta")
                    if loaded_wm_key is not None:
                        try:
                            wm_engine = DwtSvdWatermarker(alpha=loaded_wm_key.alpha, subband=loaded_wm_key.subband)
                            extracted_logo = wm_engine.extract(target_ext_img, loaded_wm_key)

                            st.image(
                                extracted_logo,
                                caption=f"Logo Watermark Terekstraksi ({extracted_logo.shape[1]}×{extracted_logo.shape[0]})",
                                width=150
                            )

                            # Calculate NC if reference logo is selected
                            if ref_logo_choice != "Tidak Menggunakan Acuan (Hanya Tampilkan Logo)":
                                ref_path = standard_watermarks.get(ref_logo_choice)
                                if ref_path and os.path.exists(ref_path):
                                    ref_np = np.array(Image.open(ref_path).convert("L"))
                                    nc_score = calculate_nc(ref_np, extracted_logo)
                                    if nc_score >= 0.85:
                                        st.success(f"✅ Hak Cipta Sah Terverifikasi! (NC = **{nc_score:.4f}** ≥ 0.85)")
                                    else:
                                        st.warning(f"⚠️ Terjadi Degradasi Hak Cipta (NC = **{nc_score:.4f}** < 0.85)")

                            # Download Logo Button
                            buf_logo = io.BytesIO()
                            Image.fromarray(extracted_logo).save(buf_logo, format="PNG")
                            st.download_button(
                                label="⬇️ Unduh Logo Terekstraksi (.png)",
                                data=buf_logo.getvalue(),
                                file_name="extracted_watermark_logo.png",
                                mime="image/png",
                                key="btn_dl_rec_logo"
                            )

                        except Exception as e:
                            st.error(f"❌ Gagal Ekstraksi Watermark: {e}")
                    else:
                        st.info("ℹ️ Ekstraksi watermark dilewati (tidak ada file kunci `.key` yang dipilih).")


# =========================================================
# TAB 3: ROBUSTNESS ATTACK SIMULATOR
# =========================================================
with tabs[2]:
    st.subheader("3. Simulator Uji Ketahanan Manipulasi Citra (Robustness Attacks)")
    
    current_test_img = st.session_state.last_stego_wm
    if current_test_img is None:
        st.warning("⚠️ Jalankan proses penyisipan pada Tab 1 terlebih dahulu untuk menguji simulasi serangan.")
    else:
        att_type = st.selectbox(
            "Pilih Jenis Serangan Manipulasi / Gangguan Kanal:",
            [
                "JPEG Compression",
                "Additive Gaussian Noise",
                "Salt & Pepper Noise",
                "Cropping (Pemotongan Sebagian Citra)",
                "Median Filtering",
                "Gaussian Blur",
            ],
            key="att_type_select"
        )

        col_p, col_prev = st.columns([1, 2])
        attacked_image = None

        with col_p:
            if att_type == "JPEG Compression":
                q_factor = st.slider("Quality Factor (Q)", 10, 95, 50, step=5, key="q_slider")
                attacked_image = attack_jpeg_compression(current_test_img, q_factor)
            elif att_type == "Additive Gaussian Noise":
                var_val = st.slider("Variance Noise (σ²)", 0.001, 0.05, 0.01, step=0.002, key="var_slider")
                attacked_image = attack_gaussian_noise(current_test_img, 0.0, var_val)
            elif att_type == "Salt & Pepper Noise":
                prob_val = st.slider("Density Probabilitas (p)", 0.005, 0.10, 0.02, step=0.005, key="sp_slider")
                attacked_image = attack_salt_pepper(current_test_img, prob_val)
            elif att_type == "Cropping (Pemotongan Sebagian Citra)":
                crop_ratio = st.slider("Rasio Luas Crop", 0.05, 0.40, 0.20, step=0.05, key="crop_slider")
                crop_pos = st.selectbox("Posisi Potong:", ["center", "top_left", "bottom_right"], key="crop_pos_sel")
                attacked_image = attack_cropping(current_test_img, crop_ratio, crop_pos)
            elif att_type == "Median Filtering":
                k_size = st.selectbox("Ukuran Kernel:", [3, 5, 7], key="med_k_sel")
                attacked_image = attack_median_filter(current_test_img, k_size)
            elif att_type == "Gaussian Blur":
                radius_val = st.slider("Blur Radius", 0.5, 3.0, 1.0, step=0.5, key="blur_r_slider")
                attacked_image = attack_gaussian_blur(current_test_img, radius_val)

        with col_prev:
            st.image(attacked_image, caption=f"Citra Pasca Serangan ({att_type})", use_container_width=True)

        if st.session_state.last_cover is not None:
            psnr_att = calculate_psnr(st.session_state.last_cover, attacked_image)
            ssim_att = calculate_ssim(st.session_state.last_cover, attacked_image)
            st.write(f"📊 Kualitas Citra Pasca Serangan: **PSNR: {psnr_att:.2f} dB** | **SSIM: {ssim_att:.4f}**")

        if st.button("🧪 Uji Ketahanan Pasca Serangan", key="btn_test_attack"):
            pipeline = DualDomainPipeline(watermark_alpha=alpha_val, watermark_subband=subband_choice)
            extract_res = pipeline.run_dual_extraction(
                stego_watermarked_image=attacked_image,
                watermark_key=st.session_state.last_key,
                original_watermark_logo=st.session_state.last_wm_logo,
                stego_passphrase=default_passphrase,
                original_payload=st.session_state.last_payload,
            )

            col_res_a, col_res_b = st.columns(2)
            with col_res_a:
                st.markdown("#### Ketahanan Watermark (DWT-SVD)")
                st.image(extract_res.extracted_watermark, caption=f"Logo Terpulihkan (NC: {extract_res.watermark_nc:.4f})", width=140)
                if extract_res.watermark_nc >= 0.85:
                    st.success(f"🛡️ Watermark Tahan Serangan! (NC: **{extract_res.watermark_nc:.4f}** ≥ 0.85)")
                else:
                    st.warning(f"⚠️ Watermark Mengalami Degradasi (NC: {extract_res.watermark_nc:.4f})")

            with col_res_b:
                st.markdown("#### Karakteristik Steganografi (Fragility)")
                if extract_res.stego_success:
                    st.success(f"🔓 Pesan Rahasia Bertahan Utuh! (BER: {extract_res.stego_ber:.1f}%)")
                else:
                    st.info(
                        "🛡️ Sifat Fragile Terkonfirmasi: Pesan rahasia terlindungi dari modifikasi. "
                        "Deteksi kerusakan memicu penolakan AES-GCM (Anti-Tampering)."
                    )
