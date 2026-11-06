"""
GhostShare Web Vault — Production-Grade Covert Data Vault & Anti-Censorship Interface.
Equipped with Plausible Deniability (Multi-Passphrase), Zero-Auxiliary-Key Architecture,
and Real-Time Forensic Steganalysis Auditing.
"""

import io
import os
import numpy as np
from PIL import Image
import streamlit as st
import matplotlib.pyplot as plt

from core.vault import GhostVault, GhostVaultError, ExtractedVaultPayload
from core.anti_steganalysis import run_full_audit, compute_amplified_residual


# -----------------------------------------------------------------------------
# Streamlit Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="GhostShare — Covert Data Vault",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Cyber Defense Styling (Dark Theme & Visual Cards)
st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    .metric-card {
        background: linear-gradient(135deg, #131b2e 0%, #1e293b 100%);
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .metric-value {
        font-size: 24px;
        font-weight: 700;
        color: #38bdf8;
    }
    .metric-label {
        font-size: 13px;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .status-badge-secure {
        display: inline-block;
        background-color: #064e3b;
        color: #34d399;
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 13px;
        border: 1px solid #059669;
    }
    .status-badge-warning {
        display: inline-block;
        background-color: #7f1d1d;
        color: #f87171;
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 13px;
        border: 1px solid #dc2626;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
@st.cache_data
def get_preset_covers():
    presets = {}
    preset_paths = {
        "Cover Sample (1024x1024)": "input/cover.png",
        "Lena (512x512)": "data/covers/lena.png",
        "Peppers (512x512)": "data/covers/peppers.png",
        "Baboon (512x512)": "data/covers/baboon.png",
        "Airplane (512x512)": "data/covers/airplane.png",
    }
    for name, path in preset_paths.items():
        if os.path.exists(path):
            presets[name] = path
    return presets


def load_image_from_file_or_preset(uploaded_file, preset_choice, presets_dict):
    if uploaded_file is not None:
        img = Image.open(uploaded_file)
        return np.array(img.convert("RGB")), uploaded_file.name
    elif preset_choice and preset_choice in presets_dict:
        path = presets_dict[preset_choice]
        img = Image.open(path)
        return np.array(img.convert("RGB")), os.path.basename(path)
    return None, ""


# -----------------------------------------------------------------------------
# Sidebar: System Status & Security Guide
# -----------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ GhostShare Vault")
    st.caption("Deniable Covert Data Vault v2.0 (Production)")

    st.markdown("---")
    st.subheader("🔐 Keamanan Sistem")
    st.markdown(
        """
        - **Kriptografi**: AES-256-GCM + PBKDF2-HMAC-SHA256 (100k iterasi)
        - **Steganografi**: PRNG-LSB Matching ($\pm 1$)
        - **Plausible Deniability**: Multi-Passphrase (*Real* vs *Decoy*) dengan partisi ruang bebas-tabrakan
        - **Zero-Key Footprint**: Citra pembawa 100% mandiri
        """
    )

    st.markdown("---")
    st.subheader("💡 Tips Plausible Deniability")
    st.info(
        "Jika Anda menghadapi risiko pemeriksaan paksa (coercion), gunakan fitur **Decoy Mode**. "
        "Memasukkan sandi tipuan akan membuka dokumen umpan yang sah, tanpa ada jejak matematis dari dokumen rahasia utama."
    )


# -----------------------------------------------------------------------------
# Main Application Tabs
# -----------------------------------------------------------------------------
tab_pack, tab_unpack, tab_audit = st.tabs([
    "🗄️ 1. Pack Vault (Kunci & Sembunyikan)",
    "🔓 2. Unpack Vault (Buka & Ekstrak)",
    "🔬 3. Forensic & Steganalysis Audit",
])

vault = GhostVault()


# =============================================================================
# TAB 1: PACK VAULT
# =============================================================================
with tab_pack:
    st.header("🗄️ Kemas & Sembunyikan File ke Citra Pembawa")
    st.write(
        "Sembunyikan file rahasia apa pun (PDF, ZIP, DOCX, TXT, KDBX, gambar) ke dalam citra foto biasa. "
        "Dapat mengaktifkan **Plausible Deniability** untuk proteksi terhadap pemaksaan kata sandi."
    )

    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("1. Pilih Citra Pembawa (Cover Image)")
        presets = get_preset_covers()
        preset_options = ["Unggah Gambar Sendiri (PNG/JPG)"] + list(presets.keys())
        choice = st.selectbox("Pilih Sumber Citra:", preset_options)

        cover_uploaded = None
        if choice == "Unggah Gambar Sendiri (PNG/JPG)":
            cover_uploaded = st.file_uploader("Unggah Cover Image:", type=["png", "jpg", "jpeg"])

        cover_arr, cover_fn = load_image_from_file_or_preset(cover_uploaded, choice, presets)

        if cover_arr is not None:
            st.image(cover_arr, caption=f"Cover: {cover_fn} ({cover_arr.shape[1]}x{cover_arr.shape[0]} px)", use_container_width=True)
            caps = vault.get_capacity_info(cover_arr.shape)
            
            c_m1, c_m2 = st.columns(2)
            with c_m1:
                st.metric("Kapasitas Single Payload", f"{caps['single_payload_max_bytes'] / 1024:.1f} KB")
            with c_m2:
                st.metric("Kapasitas Dual Decoy (Masing-masing)", f"{caps['dual_payload_max_bytes_each'] / 1024:.1f} KB")

    with col2:
        st.subheader("2. Berkas Rahasia Utama (Secret Payload)")
        secret_file = st.file_uploader("Pilih Berkas Rahasia Utama:", key="secret_file_input")
        secret_pass = st.text_input("Kata Sandi Rahasia Utama:", type="password", key="secret_pass_input", help="Digunakan untuk mengenkripsi payload rahasia.")

        st.markdown("---")
        use_deniability = st.checkbox("🛡️ Aktifkan Plausible Deniability (Decoy / Duress Mode)", value=False)

        decoy_file = None
        decoy_pass = None

        if use_deniability:
            st.markdown(
                """
                > **Plausible Deniability**: Memungkinkan Anda memiliki dua kata sandi berbeda pada satu gambar. 
                > Jika Anda dipaksa menyerahkan sandi, berikan **Decoy Passphrase** untuk membuka berkas tipuan di bawah.
                """
            )
            decoy_file = st.file_uploader("Pilih Berkas Tipuan (Decoy File):", key="decoy_file_input")
            decoy_pass = st.text_input("Kata Sandi Tipuan (Decoy Passphrase):", type="password", key="decoy_pass_input", help="Kata sandi yang diberikan saat dipaksa.")

        st.markdown("<br>", unsafe_allow_html=True)
        pack_btn = st.button("🔒 Kunci & Kemas ke Dalam Citra", type="primary", use_container_width=True)

    if pack_btn:
        if cover_arr is None:
            st.error("Silakan pilih atau unggah citra pembawa terlebih dahulu.")
        elif secret_file is None:
            st.error("Silakan pilih berkas rahasia utama yang ingin disembunyikan.")
        elif not secret_pass:
            st.error("Kata sandi rahasia utama tidak boleh kosong.")
        elif use_deniability and (decoy_file is None or not decoy_pass):
            st.error("Jika mode Plausible Deniability aktif, berkas tipuan dan sandi tipuan wajib diisi.")
        elif use_deniability and secret_pass == decoy_pass:
            st.error("Kata sandi tipuan harus berbeda dari kata sandi utama.")
        else:
            with st.spinner("Mengenkripsi dan menyisipkan data ke citra pembawa..."):
                secret_bytes = secret_file.read()
                decoy_bytes = decoy_file.read() if (use_deniability and decoy_file) else None

                try:
                    carrier_arr, audit = vault.pack(
                        cover_image=cover_arr,
                        secret_payload=secret_bytes,
                        secret_passphrase=secret_pass,
                        secret_filename=secret_file.name,
                        decoy_payload=decoy_bytes,
                        decoy_passphrase=decoy_pass,
                        decoy_filename=decoy_file.name if decoy_file else "decoy.bin",
                    )

                    st.success("✅ Berkas berhasil disembunyikan ke dalam citra pembawa!")

                    # Show Metrics
                    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
                    with m_col1:
                        st.markdown(f"<div class='metric-card'><div class='metric-label'>Fidelitas Visual (PSNR)</div><div class='metric-value'>{audit['psnr_db']:.2f} dB</div></div>", unsafe_allow_html=True)
                    with m_col2:
                        st.markdown(f"<div class='metric-card'><div class='metric-label'>Struktur Citra (SSIM)</div><div class='metric-value'>{audit['ssim']:.4f}</div></div>", unsafe_allow_html=True)
                    with m_col3:
                        st.markdown(f"<div class='metric-card'><div class='metric-label'>Stealth Score</div><div class='metric-value'>{audit['stealth_score']}%</div></div>", unsafe_allow_html=True)
                    with m_col4:
                        badge_class = "status-badge-secure" if audit["is_secure"] else "status-badge-warning"
                        st.markdown(f"<div class='metric-card'><div class='metric-label'>Status Keamanan</div><div style='margin-top:8px;'><span class='{badge_class}'>{audit['verdict']}</span></div></div>", unsafe_allow_html=True)

                    # Prepare Carrier Download
                    buf = io.BytesIO()
                    carrier_img_pil = Image.fromarray(carrier_arr.astype(np.uint8))
                    carrier_img_pil.save(buf, format="PNG")
                    carrier_bytes = buf.getvalue()

                    st.download_button(
                        label="⬇️ Unduh Citra Pembawa (carrier.png)",
                        data=carrier_bytes,
                        file_name="ghost_carrier.png",
                        mime="image/png",
                        type="primary",
                        use_container_width=True,
                    )

                except GhostVaultError as e:
                    st.error(f"Gagal mengemas brankas: {e}")


# =============================================================================
# TAB 2: UNPACK VAULT
# =============================================================================
with tab_unpack:
    st.header("🔓 Buka & Ekstrak Berkas dari Citra Pembawa")
    st.write(
        "Cukup unggah citra pembawa tunggal (`.png`) dan masukkan kata sandi Anda. "
        "Tidak memerlukan file kunci tambahan (*zero-key footprint*). "
        "Sistem secara otomatis mendeteksi apakah kata sandi yang Anda masukkan adalah sandi utama atau sandi tipuan."
    )

    col_u1, col_u2 = st.columns([1, 1])

    with col_u1:
        carrier_input = st.file_uploader("Unggah Citra Pembawa (PNG):", type=["png"], key="unpack_carrier_uploader")
        if carrier_input is not None:
            carrier_pil = Image.open(carrier_input)
            carrier_arr = np.array(carrier_pil.convert("RGB"))
            st.image(carrier_arr, caption=f"Carrier: {carrier_input.name} ({carrier_arr.shape[1]}x{carrier_arr.shape[0]} px)", use_container_width=True)
        else:
            carrier_arr = None

    with col_u2:
        unpack_pass = st.text_input("Masukkan Kata Sandi:", type="password", key="unpack_pass_input")
        unpack_btn = st.button("🔓 Buka Kunci Brankas", type="primary", use_container_width=True)

        if unpack_btn:
            if carrier_arr is None:
                st.error("Silakan unggah citra pembawa terlebih dahulu.")
            elif not unpack_pass:
                st.error("Silakan masukkan kata sandi.")
            else:
                with st.spinner("Memverifikasi integritas kriptografi dan mendekripsi berkas..."):
                    try:
                        extracted = vault.unpack(carrier_arr, unpack_pass)

                        st.success(f"🎉 Berhasil membuka berkas: **{extracted.filename}**")
                        
                        st.markdown(
                            f"""
                            <div class='metric-card'>
                                <div><strong>Nama File:</strong> {extracted.filename}</div>
                                <div><strong>Tipe Dokumen (MIME):</strong> {extracted.mime_type}</div>
                                <div><strong>Ukuran:</strong> {extracted.size_bytes:,} bytes ({extracted.size_bytes / 1024:.2f} KB)</div>
                                <div><strong>Slot Partisi:</strong> <span class='status-badge-secure'>{extracted.partition_mode.upper()}</span></div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                        # Download button for recovered file
                        st.download_button(
                            label=f"⬇️ Unduh Berkas Hasil Ekstraksi ({extracted.filename})",
                            data=extracted.payload_bytes,
                            file_name=extracted.filename,
                            mime=extracted.mime_type,
                            type="primary",
                            use_container_width=True,
                        )

                        # Inline preview if text or image
                        if extracted.mime_type.startswith("text/"):
                            st.subheader("📄 Pratinjau Teks:")
                            st.text_area("Isi Teks:", extracted.payload_bytes.decode("utf-8", errors="replace"), height=200)
                        elif extracted.mime_type.startswith("image/"):
                            st.subheader("🖼️ Pratinjau Citra:")
                            st.image(extracted.payload_bytes)

                    except GhostVaultError as e:
                        st.error(f"Gagal membuka brankas: {e}")


# =============================================================================
# TAB 3: FORENSIC & STEGANALYSIS AUDIT
# =============================================================================
with tab_audit:
    st.header("🔬 Audit Keamanan Forensik & Steganalisis")
    st.write(
        "Lakukan audit kuantitatif untuk menguji resistensi citra terhadap analisis statistik steganografi: "
        "Uji Chi-Square ($\chi^2$), rasio entropi bitplane LSB, serta inspeksi residual perbesaran $25\\times$."
    )

    col_a1, col_a2 = st.columns(2)
    with col_a1:
        audit_carrier_file = st.file_uploader("Unggah Citra yang Diuji (Carrier):", type=["png", "jpg"], key="audit_carrier")
    with col_a2:
        audit_cover_file = st.file_uploader("Unggah Citra Pembanding Asli (Opsional):", type=["png", "jpg"], key="audit_cover")

    audit_btn = st.button("🔍 Jalankan Audit Forensik Menyeluruh", type="primary")

    if audit_btn:
        if audit_carrier_file is None:
            st.error("Silakan unggah citra pembawa yang ingin diaudit.")
        else:
            with st.spinner("Menjalankan kalkulasi matriks statistik dan uji Chi-Square..."):
                c_arr = np.array(Image.open(audit_carrier_file).convert("RGB"))
                cv_arr = np.array(Image.open(audit_cover_file).convert("RGB")) if audit_cover_file else None

                report = run_full_audit(cv_arr, c_arr)

                r_col1, r_col2, r_col3, r_col4 = st.columns(4)
                with r_col1:
                    score = report["stealth_score"]
                    st.metric("Skor Keselamatan Stealth", f"{score}%")
                with r_col2:
                    p_val = report["chi2_p_value"]
                    st.metric("Chi-Square p-value", f"{p_val:.4f}")
                with r_col3:
                    det_conf = report["detection_confidence"] * 100.0
                    st.metric("Confidence Terdeteksi", f"{det_conf:.1f}%")
                with r_col4:
                    badge = "status-badge-secure" if report["is_secure"] else "status-badge-warning"
                    st.markdown(f"<div style='margin-top:16px;'><span class='{badge}'>{report['verdict']}</span></div>", unsafe_allow_html=True)

                if cv_arr is not None:
                    st.markdown("---")
                    st.subheader("Visual Residual Perbesaran 25×")
                    residual = compute_amplified_residual(cv_arr, c_arr, factor=25.0)

                    v_col1, v_col2, v_col3 = st.columns(3)
                    with v_col1:
                        st.image(cv_arr, caption="Original Cover", use_container_width=True)
                    with v_col2:
                        st.image(c_arr, caption="Stego Carrier", use_container_width=True)
                    with v_col3:
                        st.image(residual, caption="Amplified Residual (25x)", use_container_width=True)

                st.markdown("---")
                st.subheader("Entropi Distribusi LSB per Channel")
                st.json(report["lsb_entropy"])
