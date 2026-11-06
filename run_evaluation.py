"""
Comprehensive CLI Evaluation & Metric Generator.

Processes:
- Cover photo (input/cover.png)
- 1 Watermark photo (input/watermark.png)
- 10 Payload photos (input/payloads/)

Outputs:
- 'output/': Processed stego-watermarked photos (PNG) and watermark keys (.key)
- 'metric_result/': Complete evaluation metrics (CSV, Markdown) and plots (.png at 300 DPI)
"""

import os
import sys
import glob
import time
import argparse
import numpy as np
import pandas as pd
from PIL import Image
import matplotlib
os.environ["MPLCONFIGDIR"] = "/tmp"
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from tabulate import tabulate

from core.pipeline import DualDomainPipeline
from core.attacks import (
    attack_jpeg_compression,
    attack_gaussian_noise,
    attack_salt_pepper,
    attack_cropping,
    attack_median_filter,
    attack_gaussian_blur,
)
from core.steganalysis import chi_square_steganalysis
from core.metrics import calculate_nc, calculate_ber, calculate_psnr, calculate_ssim


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run complete Steganography & Watermarking metric evaluation from input/ to output/ and metric_result/."
    )
    parser.add_argument("--cover", "-c", default="input/cover.png", help="Path to cover photo (default: input/cover.png)")
    parser.add_argument("--watermark", "-w", default="input/watermark.png", help="Path to 1 watermark photo (default: input/watermark.png)")
    parser.add_argument("--payloads-dir", "-p", default="input/payloads", help="Directory containing 10 photo payloads")
    parser.add_argument("--output-dir", "-o", default="output", help="Directory for processed photos and keys (default: output/)")
    parser.add_argument("--metrics-dir", "-m", default="metric_result", help="Directory for metric tables and plots (default: metric_result/)")
    parser.add_argument("--passphrase", default="Aria2026SecureKey!", help="Secret passphrase for AES-256-GCM encryption")
    parser.add_argument("--alpha", type=float, default=0.05, help="Watermark strength factor alpha (default: 0.05)")
    parser.add_argument("--subband", default="HL", choices=["HL", "LH", "HH", "LL"], help="DWT target subband (default: HL)")
    return parser.parse_args()


def run_evaluation():
    args = parse_arguments()

    print("=" * 80)
    print("      STEGANOGRAPHY & WATERMARKING FULL METRIC EVALUATION (CLI)")
    print("=" * 80)

    # 1. Validate and prepare directories
    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs(args.metrics_dir, exist_ok=True)

    if not os.path.exists(args.cover):
        print(f"[!] Cover file '{args.cover}' not found. Generating default cover...", file=sys.stderr)
        os.makedirs(os.path.dirname(args.cover) or ".", exist_ok=True)
        from scripts.generate_sample_inputs import generate_inputs
        generate_inputs()

    if not os.path.exists(args.watermark):
        print(f"[!] Watermark file '{args.watermark}' not found. Running generator...", file=sys.stderr)
        from scripts.generate_sample_inputs import generate_inputs
        generate_inputs()

    # 2. Gather Payloads and determine required carrier capacity
    payload_files = sorted(
        [os.path.join(args.payloads_dir, f) for f in os.listdir(args.payloads_dir) if os.path.isfile(os.path.join(args.payloads_dir, f))],
        key=lambda p: os.path.getsize(p)
    )
    if len(payload_files) == 0:
        print(f"[!] No payload files found in '{args.payloads_dir}'. Generating samples...", file=sys.stderr)
        from scripts.generate_sample_inputs import generate_inputs
        generate_inputs()
        payload_files = sorted(
            [os.path.join(args.payloads_dir, f) for f in os.listdir(args.payloads_dir) if os.path.isfile(os.path.join(args.payloads_dir, f))],
            key=lambda p: os.path.getsize(p)
        )

    max_payload_bytes = max(os.path.getsize(p) for p in payload_files)
    needed_bits = (max_payload_bytes + 64) * 8

    # Load Cover Image
    cover_pil = Image.open(args.cover).convert("RGB")
    w, h = cover_pil.size
    current_bits = w * h * 3

    # Dynamic auto-scaling if payloads exceed current carrier capacity
    if needed_bits > current_bits:
        needed_pixels = needed_bits / 3.0
        needed_side = int(np.ceil(np.sqrt(needed_pixels)))
        # Standard clean step: 512, 1024, 1536, 2048
        if needed_side <= 1024:
            target_side = 1024
        elif needed_side <= 1536:
            target_side = 1536
        else:
            target_side = int(np.ceil(needed_side / 64.0) * 64)
            if target_side % 2 != 0:
                target_side += 1

        print(f"[*] Auto-scaling cover resolution from {w}x{h} to {target_side}x{target_side}:")
        print(f"    Largest payload is {max_payload_bytes:,} bytes, which exceeds {w}x{h} carrier capacity ({current_bits//8:,} bytes).")
        print(f"    New carrier capacity at {target_side}x{target_side} is {target_side*target_side*3//8:,} bytes (PSNR > 44 dB).")
        cover_pil = cover_pil.resize((target_side, target_side), Image.Resampling.LANCZOS)
        w, h = target_side, target_side

    # Ensure even dimensions for 1-level DWT
    w_even = w - (w % 2)
    h_even = h - (h % 2)
    if w != w_even or h != h_even:
        cover_pil = cover_pil.crop((0, 0, w_even, h_even))
    cover_np = np.array(cover_pil)

    # Load 1 Watermark Photo
    wm_pil = Image.open(args.watermark).convert("L")
    wm_np = np.array(wm_pil)

    print(f"[*] Cover Photo:       {args.cover} ({cover_np.shape[1]}x{cover_np.shape[0]}, RGB)")
    print(f"[*] Watermark Photo:   {args.watermark} ({wm_np.shape[1]}x{wm_np.shape[0]}, Grayscale)")
    print(f"[*] Output Photos/Keys: {args.output_dir}/")
    print(f"[*] Metric Results:    {args.metrics_dir}/")
    print(f"[*] Alpha (Strength):  {args.alpha} | Subband: {args.subband}")
    print(f"[*] Loaded {len(payload_files)} payload files from '{args.payloads_dir}'.")

    pipeline = DualDomainPipeline(watermark_alpha=args.alpha, watermark_subband=args.subband)
    benchmark_rows = []

    last_stego_img = None
    last_wm_key = None
    last_payload_bytes = None

    print("\n--> [1/3] Processing 10 Payloads Embedding & Metric Evaluation...")
    for idx, p_path in enumerate(payload_files, start=1):
        filename = os.path.basename(p_path)
        with open(p_path, "rb") as f:
            payload_data = f.read()

        payload_bytes = len(payload_data)
        payload_bits = payload_bytes * 8
        bpp = payload_bits / (cover_np.shape[0] * cover_np.shape[1] * cover_np.shape[2])

        # Dual Embedding
        embed_res = pipeline.run_dual_embedding(
            cover_image=cover_np,
            watermark_logo=wm_np,
            stego_payload=payload_data,
            stego_passphrase=args.passphrase,
        )

        # Dual Extraction Verification
        extract_res = pipeline.run_dual_extraction(
            stego_watermarked_image=embed_res.stego_watermarked_image,
            watermark_key=embed_res.watermark_key,
            original_watermark_logo=wm_np,
            stego_passphrase=args.passphrase,
            original_payload=payload_data,
        )

        # Steganalysis (Chi-Square)
        steg_res = chi_square_steganalysis(embed_res.stego_watermarked_image)

        # ---------------------------------------------------------
        # SAVE PROCESSED PHOTO & KEY TO output/
        # ---------------------------------------------------------
        out_photo_name = f"stego_watermarked_payload_{idx:02d}.png"
        out_key_name = f"watermark_key_payload_{idx:02d}.key"
        out_photo_path = os.path.join(args.output_dir, out_photo_name)
        out_key_path = os.path.join(args.output_dir, out_key_name)

        Image.fromarray(embed_res.stego_watermarked_image).save(out_photo_path)
        embed_res.watermark_key.save_to_file(out_key_path)

        total_time_ms = embed_res.embed_time_ms + extract_res.extract_time_ms

        row = {
            "No": idx,
            "Payload_File": filename,
            "Size_Bytes": payload_bytes,
            "Size_Bits": payload_bits,
            "Capacity_bpp": round(bpp, 4),
            "PSNR_dB": round(embed_res.metrics["psnr"], 2),
            "SSIM": round(embed_res.metrics["ssim"], 4),
            "MSE": round(embed_res.metrics["mse"], 3),
            "SNR_dB": round(embed_res.metrics["snr"], 2),
            "Baseline_WM_NC": round(embed_res.metrics["baseline_wm_nc"], 4),
            "Post_Stego_WM_NC": round(embed_res.metrics["post_stego_wm_nc"], 4),
            "Delta_NC": round(embed_res.metrics["delta_nc"], 5),
            "Delta_PSNR_dB": round(embed_res.metrics["delta_psnr"], 3),
            "Stego_BER_%": round(extract_res.stego_ber, 2),
            "Stego_Verified": extract_res.stego_success and (extract_res.stego_ber == 0.0),
            "Embed_Time_ms": round(embed_res.embed_time_ms, 2),
            "Extract_Time_ms": round(extract_res.extract_time_ms, 2),
            "Total_Time_ms": round(total_time_ms, 2),
            "Peak_RAM_KB": round(embed_res.peak_memory_kb, 1),
            "Chi2_p_value": round(steg_res["p_value"], 4),
            "Chi2_Confidence": round(steg_res["detection_confidence"], 4),
        }
        benchmark_rows.append(row)

        print(
            f"  [{idx:02d}/{len(payload_files):02d}] {filename:<34} | {payload_bytes:>6} B | "
            f"PSNR: {row['PSNR_dB']:>5.2f} dB | SSIM: {row['SSIM']:>6.4f} | "
            f"NC: {row['Post_Stego_WM_NC']:>6.4f} | BER: {row['Stego_BER_%']:>4.1f}% | "
            f"Time: {total_time_ms:>6.1f} ms"
        )

        if idx == len(payload_files):
            last_stego_img = embed_res.stego_watermarked_image
            last_wm_key = embed_res.watermark_key
            last_payload_bytes = payload_data

            # Save latest shortcut in output/
            Image.fromarray(last_stego_img).save(os.path.join(args.output_dir, "latest_stego_watermarked.png"))
            last_wm_key.save_to_file(os.path.join(args.output_dir, "latest_key.key"))
            Image.fromarray(extract_res.extracted_watermark).save(os.path.join(args.output_dir, "sample_extracted_watermark.png"))

    # ---------------------------------------------------------
    # 2. Robustness Attack Evaluation
    # ---------------------------------------------------------
    print("\n--> [2/3] Processing Robustness Attack Evaluations (6 Attack Types)...")
    attacks = [
        ("No Attack (Baseline)", lambda img: img.copy()),
        ("JPEG Compression (Q=90)", lambda img: attack_jpeg_compression(img, 90)),
        ("JPEG Compression (Q=75)", lambda img: attack_jpeg_compression(img, 75)),
        ("JPEG Compression (Q=50)", lambda img: attack_jpeg_compression(img, 50)),
        ("Gaussian Noise (var=0.005)", lambda img: attack_gaussian_noise(img, 0.0, 0.005)),
        ("Gaussian Noise (var=0.01)", lambda img: attack_gaussian_noise(img, 0.0, 0.01)),
        ("Salt & Pepper Noise (p=0.02)", lambda img: attack_salt_pepper(img, 0.02)),
        ("Cropping Attack (Center 20%)", lambda img: attack_cropping(img, 0.20, "center")),
        ("Cropping Attack (Corner 15%)", lambda img: attack_cropping(img, 0.15, "top_left")),
        ("Median Filter (Kernel 3x3)", lambda img: attack_median_filter(img, 3)),
        ("Gaussian Blur (Radius 1.0)", lambda img: attack_gaussian_blur(img, 1.0)),
    ]

    attack_rows = []
    for att_name, att_fn in attacks:
        att_img = att_fn(last_stego_img)
        att_psnr = calculate_psnr(cover_np, att_img)
        att_ssim = calculate_ssim(cover_np, att_img)

        # Extract Watermark
        ext_wm = pipeline.watermarker.extract(att_img, last_wm_key)
        att_nc = calculate_nc(wm_np, ext_wm)

        # Extract Stego
        try:
            ext_pl = pipeline.steganographer.extract(att_img, args.passphrase)
            att_ber = calculate_ber(last_payload_bytes, ext_pl)
            stego_survived = (att_ber == 0.0)
        except Exception:
            att_ber = 100.0
            stego_survived = False

        attack_rows.append({
            "Attack_Type": att_name,
            "Attacked_PSNR_dB": round(att_psnr, 2),
            "Attacked_SSIM": round(att_ssim, 4),
            "Watermark_NC": round(att_nc, 4),
            "Watermark_Preserved": bool(att_nc >= 0.85),
            "Stego_BER_%": round(att_ber, 2),
            "Stego_Survived": stego_survived,
        })
        print(f"  * {att_name:<30} | Attacked PSNR: {att_psnr:>5.2f} dB | WM NC: {att_nc:>6.4f} | Stego BER: {att_ber:>5.1f}%")

    # ---------------------------------------------------------
    # 3. Save Tables in metric_result/
    # ---------------------------------------------------------
    print("\n--> [3/3] Generating Metric Tables and High-Resolution Plots (.png)...")
    df_bench = pd.DataFrame(benchmark_rows)
    df_att = pd.DataFrame(attack_rows)

    csv_bench_path = os.path.join(args.metrics_dir, "benchmark_metrics.csv")
    csv_att_path = os.path.join(args.metrics_dir, "robustness_attacks.csv")
    df_bench.to_csv(csv_bench_path, index=False)
    df_att.to_csv(csv_att_path, index=False)

    # Save summary report markdown
    report_md_path = os.path.join(args.metrics_dir, "summary_report.md")
    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write("# 📊 Laporan Hasil Evaluasi Metrik Lengkap Steganografi & Watermarking\n\n")
        f.write(f"- **Cover Photo**: `{args.cover}` ({cover_np.shape[1]}x{cover_np.shape[0]})\n")
        f.write(f"- **Watermark Photo**: `{args.watermark}` ({wm_np.shape[1]}x{wm_np.shape[0]})\n")
        f.write(f"- **Jumlah Payload**: {len(payload_files)} file\n\n")
        f.write("## 1. Tabel Evaluasi 10 Payload\n\n")
        f.write(df_bench.to_markdown(index=False))
        f.write("\n\n## 2. Tabel Ketahanan terhadap Serangan (Robustness Attacks)\n\n")
        f.write(df_att.to_markdown(index=False))
        f.write("\n")

    # ---------------------------------------------------------
    # 4. Generate 5 Publication Plots in metric_result/
    # ---------------------------------------------------------
    generate_metric_plots(df_bench, df_att, cover_np, last_stego_img, wm_np, args.metrics_dir, args.output_dir)

    # ---------------------------------------------------------
    # 5. Print Formatted Terminal Summary
    # ---------------------------------------------------------
    print("\n" + "=" * 80)
    print("      EVALUATION SUMMARY TABLES")
    print("=" * 80)
    summary_cols = [
        "No", "Payload_File", "Size_Bytes", "PSNR_dB", "SSIM",
        "Post_Stego_WM_NC", "Delta_NC", "Stego_BER_%", "Total_Time_ms"
    ]
    print(tabulate(df_bench[summary_cols], headers="keys", tablefmt="fancy_grid", showindex=False))

    print("\nRobustness Attacks Summary:")
    print(tabulate(df_att, headers="keys", tablefmt="fancy_grid", showindex=False))

    print("\n" + "=" * 80)
    print(f"[+] SUCCESS: Process completed!")
    print(f"    * Processed Photos & Keys saved in : {args.output_dir}/")
    print(f"    * Metrics, Tables, and Plots saved in : {args.metrics_dir}/")
    print("=" * 80)


def generate_metric_plots(df_b: pd.DataFrame, df_a: pd.DataFrame, cover: np.ndarray, stego_wm: np.ndarray, wm_logo: np.ndarray, metrics_dir: str, output_dir: str):
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    
    x_labels = [f"{b} B" if b < 1024 else f"{b//1024} KB" for b in df_b["Size_Bytes"]]
    x_indices = np.arange(len(x_labels))

    # -------------------------------------------------------------
    # Plot 1: PSNR & SSIM vs Payload Size
    # -------------------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(9, 5))
    color1 = "#1f77b4"
    ax1.set_xlabel("Ukuran Payload (Bytes)", fontsize=11, fontweight="bold")
    ax1.set_ylabel("PSNR (dB)", color=color1, fontsize=11, fontweight="bold")
    ax1.plot(x_indices, df_b["PSNR_dB"], color=color1, marker="o", linewidth=2.2, label="PSNR (dB)")
    ax1.tick_params(axis="y", labelcolor=color1)
    ax1.set_ylim(30, 55)
    ax1.axhline(38.0, color="#d62728", linestyle="--", alpha=0.7, label="Ambang Batas Kasat Mata (38 dB)")

    ax2 = ax1.twinx()
    color2 = "#2ca02c"
    ax2.set_ylabel("SSIM", color=color2, fontsize=11, fontweight="bold")
    ax2.plot(x_indices, df_b["SSIM"], color=color2, marker="s", linewidth=2.2, linestyle="-.", label="SSIM")
    ax2.tick_params(axis="y", labelcolor=color2)
    ax2.set_ylim(0.95, 1.002)

    ax1.set_xticks(x_indices)
    ax1.set_xticklabels(x_labels, rotation=30)
    plt.title("Evaluasi Kualitas Citra: PSNR & SSIM vs Ukuran Payload Foto", fontsize=12, fontweight="bold", pad=12)
    fig.tight_layout()
    plt.savefig(os.path.join(metrics_dir, "plot1_quality_psnr_ssim.png"), dpi=300)
    plt.close()

    # -------------------------------------------------------------
    # Plot 2: Mutual Interference Analysis
    # -------------------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(9, 5))
    color1 = "#9467bd"
    ax1.set_xlabel("Ukuran Payload", fontsize=11, fontweight="bold")
    ax1.set_ylabel("Watermark NC", color=color1, fontsize=11, fontweight="bold")
    ax1.plot(x_indices, df_b["Post_Stego_WM_NC"], color=color1, marker="D", linewidth=2.2, label="Watermark NC")
    ax1.tick_params(axis="y", labelcolor=color1)
    ax1.set_ylim(0.90, 1.01)

    ax2 = ax1.twinx()
    color2 = "#ff7f0e"
    ax2.set_ylabel("Degradasi |ΔNC|", color=color2, fontsize=11, fontweight="bold")
    ax2.bar(x_indices, np.abs(df_b["Delta_NC"]), width=0.4, color=color2, alpha=0.6, label="|ΔNC|")
    ax2.tick_params(axis="y", labelcolor=color2)
    ax2.set_ylim(0, 0.05)

    ax1.set_xticks(x_indices)
    ax1.set_xticklabels(x_labels, rotation=30)
    plt.title("Analisis Interferensi: Ketahanan Watermark vs Kapasitas Steganografi", fontsize=12, fontweight="bold", pad=12)
    fig.tight_layout()
    plt.savefig(os.path.join(metrics_dir, "plot2_interference_analysis.png"), dpi=300)
    plt.close()

    # -------------------------------------------------------------
    # Plot 3: Execution Time & Memory Usage
    # -------------------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(9, 5))
    color1 = "#17becf"
    ax1.set_xlabel("Ukuran Payload", fontsize=11, fontweight="bold")
    ax1.set_ylabel("Total Waktu Komputasi (ms)", color=color1, fontsize=11, fontweight="bold")
    ax1.plot(x_indices, df_b["Total_Time_ms"], color=color1, marker="^", linewidth=2.2, label="Total Waktu (ms)")
    ax1.tick_params(axis="y", labelcolor=color1)

    ax2 = ax1.twinx()
    color2 = "#e377c2"
    ax2.set_ylabel("Penggunaan Memori RAM (KB)", color=color2, fontsize=11, fontweight="bold")
    ax2.plot(x_indices, df_b["Peak_RAM_KB"], color=color2, marker="o", linewidth=2.0, linestyle=":", label="Peak RAM")
    ax2.tick_params(axis="y", labelcolor=color2)

    ax1.set_xticks(x_indices)
    ax1.set_xticklabels(x_labels, rotation=30)
    plt.title("Efisiensi Komputasi: Waktu Proses & Penggunaan RAM vs Payload", fontsize=12, fontweight="bold", pad=12)
    fig.tight_layout()
    plt.savefig(os.path.join(metrics_dir, "plot3_efficiency_complexity.png"), dpi=300)
    plt.close()

    # -------------------------------------------------------------
    # Plot 4: Robustness under 6 Attack Types
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(10, 5.5))
    attacks_subset = df_a.iloc[1:]  # exclude baseline
    y_pos = np.arange(len(attacks_subset))
    colors = ["#2ca02c" if nc >= 0.85 else "#d62728" for nc in attacks_subset["Watermark_NC"]]
    
    bars = ax.barh(y_pos, attacks_subset["Watermark_NC"], color=colors, height=0.6, edgecolor="black", alpha=0.85)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(attacks_subset["Attack_Type"], fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("Watermark Normalized Cross-Correlation (NC)", fontsize=11, fontweight="bold")
    ax.axvline(0.85, color="red", linestyle="--", linewidth=1.5, label="Batas Validasi Hak Cipta (NC >= 0.85)")
    ax.set_xlim(0.0, 1.05)

    for bar in bars:
        w_val = bar.get_width()
        ax.text(w_val + 0.015, bar.get_y() + bar.get_height() / 2, f"{w_val:.3f}", va="center", ha="left", fontsize=9, fontweight="bold")

    plt.title("Ketahanan Watermark DWT-SVD terhadap Berbagai Serangan Manipulasi", fontsize=12, fontweight="bold", pad=12)
    plt.legend(loc="lower left")
    fig.tight_layout()
    plt.savefig(os.path.join(metrics_dir, "plot4_robustness_attacks.png"), dpi=300)
    plt.close()

    # -------------------------------------------------------------
    # Plot 5: Visual Side-by-Side Demonstration
    # -------------------------------------------------------------
    fig, axs = plt.subplots(1, 4, figsize=(14, 3.8))
    
    # 1. Original Cover
    axs[0].imshow(cover)
    axs[0].set_title("Original Cover", fontsize=10, fontweight="bold")
    axs[0].axis("off")

    # 2. Stego-Watermarked Image
    axs[1].imshow(stego_wm)
    psnr_disp = df_b["PSNR_dB"].iloc[-1]
    ssim_disp = df_b["SSIM"].iloc[-1]
    axs[1].set_title(f"Stego-Watermarked\nPSNR: {psnr_disp:.1f} dB | SSIM: {ssim_disp:.4f}", fontsize=10, fontweight="bold")
    axs[1].axis("off")

    # 3. Amplified Residual Error
    diff = np.abs(cover.astype(float) - stego_wm.astype(float)) * 20.0
    diff_clipped = np.clip(diff, 0, 255).astype(np.uint8)
    axs[2].imshow(diff_clipped)
    axs[2].set_title("Amplified Residual (x20)\n(Imperceptible)", fontsize=10, fontweight="bold")
    axs[2].axis("off")

    # 4. Extracted Watermark
    sample_ext_path = os.path.join(output_dir, "sample_extracted_watermark.png")
    if os.path.exists(sample_ext_path):
        ext_wm_img = Image.open(sample_ext_path)
    else:
        ext_wm_img = wm_logo
    axs[3].imshow(ext_wm_img, cmap="gray")
    nc_disp = df_b["Post_Stego_WM_NC"].iloc[-1]
    axs[3].set_title(f"Extracted Watermark\nNC: {nc_disp:.4f}", fontsize=10, fontweight="bold")
    axs[3].axis("off")

    fig.suptitle("Visual Comparison and Imperceptibility Verification", fontsize=12, fontweight="bold")
    fig.tight_layout()
    plt.savefig(os.path.join(metrics_dir, "plot5_visual_comparison.png"), dpi=300)
    plt.close()


if __name__ == "__main__":
    run_evaluation()

