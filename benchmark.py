"""
Comprehensive Academic Benchmark Script for Steganography + Watermarking.

Evaluates:
1. 10 progressive payloads (64 B to 32 KB).
2. Imperceptibility metrics (PSNR, SSIM, MSE, SNR).
3. Fidelity metrics (Watermark NC, Stego BER).
4. Mutual Interference (Delta NC, Delta PSNR).
5. Computational Complexity (Embedding time, Extraction time, Peak RAM).
6. Robustness against 6 realistic attacks (JPEG, Noise, Crop, Filter, Blur).
7. Statistical Security (Chi-Square Steganalysis).
8. Exports CSV summary, markdown tables, and publication-ready matplotlib figures.
"""

import os
import sys
import glob
import time
import json
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


def run_benchmark(
    cover_path: str = "data/covers/lena.png",
    watermark_path: str = "data/watermarks/copyright_64.png",
    passphrase: str = "Aria2026SecureKey!",
    output_dir: str = "output",
):
    print("=" * 80)
    print("      INTEGRATED STEGANOGRAPHY + WATERMARKING BENCHMARK SUITE")
    print("=" * 80)

    os.makedirs(os.path.join(output_dir, "images"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "reports"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "plots"), exist_ok=True)

    # 1. Load cover and watermark images
    cover_pil = Image.open(cover_path).convert("RGB")
    cover_img = np.array(cover_pil)
    wm_pil = Image.open(watermark_path).convert("L")
    wm_logo = np.array(wm_pil)

    print(f"[*] Cover Image:     {cover_path} ({cover_img.shape[1]}x{cover_img.shape[0]}, RGB)")
    print(f"[*] Watermark Logo:  {watermark_path} ({wm_logo.shape[1]}x{wm_logo.shape[0]}, Grayscale)")
    print(f"[*] Secret Passphrase: {passphrase}")

    # 2. Gather 10 payloads
    payload_files = sorted(glob.glob("data/payloads/*"))
    if len(payload_files) < 10:
        print(f"[!] Warning: Found {len(payload_files)} payloads. Expected at least 10.")
    print(f"[*] Found {len(payload_files)} test payloads.")

    pipeline = DualDomainPipeline(watermark_alpha=0.05, watermark_subband="HL")

    benchmark_rows = []
    last_stego_wm_img = None
    last_wm_key = None
    last_payload = None

    print("\n--> Running 10 Payload Evaluations...")
    for idx, p_path in enumerate(payload_files, start=1):
        filename = os.path.basename(p_path)
        with open(p_path, "rb") as f:
            payload_data = f.read()

        payload_bytes = len(payload_data)
        payload_bits = payload_bytes * 8
        bpp = payload_bits / (cover_img.shape[0] * cover_img.shape[1])

        # Dual Embedding
        embed_res = pipeline.run_dual_embedding(
            cover_image=cover_img,
            watermark_logo=wm_logo,
            stego_payload=payload_data,
            stego_passphrase=passphrase,
        )

        # Dual Extraction
        extract_res = pipeline.run_dual_extraction(
            stego_watermarked_image=embed_res.stego_watermarked_image,
            watermark_key=embed_res.watermark_key,
            original_watermark_logo=wm_logo,
            stego_passphrase=passphrase,
            original_payload=payload_data,
        )

        # Steganalysis (Chi-Square)
        steg_res = chi_square_steganalysis(embed_res.stego_watermarked_image)

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
            "Peak_RAM_KB": round(embed_res.peak_memory_kb, 1),
            "Chi2_p_value": round(steg_res["p_value"], 4),
            "Chi2_Confidence": round(steg_res["detection_confidence"], 4),
        }
        benchmark_rows.append(row)

        print(
            f"  [{idx:02d}/10] {filename:<20} | {payload_bytes:>5} B | "
            f"PSNR: {row['PSNR_dB']:>5.2f} dB | SSIM: {row['SSIM']:>6.4f} | "
            f"NC: {row['Post_Stego_WM_NC']:>6.4f} | BER: {row['Stego_BER_%']:>4.1f}% | "
            f"Time: {row['Embed_Time_ms'] + row['Extract_Time_ms']:>6.1f} ms"
        )

        # Save the largest payload result for robustness testing and visual demonstration
        if idx == len(payload_files):
            last_stego_wm_img = embed_res.stego_watermarked_image
            last_wm_key = embed_res.watermark_key
            last_payload = payload_data
            
            # Save visual artifacts and key
            Image.fromarray(embed_res.watermarked_image).save(os.path.join(output_dir, "images", "watermarked_only.png"))
            Image.fromarray(embed_res.stego_watermarked_image).save(os.path.join(output_dir, "images", "stego_watermarked.png"))
            Image.fromarray(extract_res.extracted_watermark).save(os.path.join(output_dir, "images", "extracted_watermark.png"))
            last_wm_key.save_to_file(os.path.join(output_dir, "reports", "latest_key.key"))

    df_benchmark = pd.DataFrame(benchmark_rows)
    csv_benchmark_path = os.path.join(output_dir, "reports", "benchmark_10_payloads.csv")
    df_benchmark.to_csv(csv_benchmark_path, index=False)

    print("\n--> Benchmark Table Summary:")
    summary_cols = [
        "No", "Payload_File", "Size_Bytes", "PSNR_dB", "SSIM",
        "Post_Stego_WM_NC", "Delta_NC", "Stego_BER_%", "Embed_Time_ms", "Chi2_p_value"
    ]
    print(tabulate(df_benchmark[summary_cols], headers="keys", tablefmt="fancy_grid", showindex=False))

    # 3. Robustness Attack Evaluation
    print("\n--> Running Robustness Evaluation under 6 Attack Types...")
    attacks = [
        ("No Attack (Baseline)", lambda img: img.copy()),
        ("JPEG (Q=90)", lambda img: attack_jpeg_compression(img, 90)),
        ("JPEG (Q=75)", lambda img: attack_jpeg_compression(img, 75)),
        ("JPEG (Q=50)", lambda img: attack_jpeg_compression(img, 50)),
        ("Gaussian Noise (var=0.005)", lambda img: attack_gaussian_noise(img, 0.0, 0.005)),
        ("Gaussian Noise (var=0.01)", lambda img: attack_gaussian_noise(img, 0.0, 0.01)),
        ("Salt & Pepper (p=0.02)", lambda img: attack_salt_pepper(img, 0.02)),
        ("Cropping (Center 20%)", lambda img: attack_cropping(img, 0.20, "center")),
        ("Cropping (Top-Left 15%)", lambda img: attack_cropping(img, 0.15, "top_left")),
        ("Median Filter (3x3)", lambda img: attack_median_filter(img, 3)),
        ("Gaussian Blur (r=1.0)", lambda img: attack_gaussian_blur(img, 1.0)),
    ]

    attack_rows = []
    for att_name, att_fn in attacks:
        attacked_img = att_fn(last_stego_wm_img)
        psnr_att = calculate_psnr(cover_img, attacked_img)
        ssim_att = calculate_ssim(cover_img, attacked_img)

        # Extract watermark
        extracted_wm = pipeline.watermarker.extract(attacked_img, last_wm_key)
        nc_att = calculate_nc(wm_logo, extracted_wm)

        # Extract stego
        try:
            extracted_pl = pipeline.steganographer.extract(attacked_img, passphrase)
            ber_att = calculate_ber(last_payload, extracted_pl)
            stego_survived = (ber_att == 0.0)
        except Exception:
            ber_att = 100.0
            stego_survived = False

        attack_rows.append({
            "Attack_Type": att_name,
            "Attacked_PSNR_dB": round(psnr_att, 2),
            "Attacked_SSIM": round(ssim_att, 4),
            "Watermark_NC": round(nc_att, 4),
            "Watermark_Preserved": bool(nc_att >= 0.85),
            "Stego_BER_%": round(ber_att, 2),
            "Stego_Survived": stego_survived,
        })
        print(f"  * {att_name:<28} | Attacked PSNR: {psnr_att:>5.2f} dB | WM NC: {nc_att:>6.4f} | Stego BER: {ber_att:>5.1f}%")

    df_attacks = pd.DataFrame(attack_rows)
    csv_attacks_path = os.path.join(output_dir, "reports", "robustness_attacks.csv")
    df_attacks.to_csv(csv_attacks_path, index=False)

    print("\n--> Robustness Attack Table:")
    print(tabulate(df_attacks, headers="keys", tablefmt="fancy_grid", showindex=False))

    # 4. Generate Professional Visualizations
    print("\n--> Generating Publication-Quality Plots...")
    generate_plots(df_benchmark, df_attacks, cover_img, last_stego_wm_img, wm_logo, output_dir)

    print(f"\n[+] Benchmark complete! Results saved in '{output_dir}/'")


def generate_plots(df_b: pd.DataFrame, df_a: pd.DataFrame, cover: np.ndarray, stego_wm: np.ndarray, wm_logo: np.ndarray, output_dir: str):
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    
    # -------------------------------------------------------------
    # Plot 1: PSNR & SSIM vs Payload Size
    # -------------------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(9, 5))
    x_labels = [f"{b} B" if b < 1024 else f"{b//1024} KB" for b in df_b["Size_Bytes"]]
    x_indices = np.arange(len(x_labels))

    color1 = "#1f77b4"
    ax1.set_xlabel("Payload Size (Bytes)", fontsize=11, fontweight="bold")
    ax1.set_ylabel("PSNR (dB)", color=color1, fontsize=11, fontweight="bold")
    line1 = ax1.plot(x_indices, df_b["PSNR_dB"], color=color1, marker="o", linewidth=2.2, label="PSNR (dB)")
    ax1.tick_params(axis="y", labelcolor=color1)
    ax1.set_ylim(30, 55)
    ax1.axhline(38.0, color="#d62728", linestyle="--", alpha=0.7, label="Imperceptibility Threshold (38 dB)")

    ax2 = ax1.twinx()
    color2 = "#2ca02c"
    ax2.set_ylabel("SSIM", color=color2, fontsize=11, fontweight="bold")
    line2 = ax2.plot(x_indices, df_b["SSIM"], color=color2, marker="s", linewidth=2.2, linestyle="-.", label="SSIM")
    ax2.tick_params(axis="y", labelcolor=color2)
    ax2.set_ylim(0.95, 1.002)

    ax1.set_xticks(x_indices)
    ax1.set_xticklabels(x_labels, rotation=30)
    plt.title("Image Quality Evaluation: PSNR & SSIM vs Steganography Payload Size", fontsize=12, fontweight="bold", pad=12)
    fig.tight_layout()
    plt.savefig(os.path.join(output_dir, "plots", "plot1_quality_vs_payload.png"), dpi=300)
    plt.close()

    # -------------------------------------------------------------
    # Plot 2: Mutual Interference (NC & Delta NC vs Payload)
    # -------------------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(9, 5))
    color1 = "#9467bd"
    ax1.set_xlabel("Payload Size", fontsize=11, fontweight="bold")
    ax1.set_ylabel("Watermark NC", color=color1, fontsize=11, fontweight="bold")
    ax1.plot(x_indices, df_b["Post_Stego_WM_NC"], color=color1, marker="D", linewidth=2.2, label="Watermark NC")
    ax1.tick_params(axis="y", labelcolor=color1)
    ax1.set_ylim(0.90, 1.01)

    ax2 = ax1.twinx()
    color2 = "#ff7f0e"
    ax2.set_ylabel("Interference |ΔNC|", color=color2, fontsize=11, fontweight="bold")
    ax2.bar(x_indices, np.abs(df_b["Delta_NC"]), width=0.4, color=color2, alpha=0.6, label="|ΔNC| Degradation")
    ax2.tick_params(axis="y", labelcolor=color2)
    ax2.set_ylim(0, 0.05)

    ax1.set_xticks(x_indices)
    ax1.set_xticklabels(x_labels, rotation=30)
    plt.title("Interference Analysis: Watermark Fidelity vs Steganography Embedding Size", fontsize=12, fontweight="bold", pad=12)
    fig.tight_layout()
    plt.savefig(os.path.join(output_dir, "plots", "plot2_interference_analysis.png"), dpi=300)
    plt.close()

    # -------------------------------------------------------------
    # Plot 3: Execution Time & Memory Usage
    # -------------------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(9, 5))
    total_time = df_b["Embed_Time_ms"] + df_b["Extract_Time_ms"]
    color1 = "#17becf"
    ax1.set_xlabel("Payload Size", fontsize=11, fontweight="bold")
    ax1.set_ylabel("Total Processing Time (ms)", color=color1, fontsize=11, fontweight="bold")
    ax1.plot(x_indices, total_time, color=color1, marker="^", linewidth=2.2, label="Total Time (Embed+Extract)")
    ax1.tick_params(axis="y", labelcolor=color1)

    ax2 = ax1.twinx()
    color2 = "#e377c2"
    ax2.set_ylabel("Peak RAM (KB)", color=color2, fontsize=11, fontweight="bold")
    ax2.plot(x_indices, df_b["Peak_RAM_KB"], color=color2, marker="o", linewidth=2.0, linestyle=":", label="Peak Memory")
    ax2.tick_params(axis="y", labelcolor=color2)

    ax1.set_xticks(x_indices)
    ax1.set_xticklabels(x_labels, rotation=30)
    plt.title("Computational Efficiency: Execution Time & RAM Profile vs Payload", fontsize=12, fontweight="bold", pad=12)
    fig.tight_layout()
    plt.savefig(os.path.join(output_dir, "plots", "plot3_efficiency_complexity.png"), dpi=300)
    plt.close()

    # -------------------------------------------------------------
    # Plot 4: Robustness under 6 Attack Types (Bar chart)
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
    ax.axvline(0.85, color="red", linestyle="--", linewidth=1.5, label="Robustness Criterion (NC >= 0.85)")
    ax.set_xlim(0.0, 1.05)

    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.015, bar.get_y() + bar.get_height() / 2, f"{w:.3f}", va="center", ha="left", fontsize=9, fontweight="bold")

    plt.title("Watermark Robustness Evaluation across Channel Attacks", fontsize=12, fontweight="bold", pad=12)
    plt.legend(loc="lower left")
    fig.tight_layout()
    plt.savefig(os.path.join(output_dir, "plots", "plot4_robustness_attacks.png"), dpi=300)
    plt.close()

    # -------------------------------------------------------------
    # Plot 5: Visual Side-by-Side Demonstration
    # -------------------------------------------------------------
    fig, axs = plt.subplots(1, 4, figsize=(14, 3.8))
    
    # 1. Original Cover
    axs[0].imshow(cover)
    axs[0].set_title("Original Cover (512x512)", fontsize=10, fontweight="bold")
    axs[0].axis("off")

    # 2. Stego-Watermarked Image
    axs[1].imshow(stego_wm)
    psnr_disp = df_b["PSNR_dB"].iloc[-1]
    ssim_disp = df_b["SSIM"].iloc[-1]
    axs[1].set_title(f"Stego-Watermarked\nPSNR: {psnr_disp:.1f} dB | SSIM: {ssim_disp:.4f}", fontsize=10, fontweight="bold")
    axs[1].axis("off")

    # 3. Residual Error (x15 Amplification for Visibility)
    diff = np.abs(cover.astype(float) - stego_wm.astype(float)) * 15.0
    diff_clipped = np.clip(diff, 0, 255).astype(np.uint8)
    axs[2].imshow(diff_clipped)
    axs[2].set_title("Amplified Residual (x15)\n(Imperceptible to Eye)", fontsize=10, fontweight="bold")
    axs[2].axis("off")

    # 4. Extracted Watermark Logo
    ext_wm_img = Image.open(os.path.join(output_dir, "images", "extracted_watermark.png"))
    axs[3].imshow(ext_wm_img, cmap="gray")
    nc_disp = df_b["Post_Stego_WM_NC"].iloc[-1]
    axs[3].set_title(f"Extracted Watermark\nNC: {nc_disp:.4f}", fontsize=10, fontweight="bold")
    axs[3].axis("off")

    fig.suptitle("Visual Comparison and Imperceptibility Verification", fontsize=12, fontweight="bold")
    fig.tight_layout()
    plt.savefig(os.path.join(output_dir, "plots", "plot5_visual_comparison.png"), dpi=300)
    plt.close()


if __name__ == "__main__":
    cover = sys.argv[1] if len(sys.argv) > 1 else "data/covers/lena.png"
    run_benchmark(cover_path=cover)

