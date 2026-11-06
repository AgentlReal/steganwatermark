"""
GhostShare Anti-Steganalysis & Forensic Audit Module.

Provides comprehensive forensic evaluation to verify that steganographic carriers
evade detection under statistical attacks (Chi-Square PoV, bit-plane entropy) and
maintain high visual fidelity (PSNR, SSIM, MSE).
"""

from typing import Dict, Any, Tuple, Optional
import numpy as np

from core.steganalysis import chi_square_steganalysis
from core.metrics import calculate_psnr, calculate_ssim, calculate_mse


def calculate_lsb_entropy(image: np.ndarray) -> Dict[str, float]:
    """
    Analyzes the LSB bitplane of each channel to measure bit balance.
    Natural uncompressed images typically range from 0.45 to 0.55 ones.
    AES-encrypted random bits approach exactly 0.50.
    """
    if image.ndim == 2:
        lsb = (image % 2).astype(np.float64)
        ratio_ones = float(np.mean(lsb))
        return {"channel_gray_lsb_ones_ratio": ratio_ones}
    
    results = {}
    channel_names = ["R", "G", "B"] if image.shape[2] >= 3 else [f"C{i}" for i in range(image.shape[2])]
    for i, name in enumerate(channel_names[:3]):
        lsb = (image[:, :, i] % 2).astype(np.float64)
        results[f"channel_{name}_lsb_ones_ratio"] = float(np.mean(lsb))
    return results


def compute_amplified_residual(cover_img: np.ndarray, stego_img: np.ndarray, factor: float = 25.0) -> np.ndarray:
    """
    Computes amplified pixel residual (difference) between cover and stego image
    normalized to uint8 for visual inspection.
    """
    diff = np.abs(stego_img.astype(np.float64) - cover_img.astype(np.float64))
    amplified = np.clip(diff * factor, 0, 255).astype(np.uint8)
    return amplified


def run_full_audit(
    cover_image: Optional[np.ndarray],
    carrier_image: np.ndarray,
) -> Dict[str, Any]:
    """
    Runs full forensic audit on the carrier image.
    If cover_image is provided, calculates relative distortion metrics (PSNR, SSIM, MSE).
    Otherwise, runs blind statistical tests on the carrier.
    
    Returns structured audit results including a 0-100% stealth safety score.
    """
    chi_res = chi_square_steganalysis(carrier_image)
    lsb_info = calculate_lsb_entropy(carrier_image)

    report: Dict[str, Any] = {
        "chi2_stat": chi_res["chi2_stat"],
        "chi2_p_value": chi_res["p_value"],
        "is_detected": chi_res["is_detected"],
        "detection_confidence": chi_res["detection_confidence"],
        "lsb_entropy": lsb_info,
    }

    if cover_image is not None:
        psnr = calculate_psnr(cover_image, carrier_image)
        ssim = calculate_ssim(cover_image, carrier_image)
        mse = calculate_mse(cover_image, carrier_image)
        max_diff = int(np.max(np.abs(carrier_image.astype(np.int32) - cover_image.astype(np.int32))))

        report["psnr_db"] = psnr
        report["ssim"] = ssim
        report["mse"] = mse
        report["max_pixel_delta"] = max_diff

        # Calculate composite Stealth Score (0 - 100%)
        # Base on PSNR (target >= 45 dB) and chi-square evasion
        psnr_score = min(100.0, max(0.0, (psnr - 35.0) / 25.0 * 100.0))
        ssim_score = min(100.0, max(0.0, (ssim - 0.98) / 0.02 * 100.0))
        chi_score = (1.0 - chi_res["detection_confidence"]) * 100.0

        stealth_score = round(0.4 * psnr_score + 0.3 * ssim_score + 0.3 * chi_score, 1)
    else:
        # Blind audit without cover reference
        chi_score = (1.0 - chi_res["detection_confidence"]) * 100.0
        stealth_score = round(chi_score, 1)

    report["stealth_score"] = stealth_score
    report["is_secure"] = bool(stealth_score >= 80.0 and not chi_res["is_detected"])
    report["verdict"] = "CLEAN / STEALTH SECURE" if report["is_secure"] else "SUSPICIOUS / ELEVATED RISK"

    return report
