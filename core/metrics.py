"""
Evaluation Metrics Module for Steganography and Watermarking.

Implements standard academic benchmarking metrics:
- Image Quality: PSNR, SSIM, MSE, SNR
- Watermark Fidelity: NC (Normalized Cross-Correlation), BCR (Bit Correct Rate)
- Steganography Fidelity: BER (Bit Error Rate), Character Accuracy
- Carrier Capacity: Bits per Pixel (bpp), Payload bytes
- Interference Metrics: Delta PSNR, Delta NC
"""

from typing import Tuple, List, Union, Optional
import numpy as np
from scipy.ndimage import uniform_filter


def calculate_mse(image_a: np.ndarray, image_b: np.ndarray) -> float:
    """Mean Squared Error (MSE) between two images."""
    if image_a.shape != image_b.shape:
        raise ValueError(f"Shape mismatch: {image_a.shape} vs {image_b.shape}")
    diff = image_a.astype(np.float64) - image_b.astype(np.float64)
    return float(np.mean(diff ** 2))


def calculate_psnr(image_orig: np.ndarray, image_dist: np.ndarray, max_val: float = 255.0) -> float:
    """
    Peak Signal-to-Noise Ratio (PSNR) in decibels (dB).
    Higher is better (>38 dB indicates visually indistinguishable).
    Returns infinity (inf) if images are identical.
    """
    mse = calculate_mse(image_orig, image_dist)
    if mse == 0.0:
        return float("inf")
    return float(10.0 * np.log10((max_val ** 2) / mse))


def calculate_snr(image_orig: np.ndarray, image_dist: np.ndarray) -> float:
    """
    Signal-to-Noise Ratio (SNR) in decibels (dB).
    """
    orig_f = image_orig.astype(np.float64)
    dist_f = image_dist.astype(np.float64)
    signal_power = np.sum(orig_f ** 2)
    noise_power = np.sum((orig_f - dist_f) ** 2)
    if noise_power == 0.0:
        return float("inf")
    if signal_power == 0.0:
        return 0.0
    return float(10.0 * np.log10(signal_power / noise_power))


def calculate_ssim(
    image_a: np.ndarray,
    image_b: np.ndarray,
    win_size: int = 7,
    k1: float = 0.01,
    k2: float = 0.03,
    data_range: float = 255.0,
) -> float:
    """
    Structural Similarity Index (SSIM) between two images.
    Returns value in range [-1, 1], with 1.0 being identical.
    Supports 2D (grayscale) and 3D (RGB) images.
    """
    if image_a.shape != image_b.shape:
        raise ValueError(f"Shape mismatch: {image_a.shape} vs {image_b.shape}")

    if image_a.ndim == 3:
        # Calculate per-channel SSIM and average
        channels = [
            calculate_ssim(image_a[:, :, c], image_b[:, :, c], win_size, k1, k2, data_range)
            for c in range(image_a.shape[2])
        ]
        return float(np.mean(channels))

    c1 = (k1 * data_range) ** 2
    c2 = (k2 * data_range) ** 2

    x = image_a.astype(np.float64)
    y = image_b.astype(np.float64)

    # Local means using uniform filter
    mu1 = uniform_filter(x, size=win_size)
    mu2 = uniform_filter(y, size=win_size)

    mu1_sq = mu1 ** 2
    mu2_sq = mu2 ** 2
    mu1_mu2 = mu1 * mu2

    # Local variances and covariance
    sigma1_sq = uniform_filter(x * x, size=win_size) - mu1_sq
    sigma2_sq = uniform_filter(y * y, size=win_size) - mu2_sq
    sigma12 = uniform_filter(x * y, size=win_size) - mu1_mu2

    # SSIM formula
    numerator = (2 * mu1_mu2 + c1) * (2 * sigma12 + c2)
    denominator = (mu1_sq + mu2_sq + c1) * (sigma1_sq + sigma2_sq + c2)
    ssim_map = numerator / denominator

    return float(np.mean(ssim_map))


def calculate_nc(watermark_orig: np.ndarray, watermark_ext: np.ndarray) -> float:
    """
    Normalized Cross-Correlation (NC) between original and extracted watermark.
    Value ranges from -1.0 to 1.0; 1.0 represents perfect correlation.
    """
    w1 = watermark_orig.astype(np.float64).flatten()
    w2 = watermark_ext.astype(np.float64).flatten()

    if len(w1) != len(w2):
        raise ValueError(f"Watermark size mismatch: {len(w1)} vs {len(w2)}")

    norm_w1 = np.linalg.norm(w1)
    norm_w2 = np.linalg.norm(w2)

    if norm_w1 == 0.0 or norm_w2 == 0.0:
        return 1.0 if np.array_equal(w1, w2) else 0.0

    dot_prod = np.dot(w1, w2)
    nc = dot_prod / (norm_w1 * norm_w2)
    return float(np.clip(nc, -1.0, 1.0))


def calculate_ber(bits_orig: Union[List[int], np.ndarray, bytes], bits_ext: Union[List[int], np.ndarray, bytes]) -> float:
    """
    Bit Error Rate (BER) between original and extracted bitstreams in percentage (0.0% to 100.0%).
    0.0% represents error-free extraction.
    """
    if isinstance(bits_orig, bytes):
        b1 = np.unpackbits(np.frombuffer(bits_orig, dtype=np.uint8))
    else:
        b1 = np.asarray(bits_orig, dtype=np.uint8)

    if isinstance(bits_ext, bytes):
        b2 = np.unpackbits(np.frombuffer(bits_ext, dtype=np.uint8))
    else:
        b2 = np.asarray(bits_ext, dtype=np.uint8)

    min_len = min(len(b1), len(b2))
    if min_len == 0:
        return 100.0

    errors = np.sum(b1[:min_len] != b2[:min_len]) + abs(len(b1) - len(b2))
    total_len = max(len(b1), len(b2))
    ber_val = (errors / total_len) * 100.0
    return float(ber_val)


def calculate_capacity(image_shape: Tuple[int, ...], bits_per_pixel: float = 1.0) -> dict:
    """
    Computes theoretical carrier capacity in bits, bytes, and bits-per-pixel (bpp).
    """
    total_pixels = int(np.prod(image_shape[:2]))
    channels = image_shape[2] if len(image_shape) == 3 else 1
    total_bits = int(total_pixels * channels * bits_per_pixel)
    total_bytes = total_bits // 8

    return {
        "total_pixels": total_pixels,
        "channels": channels,
        "max_bits": total_bits,
        "max_bytes": total_bytes,
        "bpp": bits_per_pixel * channels,
    }

