"""
Attack Simulation Module for Watermark & Steganography Robustness Evaluation.

Implements realistic channel distortions:
1. Lossy JPEG compression (various quality factors)
2. Additive White Gaussian Noise (AWGN)
3. Salt & Pepper impulse noise
4. Geometric cropping attacks (center / corner)
5. Median filtering
6. Gaussian smoothing blur
"""

import io
from typing import Tuple, Optional
import numpy as np
from PIL import Image, ImageFilter


def attack_jpeg_compression(image: np.ndarray, quality: int = 75) -> np.ndarray:
    """Simulates lossy JPEG compression with specified quality factor (1-100)."""
    pil_img = Image.fromarray(image)
    buffer = io.BytesIO()
    # JPEG requires RGB or L mode
    if pil_img.mode not in ("RGB", "L"):
        pil_img = pil_img.convert("RGB")
    pil_img.save(buffer, format="JPEG", quality=int(quality))
    buffer.seek(0)
    compressed_pil = Image.open(buffer)
    return np.array(compressed_pil, dtype=np.uint8)


def attack_gaussian_noise(image: np.ndarray, mean: float = 0.0, variance: float = 0.01) -> np.ndarray:
    """
    Applies Additive White Gaussian Noise (AWGN).
    Variance is relative to normalized [0, 1] range.
    """
    img_f = image.astype(np.float64) / 255.0
    sigma = np.sqrt(variance)
    noise = np.random.normal(mean, sigma, image.shape)
    noisy_img = img_f + noise
    clipped = np.clip(noisy_img * 255.0, 0.0, 255.0)
    return clipped.round().astype(np.uint8)


def attack_salt_pepper(image: np.ndarray, prob: float = 0.02) -> np.ndarray:
    """
    Applies Salt & Pepper impulse noise.
    prob: Probability of noise occurrence (0.0 to 1.0).
    """
    out = image.copy()
    num_salt = np.ceil(prob * image.size * 0.5)
    num_pepper = np.ceil(prob * image.size * 0.5)

    # Salt (white pixels: 255)
    coords = [np.random.randint(0, i - 1, int(num_salt)) for i in image.shape]
    out[tuple(coords)] = 255

    # Pepper (black pixels: 0)
    coords = [np.random.randint(0, i - 1, int(num_pepper)) for i in image.shape]
    out[tuple(coords)] = 0

    return out


def attack_cropping(image: np.ndarray, crop_ratio: float = 0.2, position: str = "center") -> np.ndarray:
    """
    Simulates cropping attack by setting a fraction of the image pixels to 0.
    
    Args:
        crop_ratio: Fraction of dimension to cut (e.g., 0.2 means 20% width & height).
        position: 'center', 'top_left', 'bottom_right'.
    """
    out = image.copy()
    h, w = image.shape[:2]
    crop_h = int(h * crop_ratio)
    crop_w = int(w * crop_ratio)

    if position == "center":
        y1 = (h - crop_h) // 2
        x1 = (w - crop_w) // 2
    elif position == "top_left":
        y1, x1 = 0, 0
    elif position == "bottom_right":
        y1, x1 = h - crop_h, w - crop_w
    else:
        y1 = (h - crop_h) // 2
        x1 = (w - crop_w) // 2

    y2 = min(h, y1 + crop_h)
    x2 = min(w, x1 + crop_w)

    out[y1:y2, x1:x2] = 0
    return out


def attack_median_filter(image: np.ndarray, kernel_size: int = 3) -> np.ndarray:
    """Applies non-linear median filtering."""
    pil_img = Image.fromarray(image)
    filtered = pil_img.filter(ImageFilter.MedianFilter(size=int(kernel_size)))
    return np.array(filtered, dtype=np.uint8)


def attack_gaussian_blur(image: np.ndarray, radius: float = 1.0) -> np.ndarray:
    """Applies Gaussian smoothing blur filter."""
    pil_img = Image.fromarray(image)
    blurred = pil_img.filter(ImageFilter.GaussianBlur(radius=float(radius)))
    return np.array(blurred, dtype=np.uint8)

