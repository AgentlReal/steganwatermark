"""
Digital Watermarking Module using Discrete Wavelet Transform (DWT)
and Singular Value Decomposition (SVD).

Designed for robust copyright protection and ownership verification.
Supports grayscale and RGB images (via YCbCr luminance decomposition).
Implements the canonical DWT-SVD algorithm:
    Embed: SVD(diag(S_c) + alpha * W) -> S_wm -> HL* = U_c @ diag(S_wm) @ V_c^T
    Extract: D* = U_w @ diag(S_wm*) @ V_w^T -> W* = (D* - diag(S_c)) / alpha
"""

import os
import pickle
from dataclasses import dataclass
from typing import Tuple, Optional
import numpy as np
import pywt
from PIL import Image


@dataclass
class WatermarkKey:
    """Metadata required for semi-blind extraction of DWT-SVD watermark."""
    alpha: float
    subband: str
    original_singular_values: np.ndarray  # S_c
    u_watermark: np.ndarray              # U_w
    vt_watermark: np.ndarray             # V_w^T
    watermark_shape: Tuple[int, int]
    is_color: bool

    def to_bytes(self) -> bytes:
        """Serialize watermark key metadata into portable byte stream."""
        return pickle.dumps(self)

    @classmethod
    def from_bytes(cls, data: bytes) -> "WatermarkKey":
        """Deserialize watermark key metadata from byte stream."""
        obj = pickle.loads(data)
        if not isinstance(obj, WatermarkKey):
            raise ValueError("Invalid watermark key data: parsed object is not a WatermarkKey instance.")
        return obj

    def save_to_file(self, filepath: str) -> None:
        """Save watermark key to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(self.to_bytes())

    @classmethod
    def load_from_file(cls, filepath: str) -> "WatermarkKey":
        """Load watermark key from disk file."""
        with open(filepath, "rb") as f:
            return cls.from_bytes(f.read())


class DwtSvdWatermarker:
    """
    Robust Watermarking engine utilizing DWT + SVD.
    
    Attributes:
        alpha: Watermark embedding strength factor (default 0.05).
        subband: DWT sub-band for embedding ('HL', 'LH', 'LL', or 'HH').
        wavelet: Wavelet family (default 'haar').
    """

    def __init__(self, alpha: float = 0.05, subband: str = "HL", wavelet: str = "haar"):
        if subband not in ("LL", "LH", "HL", "HH"):
            raise ValueError(f"Invalid subband '{subband}'. Choose from 'LL', 'LH', 'HL', 'HH'.")
        self.alpha = float(alpha)
        self.subband = subband
        self.wavelet = wavelet

    def _prepare_cover(self, image: np.ndarray) -> Tuple[np.ndarray, Optional[np.ndarray], bool]:
        """
        Convert input image to float channel and preserve color channels if RGB.
        Ensures width and height are even numbers for exact 1-level DWT decomposition.
        """
        h, w = image.shape[:2]
        h_even = h - (h % 2)
        w_even = w - (w % 2)
        if h != h_even or w != w_even:
            image = image[:h_even, :w_even]

        if image.ndim == 3 and image.shape[2] == 3:
            # Convert RGB to YCbCr using standard ITU-R BT.601
            r = image[:, :, 0].astype(np.float64)
            g = image[:, :, 1].astype(np.float64)
            b = image[:, :, 2].astype(np.float64)
            y = 0.299 * r + 0.587 * g + 0.114 * b
            cb = -0.168736 * r - 0.331264 * g + 0.5 * b + 128.0
            cr = 0.5 * r - 0.418688 * g - 0.081312 * b + 128.0
            return y, np.stack([cb, cr], axis=-1), True
        elif image.ndim == 2:
            return image.astype(np.float64), None, False
        else:
            raise ValueError(f"Unsupported image shape: {image.shape}")

    def _reconstruct_cover(self, y: np.ndarray, chrominance: Optional[np.ndarray], is_color: bool) -> np.ndarray:
        """Reconstruct uint8 image from Y channel and optional chrominance."""
        y_clipped = np.clip(y, 0.0, 255.0)
        if is_color and chrominance is not None:
            if chrominance.shape[:2] != y_clipped.shape[:2]:
                chrominance = chrominance[:y_clipped.shape[0], :y_clipped.shape[1]]
            cb = chrominance[:, :, 0]
            cr = chrominance[:, :, 1]
            r = y_clipped + 1.402 * (cr - 128.0)
            g = y_clipped - 0.344136 * (cb - 128.0) - 0.714136 * (cr - 128.0)
            b = y_clipped + 1.772 * (cb - 128.0)
            rgb = np.stack([r, g, b], axis=-1)
            return np.clip(rgb, 0.0, 255.0).round().astype(np.uint8)
        else:
            return y_clipped.round().astype(np.uint8)

    def embed(self, cover_image: np.ndarray, watermark_logo: np.ndarray) -> Tuple[np.ndarray, WatermarkKey]:
        """
        Embeds a 2D watermark logo into the cover image using canonical DWT-SVD.
        Supports arbitrary rectangular or square dimensions.
        """
        y, chrominance, is_color = self._prepare_cover(cover_image)
        wm_shape = watermark_logo.shape

        # 1. 1-level 2D Discrete Wavelet Transform on Y channel
        coeffs = pywt.dwt2(y, self.wavelet)
        ll, (lh, hl, hh) = coeffs
        subbands = {"LL": ll, "LH": lh, "HL": hl, "HH": hh}
        target_subband = subbands[self.subband].copy()

        # 2. Singular Value Decomposition of the target subband
        u_c, s_c, vt_c = np.linalg.svd(target_subband, full_matrices=False)
        k = len(s_c)

        # 3. Resize watermark matrix to square (k, k) matching singular values
        wm_pil = Image.fromarray(watermark_logo.astype(np.uint8)).resize(
            (k, k), Image.Resampling.BILINEAR
        )
        w_mat = np.array(wm_pil, dtype=np.float64)

        # 4. SVD on (diag(S_c) + alpha * W)
        mat_to_svd = np.diag(s_c) + self.alpha * w_mat
        u_w, s_wm, vt_w = np.linalg.svd(mat_to_svd, full_matrices=False)

        # 5. Reconstruct target subband using modified singular values
        target_mod = (u_c[:, :k] * s_wm) @ vt_c[:k, :]
        subbands[self.subband] = target_mod

        # 6. Inverse DWT
        reconstructed_coeffs = (subbands["LL"], (subbands["LH"], subbands["HL"], subbands["HH"]))
        y_wm = pywt.idwt2(reconstructed_coeffs, self.wavelet)

        # Handle potential boundary discrepancy in IDWT
        if y_wm.shape != y.shape:
            y_wm = y_wm[:y.shape[0], :y.shape[1]]

        watermarked_img = self._reconstruct_cover(y_wm, chrominance, is_color)

        key = WatermarkKey(
            alpha=self.alpha,
            subband=self.subband,
            original_singular_values=s_c,
            u_watermark=u_w,
            vt_watermark=vt_w,
            watermark_shape=wm_shape,
            is_color=is_color,
        )
        return watermarked_img, key

    def extract(self, watermarked_image: np.ndarray, key: WatermarkKey) -> np.ndarray:
        """
        Extracts the watermark logo from a (potentially attacked) watermarked image.
        """
        y, _, _ = self._prepare_cover(watermarked_image)

        # 1. 1-level DWT
        coeffs = pywt.dwt2(y, self.wavelet)
        ll, (lh, hl, hh) = coeffs
        subbands = {"LL": ll, "LH": lh, "HL": hl, "HH": hh}
        target_subband = subbands[key.subband]

        # 2. SVD on target subband
        _, s_wm_ext, _ = np.linalg.svd(target_subband, full_matrices=False)

        # 3. Invert SVD embedding: D* = U_w @ diag(S_wm*) @ V_w^T
        k = min(len(s_wm_ext), len(key.original_singular_values), key.u_watermark.shape[1])
        u_w = key.u_watermark[:, :k]
        vt_w = key.vt_watermark[:k, :]
        d_ext = (u_w * s_wm_ext[:k]) @ vt_w

        # 4. Extract watermark: W* = (D* - diag(S_c)) / alpha
        diag_sc = np.diag(key.original_singular_values[:k])
        w_ext = (d_ext - diag_sc) / key.alpha

        # 5. Clip, normalize, and resize back to original watermark logo dimensions
        w_clipped = np.clip(w_ext, 0.0, 255.0).astype(np.uint8)
        ext_pil = Image.fromarray(w_clipped)
        if ext_pil.size != (key.watermark_shape[1], key.watermark_shape[0]):
            ext_pil = ext_pil.resize(
                (key.watermark_shape[1], key.watermark_shape[0]),
                Image.Resampling.BILINEAR,
            )

        return np.array(ext_pil, dtype=np.uint8)
