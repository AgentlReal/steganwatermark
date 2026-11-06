"""
Dual-Domain Integrated Pipeline Orchestrator.

Combines DWT-SVD Watermarking (frequency domain) and
PRNG-LSB Steganography (spatial domain) with mutual interference tracking.
"""

from dataclasses import dataclass
from typing import Tuple, Dict, Any, Optional
import time
import tracemalloc
import numpy as np

from core.watermark import DwtSvdWatermarker, WatermarkKey
from core.steganography import PrngLsbSteganographer
from core.metrics import (
    calculate_psnr,
    calculate_ssim,
    calculate_mse,
    calculate_snr,
    calculate_nc,
    calculate_ber,
)


@dataclass
class DualEmbeddingResult:
    """Encapsulates output and diagnostic metrics from dual embedding."""
    watermarked_image: np.ndarray
    stego_watermarked_image: np.ndarray
    watermark_key: WatermarkKey
    metrics: Dict[str, Any]
    embed_time_ms: float
    peak_memory_kb: float


@dataclass
class DualExtractionResult:
    """Encapsulates recovered payloads and extraction fidelity metrics."""
    extracted_payload: Optional[bytes]
    extracted_watermark: np.ndarray
    stego_ber: float
    watermark_nc: float
    extract_time_ms: float
    peak_memory_kb: float
    stego_success: bool


class DualDomainPipeline:
    """
    Coordinates simultaneous Watermark & Steganography embedding and extraction.
    
    Order of Embedding:
        1. Cover Image -> DWT-SVD Watermark -> Watermarked Image
        2. Watermarked Image -> PRNG-LSB Steganography -> Stego-Watermarked Image
        
    Order of Extraction:
        - Stego payload extracted from spatial domain using PRNG key.
        - Watermark logo extracted from DWT-SVD frequency domain.
    """

    def __init__(
        self,
        watermark_alpha: float = 0.05,
        watermark_subband: str = "HL",
        stego_channel: Optional[int] = None,
    ):
        self.watermarker = DwtSvdWatermarker(alpha=watermark_alpha, subband=watermark_subband)
        self.steganographer = PrngLsbSteganographer(channel=stego_channel)

    def run_dual_embedding(
        self,
        cover_image: np.ndarray,
        watermark_logo: np.ndarray,
        stego_payload: bytes,
        stego_passphrase: str,
    ) -> DualEmbeddingResult:
        """
        Executes dual embedding pipeline with memory and execution profiling.
        """
        tracemalloc.start()
        start_time = time.perf_counter()

        # Step 1: Watermarking (Frequency Domain DWT-SVD)
        watermarked_img, wm_key = self.watermarker.embed(cover_image, watermark_logo)

        # Baseline watermark fidelity check (before stego)
        raw_wm_extracted = self.watermarker.extract(watermarked_img, wm_key)
        baseline_wm_nc = calculate_nc(watermark_logo, raw_wm_extracted)
        baseline_psnr = calculate_psnr(cover_image, watermarked_img)

        # Step 2: Steganography (Spatial Domain PRNG-LSB)
        stego_watermarked_img = self.steganographer.embed(
            watermarked_img, stego_payload, stego_passphrase
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Quality metrics (Final vs Original Cover)
        final_psnr = calculate_psnr(cover_image, stego_watermarked_img)
        final_ssim = calculate_ssim(cover_image, stego_watermarked_img)
        final_mse = calculate_mse(cover_image, stego_watermarked_img)
        final_snr = calculate_snr(cover_image, stego_watermarked_img)

        # Interference metrics
        delta_psnr = baseline_psnr - final_psnr
        wm_extracted_after_stego = self.watermarker.extract(stego_watermarked_img, wm_key)
        post_stego_wm_nc = calculate_nc(watermark_logo, wm_extracted_after_stego)
        delta_nc = baseline_wm_nc - post_stego_wm_nc

        metrics = {
            "psnr": final_psnr,
            "ssim": final_ssim,
            "mse": final_mse,
            "snr": final_snr,
            "baseline_wm_psnr": baseline_psnr,
            "baseline_wm_nc": baseline_wm_nc,
            "post_stego_wm_nc": post_stego_wm_nc,
            "delta_psnr": delta_psnr,
            "delta_nc": delta_nc,
            "payload_bytes": len(stego_payload),
        }

        return DualEmbeddingResult(
            watermarked_image=watermarked_img,
            stego_watermarked_image=stego_watermarked_img,
            watermark_key=wm_key,
            metrics=metrics,
            embed_time_ms=elapsed_ms,
            peak_memory_kb=peak_mem / 1024.0,
        )

    def run_dual_extraction(
        self,
        stego_watermarked_image: np.ndarray,
        watermark_key: WatermarkKey,
        original_watermark_logo: np.ndarray,
        stego_passphrase: str,
        original_payload: Optional[bytes] = None,
    ) -> DualExtractionResult:
        """
        Executes simultaneous extraction of both secret payload and watermark.
        """
        tracemalloc.start()
        start_time = time.perf_counter()

        # 1. Extract Watermark
        extracted_wm = self.watermarker.extract(stego_watermarked_image, watermark_key)
        wm_nc = calculate_nc(original_watermark_logo, extracted_wm)

        # 2. Extract Stego Payload
        stego_success = False
        extracted_data = None
        ber_val = 100.0

        try:
            extracted_data = self.steganographer.extract(stego_watermarked_image, stego_passphrase)
            stego_success = True
            if original_payload is not None:
                ber_val = calculate_ber(original_payload, extracted_data)
            else:
                ber_val = 0.0
        except Exception:
            # If payload was tampered or corrupted by attacks
            stego_success = False
            extracted_data = None
            ber_val = 100.0

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return DualExtractionResult(
            extracted_payload=extracted_data,
            extracted_watermark=extracted_wm,
            stego_ber=ber_val,
            watermark_nc=wm_nc,
            extract_time_ms=elapsed_ms,
            peak_memory_kb=peak_mem / 1024.0,
            stego_success=stego_success,
        )

