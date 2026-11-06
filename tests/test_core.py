"""
Unit and Integration Tests for Steganography + Watermarking System.
"""

import unittest
import numpy as np
from PIL import Image

from core.crypto import encrypt_payload, decrypt_payload
from core.watermark import DwtSvdWatermarker
from core.steganography import PrngLsbSteganographer
from core.metrics import (
    calculate_psnr,
    calculate_ssim,
    calculate_mse,
    calculate_snr,
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
from core.steganalysis import chi_square_steganalysis
from core.pipeline import DualDomainPipeline


class TestSteganowatermarkSystem(unittest.TestCase):

    def setUp(self):
        # Create deterministic synthetic cover image (512x512 RGB)
        np.random.seed(42)
        self.cover_img = np.random.randint(60, 200, size=(512, 512, 3), dtype=np.uint8)
        
        # Create 64x64 binary watermark logo
        self.watermark_logo = np.zeros((64, 64), dtype=np.uint8)
        self.watermark_logo[16:48, 16:48] = 255

        self.passphrase = "SecretP@ssw0rd2026!"
        self.test_payload = b"Testing steganography payload with AES-256-GCM encryption."

    def test_crypto_roundtrip(self):
        encrypted = encrypt_payload(self.test_payload, self.passphrase)
        self.assertNotEqual(encrypted, self.test_payload)
        decrypted = decrypt_payload(encrypted, self.passphrase)
        self.assertEqual(decrypted, self.test_payload)

    def test_crypto_tamper_detection(self):
        encrypted = bytearray(encrypt_payload(self.test_payload, self.passphrase))
        # Tamper last byte (auth tag)
        encrypted[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            decrypt_payload(bytes(encrypted), self.passphrase)

    def test_crypto_wrong_passphrase(self):
        encrypted = encrypt_payload(self.test_payload, self.passphrase)
        with self.assertRaises(ValueError):
            decrypt_payload(encrypted, "WrongPassword!")

    def test_watermark_embed_and_extract(self):
        watermarker = DwtSvdWatermarker(alpha=0.08, subband="HL")
        watermarked_img, wm_key = watermarker.embed(self.cover_img, self.watermark_logo)

        self.assertEqual(watermarked_img.shape, self.cover_img.shape)
        psnr_val = calculate_psnr(self.cover_img, watermarked_img)
        self.assertGreater(psnr_val, 35.0)

        extracted_logo = watermarker.extract(watermarked_img, wm_key)
        nc_val = calculate_nc(self.watermark_logo, extracted_logo)
        self.assertGreater(nc_val, 0.95)

    def test_steganography_embed_and_extract(self):
        stego = PrngLsbSteganographer()
        stego_img = stego.embed(self.cover_img, self.test_payload, self.passphrase)

        self.assertEqual(stego_img.shape, self.cover_img.shape)
        psnr_val = calculate_psnr(self.cover_img, stego_img)
        self.assertGreater(psnr_val, 45.0)

        extracted = stego.extract(stego_img, self.passphrase)
        self.assertEqual(extracted, self.test_payload)

    def test_metrics_computations(self):
        mse_identical = calculate_mse(self.cover_img, self.cover_img)
        self.assertEqual(mse_identical, 0.0)

        psnr_identical = calculate_psnr(self.cover_img, self.cover_img)
        self.assertEqual(psnr_identical, float("inf"))

        ssim_identical = calculate_ssim(self.cover_img, self.cover_img)
        self.assertAlmostEqual(ssim_identical, 1.0, places=4)

        nc_identical = calculate_nc(self.watermark_logo, self.watermark_logo)
        self.assertAlmostEqual(nc_identical, 1.0, places=4)

        ber_identical = calculate_ber(self.test_payload, self.test_payload)
        self.assertEqual(ber_identical, 0.0)

        cap = calculate_capacity(self.cover_img.shape)
        self.assertEqual(cap["total_pixels"], 512 * 512)
        self.assertEqual(cap["channels"], 3)

    def test_attack_functions_stability(self):
        att_jpeg = attack_jpeg_compression(self.cover_img, quality=50)
        self.assertEqual(att_jpeg.shape, self.cover_img.shape)

        att_noise = attack_gaussian_noise(self.cover_img, variance=0.01)
        self.assertEqual(att_noise.shape, self.cover_img.shape)

        att_sp = attack_salt_pepper(self.cover_img, prob=0.02)
        self.assertEqual(att_sp.shape, self.cover_img.shape)

        att_crop = attack_cropping(self.cover_img, crop_ratio=0.2)
        self.assertEqual(att_crop.shape, self.cover_img.shape)

        att_med = attack_median_filter(self.cover_img, kernel_size=3)
        self.assertEqual(att_med.shape, self.cover_img.shape)

        att_blur = attack_gaussian_blur(self.cover_img, radius=1.0)
        self.assertEqual(att_blur.shape, self.cover_img.shape)

    def test_steganalysis_chi_square(self):
        res = chi_square_steganalysis(self.cover_img)
        self.assertIn("chi2_stat", res)
        self.assertIn("p_value", res)
        self.assertIn("detection_confidence", res)

    def test_dual_pipeline_integration(self):
        pipeline = DualDomainPipeline(watermark_alpha=0.06, watermark_subband="HL")
        
        # Dual Embedding
        embed_res = pipeline.run_dual_embedding(
            cover_image=self.cover_img,
            watermark_logo=self.watermark_logo,
            stego_payload=self.test_payload,
            stego_passphrase=self.passphrase,
        )

        self.assertGreater(embed_res.metrics["psnr"], 35.0)
        self.assertGreater(embed_res.metrics["ssim"], 0.95)
        # Interference check: Delta NC should be very small (< 0.05)
        self.assertLess(abs(embed_res.metrics["delta_nc"]), 0.05)

        # Dual Extraction
        extract_res = pipeline.run_dual_extraction(
            stego_watermarked_image=embed_res.stego_watermarked_image,
            watermark_key=embed_res.watermark_key,
            original_watermark_logo=self.watermark_logo,
            stego_passphrase=self.passphrase,
            original_payload=self.test_payload,
        )

        self.assertTrue(extract_res.stego_success)
        self.assertEqual(extract_res.extracted_payload, self.test_payload)
        self.assertEqual(extract_res.stego_ber, 0.0)
        self.assertGreater(extract_res.watermark_nc, 0.95)

    def test_watermark_key_serialization(self):
        watermarker = DwtSvdWatermarker(alpha=0.05, subband="HL")
        _, wm_key = watermarker.embed(self.cover_img, self.watermark_logo)

        # Test to_bytes / from_bytes
        key_bytes = wm_key.to_bytes()
        self.assertIsInstance(key_bytes, bytes)
        self.assertGreater(len(key_bytes), 100)

        restored_key = wm_key.from_bytes(key_bytes)
        self.assertEqual(restored_key.alpha, wm_key.alpha)
        self.assertEqual(restored_key.subband, wm_key.subband)
        self.assertTrue(np.allclose(restored_key.original_singular_values, wm_key.original_singular_values))

        # Test save_to_file / load_from_file
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            wm_key.save_to_file(tmp_path)
            loaded_key = wm_key.load_from_file(tmp_path)
            self.assertEqual(loaded_key.watermark_shape, wm_key.watermark_shape)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_odd_dimensions_handling(self):
        # Create image with odd width and odd height (511 x 509)
        odd_img = np.random.randint(60, 200, size=(511, 509, 3), dtype=np.uint8)
        watermarker = DwtSvdWatermarker(alpha=0.05, subband="HL")
        
        # Embed and extract should not crash
        wm_img, wm_key = watermarker.embed(odd_img, self.watermark_logo)
        self.assertEqual(wm_img.shape[0] % 2, 0)
        self.assertEqual(wm_img.shape[1] % 2, 0)

        extracted = watermarker.extract(wm_img, wm_key)
        nc_val = calculate_nc(self.watermark_logo, extracted)
        self.assertGreater(nc_val, 0.95)


if __name__ == "__main__":
    unittest.main()

