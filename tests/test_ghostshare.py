"""
Unit tests for GhostShare Suite.
"""

import unittest
import os
import numpy as np

from core.envelope import pack_envelope, unpack_envelope, GhostEnvelopeError
from core.deniable import (
    PARTITION_FULL,
    PARTITION_EVEN,
    PARTITION_ODD,
    get_partition_indices,
    generate_shuffled_partition_indices,
)
from core.vault import GhostVault, GhostVaultError
from core.anti_steganalysis import run_full_audit


class TestGhostShare(unittest.TestCase):

    def setUp(self):
        # Create a synthetic 128x128 RGB test image with natural image gradients
        x = np.linspace(0, 10, 128)
        y = np.linspace(0, 10, 128)
        xx, yy = np.meshgrid(x, y)
        pattern = (100 + 40 * np.sin(xx) * np.cos(yy)).astype(np.uint8)
        self.cover_rgb = np.stack([pattern, pattern, pattern], axis=-1)
        self.vault = GhostVault()

    def test_envelope_roundtrip(self):
        """Test binary envelope packing and unpacking."""
        original_data = b"TOP_SECRET_CLASSIFIED_DISCLOSURE_2026_DATA"
        filename = "leak_doc.pdf"
        mime = "application/pdf"

        envelope = pack_envelope(original_data, filename=filename, mime_type=mime)
        self.assertGreater(len(envelope), len(original_data))

        fn, m, payload = unpack_envelope(envelope)
        self.assertEqual(fn, filename)
        self.assertEqual(m, mime)
        self.assertEqual(payload, original_data)

    def test_envelope_tamper_detection(self):
        """Test envelope detects corrupted or modified bytes in payload or checksum."""
        original_data = b"SOME_DATA_TO_CORRUPT"
        envelope = bytearray(pack_envelope(original_data, filename="test.txt"))
        
        # Tamper the last byte of the payload
        envelope[-35] ^= 0xFF
        with self.assertRaises(GhostEnvelopeError):
            unpack_envelope(bytes(envelope))

    def test_partition_disjointness(self):
        """Test that Even and Odd partitions have strictly zero overlap."""
        total = 1000
        even_idx = get_partition_indices(total, PARTITION_EVEN)
        odd_idx = get_partition_indices(total, PARTITION_ODD)

        intersection = set(even_idx).intersection(set(odd_idx))
        self.assertEqual(len(intersection), 0, "Partitions MUST be completely disjoint.")
        self.assertEqual(len(even_idx) + len(odd_idx), total)

    def test_single_payload_vault_lifecycle(self):
        """Test single-payload pack, audit, and unpack."""
        secret_content = b"SingleSecretPayloadTestBytes_12345"
        secret_pass = "MyStrongPassword_2026!"
        secret_fn = "secret_memo.txt"

        carrier, audit = self.vault.pack(
            cover_image=self.cover_rgb,
            secret_payload=secret_content,
            secret_passphrase=secret_pass,
            secret_filename=secret_fn,
        )

        self.assertEqual(carrier.shape, self.cover_rgb.shape)
        self.assertGreater(audit["psnr_db"], 45.0)
        self.assertTrue(audit["is_secure"])

        # Unpack with correct password
        extracted = self.vault.unpack(carrier, secret_pass)
        self.assertEqual(extracted.filename, secret_fn)
        self.assertEqual(extracted.payload_bytes, secret_content)

        # Unpack with wrong password must fail
        with self.assertRaises(GhostVaultError):
            self.vault.unpack(carrier, "WrongPassword!")

    def test_plausible_deniability_dual_payload(self):
        """
        Critical Test: Plausible Deniability Dual-Payload Isolation.
        1. Carrier holds Real Secret AND Decoy Payload.
        2. Entering Decoy Passphrase extracts ONLY the Decoy Payload.
        3. Entering Real Passphrase extracts ONLY the Real Secret Payload.
        """
        real_content = b"ACTUAL_SECRET_LEAK_CONFIDENTIAL_FILES_2026" * 5
        real_pass = "RealSecretKey_Alpha!"
        real_fn = "classified_leak.pdf"

        decoy_content = b"Innocent shopping list: apples, milk, bread, butter." * 3
        decoy_pass = "InnocentDecoyKey_Beta!"
        decoy_fn = "shopping_list.txt"

        carrier, audit = self.vault.pack(
            cover_image=self.cover_rgb,
            secret_payload=real_content,
            secret_passphrase=real_pass,
            secret_filename=real_fn,
            decoy_payload=decoy_content,
            decoy_passphrase=decoy_pass,
            decoy_filename=decoy_fn,
        )

        self.assertEqual(audit["mode"], "dual_deniable")
        self.assertGreater(audit["psnr_db"], 45.0)

        # Test Decoy Extraction (Simulating coerced user providing decoy password)
        decoy_extracted = self.vault.unpack(carrier, decoy_pass)
        self.assertEqual(decoy_extracted.filename, decoy_fn)
        self.assertEqual(decoy_extracted.payload_bytes, decoy_content)

        # Test Real Secret Extraction
        real_extracted = self.vault.unpack(carrier, real_pass)
        self.assertEqual(real_extracted.filename, real_fn)
        self.assertEqual(real_extracted.payload_bytes, real_content)

        # Test Wrong Password Rejection
        with self.assertRaises(GhostVaultError):
            self.vault.unpack(carrier, "AdversaryGuessPassword")

    def test_capacity_calculation(self):
        """Test capacity estimation."""
        caps = self.vault.get_capacity_info((256, 256, 3))
        self.assertEqual(caps["total_pixels"], 256 * 256 * 3)
        self.assertGreater(caps["single_payload_max_bytes"], 20000)
        self.assertGreater(caps["dual_payload_max_bytes_each"], 10000)

    def test_audit_report_structure(self):
        """Test anti-steganalysis audit report fields."""
        report = run_full_audit(self.cover_rgb, self.cover_rgb)
        self.assertIn("chi2_p_value", report)
        self.assertIn("stealth_score", report)
        self.assertIn("verdict", report)
        self.assertTrue(report["is_secure"])


if __name__ == "__main__":
    unittest.main()
