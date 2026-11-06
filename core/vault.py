"""
GhostShare Vault Orchestration Module.

Combines Binary Envelope packaging, AES-256-GCM encryption,
Plausible Deniability (Multi-Passphrase / Decoy mode), and
Steganalysis Auditing into a unified, zero-auxiliary-key architecture.
"""

from dataclasses import dataclass
import hashlib
from typing import Dict, Any, Tuple, Optional, List
import numpy as np

from core.crypto import encrypt_payload, decrypt_payload
from core.envelope import pack_envelope, unpack_envelope, detect_mime_type, GhostEnvelopeError
from core.deniable import (
    PARTITION_FULL,
    PARTITION_EVEN,
    PARTITION_ODD,
    CANDIDATE_PARTITIONS,
    generate_shuffled_partition_indices,
    get_partition_indices,
)
from core.anti_steganalysis import run_full_audit


class GhostVaultError(Exception):
    """Raised when vault packaging or unpacking fails."""
    pass


@dataclass
class ExtractedVaultPayload:
    """Represents an extracted file from a GhostShare carrier."""
    filename: str
    mime_type: str
    payload_bytes: bytes
    partition_mode: str
    size_bytes: int


def bytes_to_bits(data: bytes) -> List[int]:
    """Convert bytes to a list of bit integers (0 or 1)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    """Convert a list of bit integers to bytes."""
    byte_list = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        chunk = bits[i:i + 8]
        for bit in chunk:
            byte = (byte << 1) | bit
        byte_list.append(byte)
    return bytes(byte_list)


class GhostVault:
    """
    High-level orchestrator for packing and unpacking GhostShare covert data carriers.
    """

    def __init__(self, channel: Optional[int] = None):
        """
        Args:
            channel: Target color channel index (e.g. 2 for Blue), or None for all channels.
        """
        self.channel = channel

    def _get_flat_view(self, image: np.ndarray) -> np.ndarray:
        """Returns 1D flat view of target channel(s)."""
        if image.ndim == 2:
            return image.reshape(-1)
        elif image.ndim == 3:
            if self.channel is not None:
                return image[:, :, self.channel].reshape(-1)
            return image.reshape(-1)
        else:
            raise GhostVaultError(f"Unsupported image dimensions: {image.ndim}")

    def get_capacity_info(self, image_shape: Tuple[int, ...]) -> Dict[str, int]:
        """
        Calculates usable plaintext capacity in bytes for each partition mode.
        Accounts for envelope overhead (~50 bytes) and AES-GCM + length overhead (48 bytes).
        """
        if len(image_shape) == 2:
            total_elements = image_shape[0] * image_shape[1]
        elif len(image_shape) == 3:
            if self.channel is not None:
                total_elements = image_shape[0] * image_shape[1]
            else:
                total_elements = image_shape[0] * image_shape[1] * image_shape[2]
        else:
            total_elements = 0

        overhead_bytes = 4 + 16 + 12 + 16 + 60  # Length (4) + Salt (16) + Nonce (12) + Tag (16) + Envelope (~60)
        
        full_bytes = max(0, (total_elements // 8) - overhead_bytes)
        even_odd_bytes = max(0, ((total_elements // 2) // 8) - overhead_bytes)

        return {
            "total_pixels": total_elements,
            "single_payload_max_bytes": full_bytes,
            "dual_payload_max_bytes_each": even_odd_bytes,
        }

    def _embed_bits_to_indices(
        self,
        flat_view: np.ndarray,
        bits_to_embed: List[int],
        indices: np.ndarray,
        passphrase: str,
    ) -> None:
        """
        Embeds bit stream into specified pixel coordinates using PRNG LSB Matching (±1).
        Modifies flat_view in-place.
        """
        num_bits = len(bits_to_embed)
        if num_bits > len(indices):
            raise GhostVaultError(
                f"Data size ({num_bits} bits) exceeds available capacity in partition ({len(indices)} bits)."
            )

        selected_indices = indices[:num_bits]
        rng_tie = np.random.default_rng(
            int.from_bytes(hashlib.sha256((passphrase + "_tie").encode("utf-8")).digest()[:8], "big")
        )

        for k in range(num_bits):
            target_bit = bits_to_embed[k]
            idx = selected_indices[k]
            pixel_val = int(flat_view[idx])

            if (pixel_val % 2) != target_bit:
                if pixel_val == 0:
                    pixel_val = 1
                elif pixel_val == 255:
                    pixel_val = 254
                else:
                    delta = 1 if rng_tie.random() > 0.5 else -1
                    pixel_val += delta
                flat_view[idx] = pixel_val

    def pack(
        self,
        cover_image: np.ndarray,
        secret_payload: bytes,
        secret_passphrase: str,
        secret_filename: str = "secret.bin",
        secret_mime: Optional[str] = None,
        decoy_payload: Optional[bytes] = None,
        decoy_passphrase: Optional[str] = None,
        decoy_filename: str = "decoy.bin",
        decoy_mime: Optional[str] = None,
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Packs secret payload (and optional decoy payload) into cover_image.
        
        Returns:
            (carrier_image, audit_report)
        """
        if not secret_passphrase:
            raise GhostVaultError("Secret passphrase cannot be empty.")
        if len(secret_payload) == 0:
            raise GhostVaultError("Secret payload cannot be empty.")

        carrier_img = cover_image.copy()
        flat_view = self._get_flat_view(carrier_img)
        total_elements = len(flat_view)

        # 1. Prepare secret envelope & ciphertext
        secret_envelope = pack_envelope(secret_payload, filename=secret_filename, mime_type=secret_mime)
        secret_encrypted = encrypt_payload(secret_envelope, secret_passphrase)
        secret_packet = len(secret_encrypted).to_bytes(4, byteorder="big") + secret_encrypted
        secret_bits = bytes_to_bits(secret_packet)

        is_dual_mode = bool(decoy_payload is not None and decoy_passphrase)

        if is_dual_mode:
            if not decoy_passphrase:
                raise GhostVaultError("Decoy passphrase is required when decoy payload is provided.")
            if decoy_passphrase == secret_passphrase:
                raise GhostVaultError("Decoy passphrase must be different from Secret passphrase.")

            # Prepare decoy envelope & ciphertext
            decoy_envelope = pack_envelope(decoy_payload, filename=decoy_filename, mime_type=decoy_mime)
            decoy_encrypted = encrypt_payload(decoy_envelope, decoy_passphrase)
            decoy_packet = len(decoy_encrypted).to_bytes(4, byteorder="big") + decoy_encrypted
            decoy_bits = bytes_to_bits(decoy_packet)

            # Partition allocation: Decoy -> EVEN, Secret -> ODD (disjoint sets)
            decoy_indices = generate_shuffled_partition_indices(total_elements, decoy_passphrase, PARTITION_EVEN)
            secret_indices = generate_shuffled_partition_indices(total_elements, secret_passphrase, PARTITION_ODD)

            # Embed both independently
            self._embed_bits_to_indices(flat_view, decoy_bits, decoy_indices, decoy_passphrase)
            self._embed_bits_to_indices(flat_view, secret_bits, secret_indices, secret_passphrase)
        else:
            # Single payload mode: Uses full space
            indices = generate_shuffled_partition_indices(total_elements, secret_passphrase, PARTITION_FULL)
            self._embed_bits_to_indices(flat_view, secret_bits, indices, secret_passphrase)

        # Run forensic audit
        audit_report = run_full_audit(cover_image, carrier_img)
        audit_report["mode"] = "dual_deniable" if is_dual_mode else "single"
        audit_report["secret_filename"] = secret_filename
        audit_report["secret_size_bytes"] = len(secret_payload)
        if is_dual_mode:
            audit_report["decoy_filename"] = decoy_filename
            audit_report["decoy_size_bytes"] = len(decoy_payload)

        return carrier_img, audit_report

    def unpack(self, carrier_image: np.ndarray, passphrase: str) -> ExtractedVaultPayload:
        """
        Unpacks payload corresponding to the given passphrase.
        Checks candidate partitions automatically.
        
        Returns:
            ExtractedVaultPayload
            
        Raises:
            GhostVaultError if authentication fails.
        """
        if not passphrase:
            raise GhostVaultError("Passphrase cannot be empty.")

        flat_view = self._get_flat_view(carrier_image)
        total_elements = len(flat_view)

        # Try candidate partitions
        for partition_name in CANDIDATE_PARTITIONS:
            try:
                indices = generate_shuffled_partition_indices(total_elements, passphrase, partition_name)
                if len(indices) < 32:
                    continue

                # Read 4-byte (32-bit) length header
                header_idx = indices[:32]
                header_bits = [int(flat_view[i] % 2) for i in header_idx]
                blob_len = int.from_bytes(bits_to_bytes(header_bits), byteorder="big")

                total_needed_bits = (4 + blob_len) * 8
                if blob_len <= 0 or total_needed_bits > len(indices):
                    continue

                # Read ciphertext bits
                packet_idx = indices[32:total_needed_bits]
                packet_bits = [int(flat_view[i] % 2) for i in packet_idx]
                encrypted_blob = bits_to_bytes(packet_bits)

                # Attempt AES-256-GCM decryption
                decrypted_envelope = decrypt_payload(encrypted_blob, passphrase)

                # Attempt Envelope parsing
                filename, mime_type, payload_bytes = unpack_envelope(decrypted_envelope)

                return ExtractedVaultPayload(
                    filename=filename,
                    mime_type=mime_type,
                    payload_bytes=payload_bytes,
                    partition_mode=partition_name,
                    size_bytes=len(payload_bytes),
                )
            except Exception:
                # Any decryption error, GCM tag mismatch, or envelope format error means
                # this partition or passphrase does not match. Continue to next candidate.
                continue

        raise GhostVaultError(
            "Authentication failed: invalid passphrase or image does not contain a GhostShare payload."
        )
