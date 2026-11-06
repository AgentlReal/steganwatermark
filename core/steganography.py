"""
Steganography Module using PRNG-scattered LSB Matching (±1 embedding)
combined with AES-256-GCM encryption.

Designed for high imperceptibility, statistical security against Chi-Square attacks,
and robust mutual non-interference with frequency-domain watermarks.
"""

import random
import hashlib
from typing import Tuple, List, Optional
import numpy as np

from core.crypto import encrypt_payload, decrypt_payload


class PrngLsbSteganographer:
    """
    Steganography engine providing:
    1. AES-256-GCM encryption with PBKDF2 key derivation.
    2. Pseudo-Random Number Generator (PRNG) scattered pixel selection.
    3. LSB Matching (random ±1) embedding to preserve histogram symmetry.
    """

    def __init__(self, channel: Optional[int] = None):
        """
        Args:
            channel: Target color channel for embedding (e.g. 2 for Blue channel in RGB,
                     or None to use all available channels sequentially).
        """
        self.channel = channel

    def _get_capacity_bits(self, image_shape: Tuple[int, ...]) -> int:
        """Returns total bits available in the image based on channel configuration."""
        if len(image_shape) == 2:
            return image_shape[0] * image_shape[1]
        elif len(image_shape) == 3:
            if self.channel is not None:
                return image_shape[0] * image_shape[1]
            return image_shape[0] * image_shape[1] * image_shape[2]
        return 0

    def get_max_payload_bytes(self, image_shape: Tuple[int, ...]) -> int:
        """
        Returns maximum usable plaintext payload bytes (accounting for
        length header, salt, nonce, and auth tag overhead).
        Overhead = 4 (length) + 16 (salt) + 12 (nonce) + 16 (tag) = 48 bytes.
        """
        total_bits = self._get_capacity_bits(image_shape)
        total_bytes = total_bits // 8
        overhead = 4 + 16 + 12 + 16
        return max(0, total_bytes - overhead)

    def _generate_shuffled_indices(self, total_elements: int, passphrase: str) -> np.ndarray:
        """Generate a deterministic pseudo-random permutation of indices using passphrase."""
        # Derive integer seed from SHA-256 hash of passphrase
        seed_hash = hashlib.sha256(passphrase.encode("utf-8")).digest()
        seed_int = int.from_bytes(seed_hash[:8], byteorder="big")
        
        # Deterministic shuffle
        rng = np.random.default_rng(seed_int)
        indices = np.arange(total_elements, dtype=np.int64)
        rng.shuffle(indices)
        return indices

    def _bytes_to_bits(self, data: bytes) -> List[int]:
        """Convert bytes to a list of bit integers (0 or 1)."""
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    def _bits_to_bytes(self, bits: List[int]) -> bytes:
        """Convert a list of bit integers to bytes."""
        byte_list = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            chunk = bits[i:i + 8]
            for bit in chunk:
                byte = (byte << 1) | bit
            byte_list.append(byte)
        return bytes(byte_list)

    def embed(self, host_image: np.ndarray, payload: bytes, passphrase: str) -> np.ndarray:
        """
        Encrypts payload with AES-256-GCM and embeds into host image using PRNG LSB Matching.
        
        Args:
            host_image: 2D (grayscale) or 3D (RGB) uint8 image.
            payload: Secret data bytes.
            passphrase: Secret key for encryption and PRNG sequence.
            
        Returns:
            stego_image: Modified uint8 image.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("Payload must be bytes or bytearray.")
        if len(payload) == 0:
            raise ValueError("Payload cannot be empty.")

        # 1. Encrypt payload
        encrypted_blob = encrypt_payload(payload, passphrase)
        blob_len = len(encrypted_blob)

        # 2. Pack 4-byte length header + encrypted blob
        packed_data = blob_len.to_bytes(4, byteorder="big") + encrypted_blob
        bits_to_embed = self._bytes_to_bits(packed_data)
        num_bits = len(bits_to_embed)

        # 3. Flatten target region
        img_out = host_image.copy()
        if host_image.ndim == 2:
            flat_view = img_out.reshape(-1)
        elif host_image.ndim == 3:
            if self.channel is not None:
                flat_view = img_out[:, :, self.channel].reshape(-1)
            else:
                flat_view = img_out.reshape(-1)
        else:
            raise ValueError(f"Unsupported image dimensions: {host_image.ndim}")

        total_pixels = len(flat_view)
        if num_bits > total_pixels:
            raise ValueError(
                f"Payload size ({num_bits} bits) exceeds carrier capacity ({total_pixels} bits)."
            )

        # 4. Generate shuffled indices based on passphrase
        shuffled_idx = self._generate_shuffled_indices(total_pixels, passphrase)
        selected_idx = shuffled_idx[:num_bits]

        # 5. LSB Matching (randomized ±1 embedding to preserve histogram symmetry)
        # Seed secondary RNG for tie-breaking ±1
        rng_tie = np.random.default_rng(int.from_bytes(hashlib.md5(passphrase.encode()).digest()[:8], "big"))
        
        for k in range(num_bits):
            target_bit = bits_to_embed[k]
            idx = selected_idx[k]
            pixel_val = int(flat_view[idx])

            if (pixel_val % 2) != target_bit:
                if pixel_val == 0:
                    pixel_val = 1
                elif pixel_val == 255:
                    pixel_val = 254
                else:
                    # Randomly choose +1 or -1
                    delta = 1 if rng_tie.random() > 0.5 else -1
                    pixel_val += delta
                flat_view[idx] = pixel_val

        return img_out

    def extract(self, stego_image: np.ndarray, passphrase: str) -> bytes:
        """
        Extracts and decrypts secret payload from stego image.
        
        Args:
            stego_image: 2D or 3D uint8 image.
            passphrase: Secret key used during embedding.
            
        Returns:
            decrypted_payload: Original plaintext bytes.
        """
        if stego_image.ndim == 2:
            flat_view = stego_image.reshape(-1)
        elif stego_image.ndim == 3:
            if self.channel is not None:
                flat_view = stego_image[:, :, self.channel].reshape(-1)
            else:
                flat_view = stego_image.reshape(-1)
        else:
            raise ValueError(f"Unsupported image dimensions: {stego_image.ndim}")

        total_pixels = len(flat_view)
        shuffled_idx = self._generate_shuffled_indices(total_pixels, passphrase)

        # 1. Read first 32 bits (4 bytes) to determine payload length
        if total_pixels < 32:
            raise ValueError("Image too small to contain stego header.")

        header_idx = shuffled_idx[:32]
        header_bits = [int(flat_view[i] % 2) for i in header_idx]
        blob_len = int.from_bytes(self._bits_to_bytes(header_bits), byteorder="big")

        # Basic sanity check
        total_needed_bits = (4 + blob_len) * 8
        if blob_len <= 0 or total_needed_bits > total_pixels:
            raise ValueError(
                f"Invalid or corrupted stego payload length: {blob_len} bytes "
                f"(needs {total_needed_bits} bits, carrier has {total_pixels} bits). "
                "Check passphrase or image integrity."
            )

        # 2. Read remaining payload bits
        payload_idx = shuffled_idx[32:total_needed_bits]
        payload_bits = [int(flat_view[i] % 2) for i in payload_idx]
        encrypted_blob = self._bits_to_bytes(payload_bits)

        # 3. Decrypt and verify AES-256-GCM auth tag
        plaintext = decrypt_payload(encrypted_blob, passphrase)
        return plaintext

    def extract_raw_bits(self, stego_image: np.ndarray, passphrase: str, num_bits: int) -> List[int]:
        """Extract raw LSB bits at PRNG positions (useful for Bit Error Rate / BER testing)."""
        if stego_image.ndim == 2:
            flat_view = stego_image.reshape(-1)
        elif stego_image.ndim == 3:
            if self.channel is not None:
                flat_view = stego_image[:, :, self.channel].reshape(-1)
            else:
                flat_view = stego_image.reshape(-1)
        else:
            raise ValueError(f"Unsupported image dimensions: {stego_image.ndim}")

        shuffled_idx = self._generate_shuffled_indices(len(flat_view), passphrase)
        selected_idx = shuffled_idx[:num_bits]
        return [int(flat_view[i] % 2) for i in selected_idx]

