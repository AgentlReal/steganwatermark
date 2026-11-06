"""
Cryptographic module for Steganography payload security.
Implements AES-256-GCM with PBKDF2 key derivation.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_LENGTH = 32  # 256 bits
PBKDF2_ITERATIONS = 100_000


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive 256-bit AES key from passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_payload(data: bytes, passphrase: str) -> bytes:
    """
    Encrypts arbitrary byte payload using AES-256-GCM.
    
    Structure of returned bytearray:
    [16 bytes Salt] + [12 bytes Nonce] + [Ciphertext + 16 bytes Auth Tag]
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Payload data must be bytes or bytearray.")
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    # AESGCM encrypt appends tag (16 bytes) at the end of ciphertext
    ciphertext_with_tag = aesgcm.encrypt(nonce, bytes(data), None)

    return salt + nonce + ciphertext_with_tag


def decrypt_payload(encrypted_blob: bytes, passphrase: str) -> bytes:
    """
    Decrypts AES-256-GCM encrypted blob and verifies integrity.
    
    Raises:
        ValueError if blob is truncated or decryption/auth tag verification fails.
    """
    min_len = SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(encrypted_blob) < min_len:
        raise ValueError(f"Encrypted blob too short ({len(encrypted_blob)} bytes). Expected at least {min_len} bytes.")

    salt = encrypted_blob[:SALT_SIZE]
    nonce = encrypted_blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext_with_tag = encrypted_blob[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed or invalid key/tampered payload: {e}")

