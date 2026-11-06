"""
GhostShare Binary Envelope Protocol.

Serializes and deserializes arbitrary file payloads into a self-contained binary envelope
preserving original filename, MIME-type, payload content, and SHA-256 checksum.
"""

import struct
import hashlib
import mimetypes
import os
from typing import Tuple, Optional


MAGIC_BYTES = b"GHST"
PROTOCOL_VERSION = 1


class GhostEnvelopeError(Exception):
    """Raised when envelope packing or unpacking fails."""
    pass


def detect_mime_type(filename: str, fallback: str = "application/octet-stream") -> str:
    """Guess MIME type from filename or return fallback."""
    mime, _ = mimetypes.guess_type(filename)
    return mime or fallback


def pack_envelope(
    payload_data: bytes,
    filename: str = "payload.bin",
    mime_type: Optional[str] = None,
) -> bytes:
    """
    Packs arbitrary bytes into a binary envelope.
    
    Binary Format:
      [0:4]   Magic bytes (b"GHST")
      [4:5]   Protocol version (uint8)
      [5:6]   Filename length (uint8, max 255)
      [6:6+N] Filename (UTF-8 encoded)
      [M:M+1] MIME type length (uint8, max 255)
      [M+1:P] MIME type (ASCII encoded)
      [P:P+4] Payload length (uint32 big-endian)
      [P+4:X] Payload bytes
      [X:X+32] SHA-256 checksum of payload bytes
    """
    if not isinstance(payload_data, (bytes, bytearray)):
        raise GhostEnvelopeError("payload_data must be bytes or bytearray.")

    clean_filename = os.path.basename(filename).strip() or "payload.bin"
    fn_bytes = clean_filename.encode("utf-8")[:255]

    if not mime_type:
        mime_type = detect_mime_type(clean_filename)
    mime_bytes = mime_type.encode("ascii", errors="ignore")[:255]

    payload_len = len(payload_data)
    checksum = hashlib.sha256(payload_data).digest()

    header = (
        MAGIC_BYTES +
        struct.pack("!BBB", PROTOCOL_VERSION, len(fn_bytes), len(mime_bytes)) +
        fn_bytes +
        mime_bytes +
        struct.pack("!I", payload_len)
    )

    return header + bytes(payload_data) + checksum


def unpack_envelope(envelope_bytes: bytes) -> Tuple[str, str, bytes]:
    """
    Unpacks binary envelope and verifies SHA-256 integrity.
    
    Returns:
        (filename, mime_type, payload_bytes)
        
    Raises:
        GhostEnvelopeError on invalid magic, truncated data, or checksum mismatch.
    """
    if len(envelope_bytes) < 4 + 3 + 4 + 32:
        raise GhostEnvelopeError("Envelope data too short to be valid GhostShare envelope.")

    magic = envelope_bytes[:4]
    if magic != MAGIC_BYTES:
        raise GhostEnvelopeError(f"Invalid magic bytes: expected {MAGIC_BYTES}, got {magic}.")

    version, fn_len, mime_len = struct.unpack("!BBB", envelope_bytes[4:7])
    if version != PROTOCOL_VERSION:
        raise GhostEnvelopeError(f"Unsupported protocol version: {version}.")

    offset = 7
    if len(envelope_bytes) < offset + fn_len + mime_len + 4 + 32:
        raise GhostEnvelopeError("Truncated envelope header.")

    fn_bytes = envelope_bytes[offset:offset + fn_len]
    offset += fn_len
    filename = fn_bytes.decode("utf-8", errors="replace")

    mime_bytes = envelope_bytes[offset:offset + mime_len]
    offset += mime_len
    mime_type = mime_bytes.decode("ascii", errors="replace")

    (payload_len,) = struct.unpack("!I", envelope_bytes[offset:offset + 4])
    offset += 4

    total_expected = offset + payload_len + 32
    if len(envelope_bytes) < total_expected:
        raise GhostEnvelopeError(
            f"Truncated envelope payload: expected {total_expected} bytes, found {len(envelope_bytes)}."
        )

    payload_bytes = envelope_bytes[offset:offset + payload_len]
    offset += payload_len

    expected_checksum = envelope_bytes[offset:offset + 32]
    actual_checksum = hashlib.sha256(payload_bytes).digest()

    if actual_checksum != expected_checksum:
        raise GhostEnvelopeError("Envelope checksum mismatch: payload may have been corrupted or tampered.")

    return filename, mime_type, payload_bytes
