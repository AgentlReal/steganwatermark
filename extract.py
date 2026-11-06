"""
Standalone CLI Utility for Extracting Steganography and Watermark from Images.

Usage Examples:
    # Extract both Steganography and Watermark:
    python extract.py --image output/images/stego_watermarked.png \
                      --passphrase "Aria2026SecureKey!" \
                      --key-file output/reports/latest_key.key \
                      --watermark-ref data/watermarks/copyright_64.png

    # Extract Steganography only (blind extraction):
    python extract.py --image path/to/my_photo.png --passphrase "Aria2026SecureKey!"

    # Extract Watermark only:
    python extract.py --image path/to/my_photo.png --key-file path/to/my_key.key
"""

import os
import sys
import argparse
import numpy as np
from PIL import Image

from core.watermark import DwtSvdWatermarker, WatermarkKey
from core.steganography import PrngLsbSteganographer
from core.metrics import calculate_nc, calculate_ber


def main():
    parser = argparse.ArgumentParser(
        description="Extract and verify secret steganography data and/or digital watermark from an image."
    )
    parser.add_argument(
        "--image", "-i", required=True, help="Path to the stego-watermarked image file (PNG/JPG)."
    )
    parser.add_argument(
        "--passphrase", "-p", default=None, help="Secret passphrase used for AES-256-GCM steganography decryption."
    )
    parser.add_argument(
        "--key-file", "-k", default=None, help="Path to the watermark metadata key file (.key)."
    )
    parser.add_argument(
        "--watermark-ref", "-w", default=None, help="Path to original watermark logo image to calculate NC score."
    )
    parser.add_argument(
        "--output-dir", "-o", default="output/extracted", help="Directory where extracted files will be saved."
    )

    args = parser.parse_args()

    if not os.path.exists(args.image):
        print(f"[!] Error: Image file not found: {args.image}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    # 1. Load target image
    pil_img = Image.open(args.image)
    if pil_img.mode not in ("RGB", "L"):
        pil_img = pil_img.convert("RGB")
    img_np = np.array(pil_img)
    print("=" * 70)
    print("      STANDALONE EXTRACTION & VERIFICATION UTILITY")
    print("=" * 70)
    print(f"[*] Target Image: {args.image} ({img_np.shape[1]}x{img_np.shape[0]}, {pil_img.mode})")

    # 2. Extract Steganography (if passphrase provided)
    if args.passphrase is not None:
        print("\n--> [1/2] Processing Steganography Extraction (PRNG-LSB + AES-256-GCM)...")
        stego_engine = PrngLsbSteganographer()
        try:
            decrypted_bytes = stego_engine.extract(img_np, args.passphrase)
            
            # Determine text vs binary
            try:
                text_content = decrypted_bytes.decode("utf-8")
                out_path = os.path.join(args.output_dir, "recovered_secret.txt")
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(text_content)
                is_text = True
            except UnicodeDecodeError:
                out_path = os.path.join(args.output_dir, "recovered_secret.bin")
                with open(out_path, "wb") as f:
                    f.write(decrypted_bytes)
                is_text = False

            print(f"[+] SUCCESS: Steganography payload successfully decrypted and authenticated!")
            print(f"    * Payload Size: {len(decrypted_bytes)} bytes")
            print(f"    * Output Saved: {out_path}")
            if is_text:
                preview = text_content[:150] + ("..." if len(text_content) > 150 else "")
                print(f"    * Plaintext Preview: \"{preview}\"")
        except Exception as e:
            print(f"[-] FAILED: Steganography extraction failed: {e}")
            print("    (Passphrase incorrect, or image data was modified/corrupted)")
    else:
        print("\n--> [1/2] Steganography extraction skipped (no --passphrase provided).")

    # 3. Extract Watermark (if key file provided)
    if args.key_file is not None:
        print("\n--> [2/2] Processing Watermark Extraction (DWT-SVD)...")
        if not os.path.exists(args.key_file):
            print(f"[!] Error: Key file not found: {args.key_file}", file=sys.stderr)
            sys.exit(1)

        try:
            wm_key = WatermarkKey.load_from_file(args.key_file)
            watermarker = DwtSvdWatermarker(alpha=wm_key.alpha, subband=wm_key.subband)
            extracted_logo = watermarker.extract(img_np, wm_key)

            out_logo_path = os.path.join(args.output_dir, "extracted_watermark_logo.png")
            Image.fromarray(extracted_logo).save(out_logo_path)
            print(f"[+] SUCCESS: Watermark logo reconstructed successfully!")
            print(f"    * Logo Dimensions: {extracted_logo.shape[1]}x{extracted_logo.shape[0]}")
            print(f"    * Output Saved:    {out_logo_path}")

            if args.watermark_ref is not None and os.path.exists(args.watermark_ref):
                ref_logo = np.array(Image.open(args.watermark_ref).convert("L"))
                nc_score = calculate_nc(ref_logo, extracted_logo)
                print(f"    * Watermark NC:    {nc_score:.4f}")
                if nc_score >= 0.85:
                    print(f"    * Ownership Status: VERIFIED VALID COPYRIGHT (NC >= 0.85)")
                else:
                    print(f"    * Ownership Status: DEGRADED WATERMARK (NC < 0.85)")
        except Exception as e:
            print(f"[-] FAILED: Watermark extraction failed: {e}")
    else:
        print("\n--> [2/2] Watermark extraction skipped (no --key-file provided).")

    print("\n[+] Extraction process finished.")


if __name__ == "__main__":
    main()

