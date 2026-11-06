#!/usr/bin/env python3
"""
GhostShare CLI — Deniable Covert Data Vault & Anti-Censorship Tool.

Usage:
  # 1. Pack secret file into cover image:
  python ghostshare_cli.py pack --cover input/cover.png --secret secret.pdf --secret-pass "AlphaPass!"

  # 2. Pack with Plausible Deniability (Real + Decoy):
  python ghostshare_cli.py pack --cover input/cover.png \
      --secret classified.pdf --secret-pass "RealPass!" \
      --decoy grocery.txt --decoy-pass "DecoyPass!" \
      --output output/carrier.png

  # 3. Unpack file using either password:
  python ghostshare_cli.py unpack --carrier output/carrier.png --passphrase "DecoyPass!"

  # 4. Forensic & Steganalysis Audit:
  python ghostshare_cli.py audit --carrier output/carrier.png --cover input/cover.png

  # 5. Check carrier capacity:
  python ghostshare_cli.py capacity --cover input/cover.png
"""

import argparse
import os
import sys
import numpy as np
from PIL import Image

from core.vault import GhostVault, GhostVaultError
from core.anti_steganalysis import run_full_audit


def load_image(filepath: str) -> np.ndarray:
    if not os.path.exists(filepath):
        print(f"[-] Error: Image file not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    img = Image.open(filepath)
    return np.array(img.convert("RGB"))


def save_image(image_arr: np.ndarray, filepath: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    img = Image.fromarray(image_arr.astype(np.uint8))
    # Must save as lossless PNG to protect steganographic bits
    if not filepath.lower().endswith(".png"):
        filepath = os.path.splitext(filepath)[0] + ".png"
    img.save(filepath, format="PNG", optimize=False)
    print(f"[+] Carrier saved: {filepath} ({os.path.getsize(filepath):,} bytes)")


def cmd_pack(args):
    cover_arr = load_image(args.cover)
    vault = GhostVault(channel=args.channel)

    if not os.path.exists(args.secret):
        print(f"[-] Error: Secret file not found: {args.secret}", file=sys.stderr)
        sys.exit(1)

    with open(args.secret, "rb") as f:
        secret_bytes = f.read()
    secret_fn = os.path.basename(args.secret)

    decoy_bytes = None
    decoy_fn = "decoy.bin"
    if args.decoy:
        if not os.path.exists(args.decoy):
            print(f"[-] Error: Decoy file not found: {args.decoy}", file=sys.stderr)
            sys.exit(1)
        if not args.decoy_pass:
            print("[-] Error: --decoy-pass is required when --decoy is provided.", file=sys.stderr)
            sys.exit(1)
        with open(args.decoy, "rb") as f:
            decoy_bytes = f.read()
        decoy_fn = os.path.basename(args.decoy)

    print("[*] Packaging payload into GhostShare vault...")
    try:
        carrier_arr, audit = vault.pack(
            cover_image=cover_arr,
            secret_payload=secret_bytes,
            secret_passphrase=args.secret_pass,
            secret_filename=secret_fn,
            decoy_payload=decoy_bytes,
            decoy_passphrase=args.decoy_pass,
            decoy_filename=decoy_fn,
        )
    except GhostVaultError as e:
        print(f"[-] Vault packaging failed: {e}", file=sys.stderr)
        sys.exit(1)

    out_path = args.output or "output/carrier.png"
    save_image(carrier_arr, out_path)

    print("\n" + "=" * 50)
    print("🛡️  GHOSTSHARE PACK REPORT")
    print("=" * 50)
    print(f"Mode               : {audit['mode'].upper()}")
    print(f"Secret File        : {secret_fn} ({len(secret_bytes):,} bytes)")
    if decoy_bytes is not None:
        print(f"Decoy File         : {decoy_fn} ({len(decoy_bytes):,} bytes)")
    print(f"PSNR Fidelity      : {audit['psnr_db']:.2f} dB (Imperceptible > 45 dB)")
    print(f"SSIM Structural    : {audit['ssim']:.4f}")
    print(f"Chi-Square p-value : {audit['chi2_p_value']:.4f} (Normal p >= 0.05)")
    print(f"Stealth Safety     : {audit['stealth_score']}%")
    print(f"Security Verdict   : {audit['verdict']}")
    print("=" * 50)


def cmd_unpack(args):
    carrier_arr = load_image(args.carrier)
    vault = GhostVault(channel=args.channel)

    print("[*] Authenticating and extracting payload from carrier...")
    try:
        extracted = vault.unpack(carrier_arr, args.passphrase)
    except GhostVaultError as e:
        print(f"[-] Extraction failed: {e}", file=sys.stderr)
        sys.exit(1)

    out_dir = args.out_dir or "output/recovered"
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, extracted.filename)

    with open(out_file, "wb") as f:
        f.write(extracted.payload_bytes)

    print("\n" + "=" * 50)
    print("🔓 GHOSTSHARE UNPACK SUCCESS")
    print("=" * 50)
    print(f"Extracted File     : {extracted.filename}")
    print(f"MIME Type          : {extracted.mime_type}")
    print(f"Size               : {extracted.size_bytes:,} bytes")
    print(f"Saved To           : {out_file}")
    print(f"Partition Slot     : {extracted.partition_mode}")
    print("=" * 50)


def cmd_audit(args):
    carrier_arr = load_image(args.carrier)
    cover_arr = load_image(args.cover) if args.cover else None

    print("[*] Running forensic & steganalysis audit...")
    audit = run_full_audit(cover_arr, carrier_arr)

    print("\n" + "=" * 50)
    print("🔬 GHOSTSHARE FORENSIC AUDIT REPORT")
    print("=" * 50)
    if cover_arr is not None:
        print(f"PSNR Fidelity      : {audit['psnr_db']:.2f} dB")
        print(f"SSIM Structural    : {audit['ssim']:.4f}")
        print(f"MSE Distortion     : {audit['mse']:.4f}")
        print(f"Max Pixel Delta    : {audit['max_pixel_delta']} (Expected <= 1 for LSB Matching)")
    print(f"Chi-Square Stat    : {audit['chi2_stat']:.2f}")
    print(f"Chi-Square p-value : {audit['chi2_p_value']:.4f}")
    print(f"Detection Conf.    : {audit['detection_confidence'] * 100:.1f}%")
    print(f"Stealth Safety     : {audit['stealth_score']}%")
    print(f"Verdict            : {audit['verdict']}")
    print("=" * 50)


def cmd_capacity(args):
    cover_arr = load_image(args.cover)
    vault = GhostVault(channel=args.channel)
    caps = vault.get_capacity_info(cover_arr.shape)

    print("\n" + "=" * 50)
    print(f"📊 CARRIER CAPACITY: {args.cover} ({cover_arr.shape[1]}x{cover_arr.shape[0]} px)")
    print("=" * 50)
    print(f"Total Available Bits        : {caps['total_pixels']:,} bits")
    print(f"Single Payload Max Usable   : {caps['single_payload_max_bytes']:,} bytes ({caps['single_payload_max_bytes'] / 1024:.1f} KB)")
    print(f"Dual Payload Max Each (x2)  : {caps['dual_payload_max_bytes_each']:,} bytes ({caps['dual_payload_max_bytes_each'] / 1024:.1f} KB each)")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="GhostShare: Deniable Covert Data Vault & Anti-Censorship System"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sub-command: pack
    p_pack = subparsers.add_parser("pack", help="Pack secret file into cover image")
    p_pack.add_argument("--cover", required=True, help="Path to input cover image (PNG/JPG)")
    p_pack.add_argument("--secret", required=True, help="Path to secret file to hide")
    p_pack.add_argument("--secret-pass", required=True, help="Passphrase for secret file")
    p_pack.add_argument("--decoy", help="Optional path to decoy file (Plausible Deniability)")
    p_pack.add_argument("--decoy-pass", help="Passphrase for decoy file")
    p_pack.add_argument("--output", help="Path to save output carrier PNG (default: output/carrier.png)")
    p_pack.add_argument("--channel", type=int, default=None, help="Target channel (default: all channels)")
    p_pack.set_defaults(func=cmd_pack)

    # Sub-command: unpack
    p_unpack = subparsers.add_parser("unpack", help="Unpack secret file from carrier image")
    p_unpack.add_argument("--carrier", required=True, help="Path to carrier image (PNG)")
    p_unpack.add_argument("--passphrase", required=True, help="Passphrase (Secret or Decoy)")
    p_unpack.add_argument("--out-dir", help="Directory to save extracted file (default: output/recovered)")
    p_unpack.add_argument("--channel", type=int, default=None, help="Target channel (default: all channels)")
    p_unpack.set_defaults(func=cmd_unpack)

    # Sub-command: audit
    p_audit = subparsers.add_parser("audit", help="Run forensic steganalysis on carrier image")
    p_audit.add_argument("--carrier", required=True, help="Path to carrier image (PNG)")
    p_audit.add_argument("--cover", help="Optional path to original cover image")
    p_audit.set_defaults(func=cmd_audit)

    # Sub-command: capacity
    p_cap = subparsers.add_parser("capacity", help="Check maximum payload capacity of a cover image")
    p_cap.add_argument("--cover", required=True, help="Path to cover image")
    p_cap.add_argument("--channel", type=int, default=None, help="Target channel")
    p_cap.set_defaults(func=cmd_capacity)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
