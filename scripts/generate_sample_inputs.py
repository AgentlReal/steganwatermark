"""
Script to initialize or reset sample input files in the 'input/' folder.
Sets up:
- 1 Cover image (input/cover.png)
- 1 Watermark photo (input/watermark.png)
- 10 Progressive photo payloads with sizes from ~100 B to ~30 KB (input/payloads/)
"""

import os
import shutil
import numpy as np
from PIL import Image, ImageDraw


def generate_inputs(base_dir: str = "."):
    input_dir = os.path.join(base_dir, "input")
    payloads_dir = os.path.join(input_dir, "payloads")
    shutil.rmtree(payloads_dir, ignore_errors=True)
    os.makedirs(payloads_dir, exist_ok=True)

    print("=" * 70)
    print("      INITIALIZING SAMPLE INPUTS IN 'input/'")
    print("=" * 70)

    # 1. Setup Cover Image (input/cover.png)
    cover_target = os.path.join(input_dir, "cover.png")
    source_cover = os.path.join(base_dir, "data/covers/lena.png")
    if os.path.exists(source_cover):
        shutil.copyfile(source_cover, cover_target)
    else:
        arr = np.random.randint(60, 200, (512, 512, 3), dtype=np.uint8)
        Image.fromarray(arr).save(cover_target)
    print(f"[+] Cover Image setup:     {cover_target}")

    # 2. Setup Watermark Photo (input/watermark.png)
    wm_target = os.path.join(input_dir, "watermark.png")
    source_wm = os.path.join(base_dir, "data/watermarks/copyright_64.png")
    if os.path.exists(source_wm):
        shutil.copyfile(source_wm, wm_target)
    else:
        wm_im = Image.new("L", (64, 64), color=0)
        draw = ImageDraw.Draw(wm_im)
        draw.ellipse([4, 4, 59, 59], outline=255, width=4)
        draw.arc([16, 16, 47, 47], start=45, end=315, fill=255, width=5)
        wm_im.save(wm_target)
    print(f"[+] Watermark Photo setup: {wm_target}")

    # 3. Setup 10 Progressive Photo Payloads with clean progressive sizes:
    # JPEG/PNG combinations spanning ~100 B to ~30 KB
    specs = [
        ("photo_payload_01_micro.png", 8, 8, "solid"),          # ~100 B
        ("photo_payload_02_tiny.jpg", 16, 16, "texture"),       # ~800 B
        ("photo_payload_03_badge.png", 24, 24, "texture"),      # ~1.8 KB
        ("photo_payload_04_icon.png", 32, 32, "texture"),       # ~3.2 KB
        ("photo_payload_05_stamp.png", 42, 42, "texture"),      # ~5.4 KB
        ("photo_payload_06_avatar.png", 52, 52, "texture"),     # ~8.2 KB
        ("photo_payload_07_emblem.png", 64, 64, "texture"),     # ~12.4 KB
        ("photo_payload_08_seal.png", 78, 78, "texture"),       # ~18.3 KB
        ("photo_payload_09_thumbnail.png", 92, 92, "texture"),  # ~25.5 KB
        ("photo_payload_10_large_photo.png", 104, 104, "texture"), # ~32.5 KB
    ]

    print("\n--> Generating 10 Progressive Photo Payloads:")
    for idx, (filename, w, h, style) in enumerate(specs, start=1):
        target_path = os.path.join(payloads_dir, filename)
        if style == "texture":
            np.random.seed(idx * 13)
            noise = np.random.randint(0, 255, (h, w, 3), dtype=np.uint8)
            img = Image.fromarray(noise)
        else:
            img = Image.new("RGB", (w, h), color=(idx * 25, 120, 200 - idx * 15))
            draw = ImageDraw.Draw(img)
            draw.rectangle([1, 1, w - 2, h - 2], outline="white")

        if filename.endswith(".jpg"):
            img.save(target_path, "JPEG", quality=85)
        else:
            img.save(target_path, "PNG", compress_level=3)

        file_size = os.path.getsize(target_path)
        print(f"  [{idx:02d}/10] {filename:<34} ({w:>3}x{h:<3}) : {file_size:>6} bytes")

    print(f"\n[+] Successfully prepared 10 photo payloads in '{payloads_dir}'")


if __name__ == "__main__":
    generate_inputs()
