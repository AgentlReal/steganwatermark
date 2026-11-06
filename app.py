"""
GhostShare Web Vault — High-Performance Starlette ASGI Application.
Provides modern, zero-flicker UI and REST API for covert data packing,
unpacking, capacity calculation, and forensic steganalysis.
"""

import base64
import io
import os
import sys
from typing import Optional
import numpy as np
from PIL import Image

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, Response, FileResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
import uvicorn

from core.vault import GhostVault, GhostVaultError
from core.anti_steganalysis import run_full_audit, compute_amplified_residual


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
PRESET_MAP = {
    "Cover Sample (1024x1024)": "input/cover.png",
    "Lena (512x512)": "data/covers/lena.png",
    "Peppers (512x512)": "data/covers/peppers.png",
    "Baboon (512x512)": "data/covers/baboon.png",
    "Airplane (512x512)": "data/covers/airplane.png",
}

vault = GhostVault()


def image_to_base64_data_url(image_arr: np.ndarray, format: str = "PNG") -> str:
    """Encodes NumPy uint8 image array to data:image/png;base64 string."""
    pil_img = Image.fromarray(image_arr.astype(np.uint8))
    buf = io.BytesIO()
    pil_img.save(buf, format=format)
    b64_str = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/{format.lower()};base64,{b64_str}"


def bytes_to_data_url(data_bytes: bytes, mime_type: str = "application/octet-stream") -> str:
    """Encodes arbitrary bytes to data URL."""
    b64_str = base64.b64encode(data_bytes).decode("ascii")
    return f"data:{mime_type};base64,{b64_str}"


def read_image_from_upload(upload_file) -> np.ndarray:
    """Reads uploaded image file into RGB numpy array."""
    data = upload_file.file.read()
    pil_img = Image.open(io.BytesIO(data))
    return np.array(pil_img.convert("RGB"))


def read_preset_image(preset_name: str) -> np.ndarray:
    """Loads a preset image into RGB numpy array."""
    path = PRESET_MAP.get(preset_name, "input/cover.png")
    if not os.path.exists(path):
        path = "input/cover.png"
    pil_img = Image.open(path)
    return np.array(pil_img.convert("RGB"))


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
async def index_view(request):
    """Serves the Single-Page Application."""
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    with open(template_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(html_content)


async def favicon_view(request):
    """Serves the application favicon."""
    fav_path = os.path.join(os.path.dirname(__file__), "static", "favicon.ico")
    if os.path.exists(fav_path):
        return FileResponse(fav_path, media_type="image/x-icon")
    return Response(status_code=404)


async def health_check(request):
    """Health check endpoint for Docker / orchestration."""
    return JSONResponse({"status": "healthy", "service": "ghostshare-vault", "version": "2.0.0"})


async def api_capacity(request):
    """Calculates available payload capacity in bytes for a given cover or preset."""
    form = await request.form()
    
    if "cover_file" in form and form["cover_file"].filename:
        cover_arr = read_image_from_upload(form["cover_file"])
    elif "preset" in form:
        cover_arr = read_preset_image(str(form["preset"]))
    else:
        cover_arr = read_preset_image("Cover Sample (1024x1024)")

    caps = vault.get_capacity_info(cover_arr.shape)
    caps["width"] = int(cover_arr.shape[1])
    caps["height"] = int(cover_arr.shape[0])
    return JSONResponse(caps)


async def api_pack(request):
    """
    Encrypts and embeds secret (and optional decoy) into cover image.
    Returns audit metrics and carrier base64 data URL.
    """
    form = await request.form()

    # Load cover
    if "cover_file" in form and form["cover_file"].filename:
        cover_arr = read_image_from_upload(form["cover_file"])
    elif "preset" in form:
        cover_arr = read_preset_image(str(form["preset"]))
    else:
        cover_arr = read_preset_image("Cover Sample (1024x1024)")

    # Secret payload
    if "secret_file" not in form or not form["secret_file"].filename:
        return JSONResponse({"detail": "Secret file is required."}, status_code=400)
    
    secret_pass = form.get("secret_pass", "").strip()
    if not secret_pass:
        return JSONResponse({"detail": "Secret passphrase cannot be empty."}, status_code=400)

    secret_file = form["secret_file"]
    secret_bytes = secret_file.file.read()
    secret_fn = secret_file.filename

    # Decoy payload (optional)
    decoy_bytes = None
    decoy_fn = "decoy.bin"
    decoy_pass = None

    if "decoy_file" in form and form["decoy_file"].filename:
        decoy_file = form["decoy_file"]
        decoy_bytes = decoy_file.file.read()
        decoy_fn = decoy_file.filename
        decoy_pass = form.get("decoy_pass", "").strip()

        if not decoy_pass:
            return JSONResponse({"detail": "Decoy passphrase is required when decoy file is provided."}, status_code=400)
        if decoy_pass == secret_pass:
            return JSONResponse({"detail": "Decoy passphrase must be different from Secret passphrase."}, status_code=400)

    try:
        carrier_arr, audit = vault.pack(
            cover_image=cover_arr,
            secret_payload=secret_bytes,
            secret_passphrase=secret_pass,
            secret_filename=secret_fn,
            decoy_payload=decoy_bytes,
            decoy_passphrase=decoy_pass,
            decoy_filename=decoy_fn,
        )

        carrier_data_url = image_to_base64_data_url(carrier_arr, format="PNG")

        return JSONResponse({
            "success": True,
            "audit": audit,
            "carrier_url": carrier_data_url,
        })
    except GhostVaultError as e:
        return JSONResponse({"detail": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"detail": f"Internal packing error: {str(e)}"}, status_code=500)


async def api_unpack(request):
    """
    Unpacks payload corresponding to provided passphrase.
    Returns extracted file metadata, download URL, and optional text preview.
    """
    form = await request.form()

    if "carrier_file" not in form or not form["carrier_file"].filename:
        return JSONResponse({"detail": "Carrier image file is required."}, status_code=400)

    passphrase = form.get("passphrase", "").strip()
    if not passphrase:
        return JSONResponse({"detail": "Passphrase is required."}, status_code=400)

    carrier_arr = read_image_from_upload(form["carrier_file"])

    try:
        extracted = vault.unpack(carrier_arr, passphrase)
        download_url = bytes_to_data_url(extracted.payload_bytes, extracted.mime_type)

        is_text = extracted.mime_type.startswith("text/")
        text_content = ""
        if is_text:
            text_content = extracted.payload_bytes.decode("utf-8", errors="replace")

        return JSONResponse({
            "success": True,
            "filename": extracted.filename,
            "mime_type": extracted.mime_type,
            "size_bytes": extracted.size_bytes,
            "partition_mode": extracted.partition_mode,
            "download_url": download_url,
            "is_text": is_text,
            "text_content": text_content[:5000],  # preview up to 5KB
        })
    except GhostVaultError as e:
        return JSONResponse({"detail": str(e)}, status_code=401)
    except Exception as e:
        return JSONResponse({"detail": f"Extraction error: {str(e)}"}, status_code=500)


async def api_audit(request):
    """
    Executes forensic and steganalysis audit on a carrier image.
    Generates Before/After and Residual visualizations.
    """
    form = await request.form()

    if "carrier_file" not in form or not form["carrier_file"].filename:
        return JSONResponse({"detail": "Carrier image is required for audit."}, status_code=400)

    carrier_arr = read_image_from_upload(form["carrier_file"])
    cover_arr = None

    if "cover_file" in form and form["cover_file"].filename:
        cover_arr = read_image_from_upload(form["cover_file"])

    try:
        report = run_full_audit(cover_arr, carrier_arr)

        res_payload = {
            "success": True,
            "stealth_score": report["stealth_score"],
            "chi2_p_value": report["chi2_p_value"],
            "chi2_stat": report["chi2_stat"],
            "detection_confidence": report["detection_confidence"],
            "verdict": report["verdict"],
            "is_secure": report["is_secure"],
            "lsb_entropy": report["lsb_entropy"],
        }

        if cover_arr is not None:
            res_payload["psnr_db"] = report.get("psnr_db")
            res_payload["ssim"] = report.get("ssim")
            res_payload["mse"] = report.get("mse")
            res_payload["max_pixel_delta"] = report.get("max_pixel_delta")

            # Generate Before/After Data URLs
            res_payload["cover_url"] = image_to_base64_data_url(cover_arr, format="PNG")
            res_payload["carrier_url"] = image_to_base64_data_url(carrier_arr, format="PNG")

            # Compute Amplified Residual
            residual_arr = compute_amplified_residual(cover_arr, carrier_arr, factor=25.0)
            res_payload["residual_url"] = image_to_base64_data_url(residual_arr, format="PNG")

        return JSONResponse(res_payload)
    except Exception as e:
        return JSONResponse({"detail": f"Audit error: {str(e)}"}, status_code=500)


# -----------------------------------------------------------------------------
# Application Setup & Routing
# -----------------------------------------------------------------------------
routes = [
    Route("/", endpoint=index_view, methods=["GET"]),
    Route("/favicon.ico", endpoint=favicon_view, methods=["GET"]),
    Route("/health", endpoint=health_check, methods=["GET"]),
    Route("/_stcore/health", endpoint=health_check, methods=["GET"]),
    Route("/api/capacity", endpoint=api_capacity, methods=["POST"]),
    Route("/api/pack", endpoint=api_pack, methods=["POST"]),
    Route("/api/unpack", endpoint=api_unpack, methods=["POST"]),
    Route("/api/audit", endpoint=api_audit, methods=["POST"]),
    Mount("/static", app=StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static"),
]

middleware = [
    Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]),
]

app = Starlette(debug=False, routes=routes, middleware=middleware)


# -----------------------------------------------------------------------------
# Standalone Runner
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8501))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[*] Launching GhostShare Web Vault on http://{host}:{port} ...")
    uvicorn.run(app, host=host, port=port, log_level="info")
