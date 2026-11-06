"""
Unit tests for GhostShare Web Application (Starlette ASGI).
Tests routes, HTML serving, API endpoints, and multipart form processing.
"""

import asyncio
import base64
import json
import unittest
from app import app


def run_asgi_request(method: str, path: str, headers=None, body: bytes = b""):
    """Helper to execute an HTTP request against the ASGI application in-memory."""
    if headers is None:
        headers = []

    raw_headers = [(k.lower().encode("latin1"), v.encode("latin1")) for k, v in headers]

    scope = {
        "type": "http",
        "method": method.upper(),
        "path": path,
        "headers": raw_headers,
    }

    response_body = []
    response_status = None
    response_headers = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        nonlocal response_status, response_headers
        if message["type"] == "http.response.start":
            response_status = message["status"]
            response_headers = message.get("headers", [])
        elif message["type"] == "http.response.body":
            response_body.append(message.get("body", b""))

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(app(scope, receive, send))
    finally:
        loop.close()

    return response_status, b"".join(response_body), response_headers


def build_multipart_payload(fields, files, boundary="----GhostShareBoundary7MA4"):
    """Encodes fields and files into multipart/form-data payload."""
    lines = []
    for name, value in fields.items():
        lines.append(f"--{boundary}".encode())
        lines.append(f'Content-Disposition: form-data; name="{name}"\r\n'.encode())
        lines.append(str(value).encode())

    for name, (filename, content, mime) in files.items():
        lines.append(f"--{boundary}".encode())
        lines.append(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode())
        lines.append(f'Content-Type: {mime}\r\n'.encode())
        lines.append(content)

    lines.append(f"--{boundary}--\r\n".encode())
    body = b"\r\n".join(lines)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


class TestWebAPI(unittest.TestCase):

    def test_health_endpoints(self):
        """Test health check endpoints."""
        status, body, _ = run_asgi_request("GET", "/health")
        self.assertEqual(status, 200)
        data = json.loads(body.decode())
        self.assertEqual(data["status"], "healthy")

        status2, body2, _ = run_asgi_request("GET", "/_stcore/health")
        self.assertEqual(status2, 200)

    def test_root_index_html(self):
        """Test root serves HTML with modern UI components."""
        status, body, _ = run_asgi_request("GET", "/")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn("GHOSTSHARE VAULT", html)
        self.assertIn("tab-pack", html)
        self.assertIn("tab-unpack", html)
        self.assertIn("tab-audit", html)
        self.assertIn("Interactive Before / After Swipe Comparator", html)

    def test_api_capacity(self):
        """Test capacity calculation endpoint with preset."""
        body, ct = build_multipart_payload({"preset": "Cover Sample (1024x1024)"}, {})
        status, body_resp, _ = run_asgi_request("POST", "/api/capacity", headers=[("content-type", ct)], body=body)

        self.assertEqual(status, 200)
        data = json.loads(body_resp.decode())
        self.assertIn("total_pixels", data)
        self.assertIn("single_payload_max_bytes", data)
        self.assertGreater(data["single_payload_max_bytes"], 100000)

    def test_api_pack_and_unpack_flow(self):
        """End-to-end Web API test: Pack via /api/pack then Unpack via /api/unpack."""
        secret_content = b"TOP_SECRET_WEB_API_FILE_DATA_2026"
        secret_pass = "WebSecretPassphrase123!"

        # 1. Pack
        fields = {
            "preset": "Lena (512x512)",
            "secret_pass": secret_pass,
        }
        files = {
            "secret_file": ("classified.txt", secret_content, "text/plain"),
        }
        body, ct = build_multipart_payload(fields, files)
        status, resp_bytes, _ = run_asgi_request("POST", "/api/pack", headers=[("content-type", ct)], body=body)

        self.assertEqual(status, 200)
        pack_data = json.loads(resp_bytes.decode())
        self.assertTrue(pack_data["success"])
        self.assertIn("carrier_url", pack_data)
        self.assertIn("audit", pack_data)
        self.assertGreater(pack_data["audit"]["psnr_db"], 45.0)

        # 2. Decode carrier from data URL
        carrier_data_url = pack_data["carrier_url"]
        b64_img = carrier_data_url.split(",")[1]
        carrier_png_bytes = base64.b64decode(b64_img)

        # 3. Unpack via /api/unpack
        unpack_fields = {"passphrase": secret_pass}
        unpack_files = {"carrier_file": ("carrier.png", carrier_png_bytes, "image/png")}
        up_body, up_ct = build_multipart_payload(unpack_fields, unpack_files)
        status_up, up_resp_bytes, _ = run_asgi_request("POST", "/api/unpack", headers=[("content-type", up_ct)], body=up_body)

        self.assertEqual(status_up, 200)
        unpack_data = json.loads(up_resp_bytes.decode())
        self.assertTrue(unpack_data["success"])
        self.assertEqual(unpack_data["filename"], "classified.txt")
        self.assertEqual(unpack_data["text_content"], secret_content.decode())

        # 4. Audit via /api/audit
        audit_fields = {}
        audit_files = {"carrier_file": ("carrier.png", carrier_png_bytes, "image/png")}
        aud_body, aud_ct = build_multipart_payload(audit_fields, audit_files)
        status_aud, aud_resp_bytes, _ = run_asgi_request("POST", "/api/audit", headers=[("content-type", aud_ct)], body=aud_body)

        self.assertEqual(status_aud, 200)
        aud_data = json.loads(aud_resp_bytes.decode())
        self.assertTrue(aud_data["success"])
        self.assertIn("stealth_score", aud_data)


if __name__ == "__main__":
    unittest.main()
