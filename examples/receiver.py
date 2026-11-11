"""Minimal webhook receiver using only the standard library.

Run:
    WEBHOOK_SECRET=demo-secret python3 examples/receiver.py
Then, in another terminal:
    python3 examples/send_test_event.py

The receiver reads the raw body, verifies it, and only then parses JSON.
It answers 401 on any verification failure without saying which check failed.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webhook_hmac_verifier import SignatureError, verify  # noqa: E402

SECRET = os.environ.get("WEBHOOK_SECRET", "").encode()
HEADER = "X-Signature"
MAX_BODY = 1_000_000


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self.send_error(413)
            return
        raw = self.rfile.read(length)
        try:
            verify(SECRET, raw, self.headers.get(HEADER, ""))
        except SignatureError:
            self.send_error(401)
            return
        event = json.loads(raw)
        print("accepted event:", event.get("id"))
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    if not SECRET:
        sys.exit("set WEBHOOK_SECRET")
    HTTPServer(("127.0.0.1", 8787), Handler).serve_forever()
