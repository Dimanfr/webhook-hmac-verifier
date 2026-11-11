"""Send one signed test event to the local example receiver."""

import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webhook_hmac_verifier import sign  # noqa: E402

secret = os.environ.get("WEBHOOK_SECRET", "demo-secret").encode()
body = b'{"event":"message.created","id":"evt_demo_1"}'
request = urllib.request.Request(
    "http://127.0.0.1:8787/webhook",
    data=body,
    headers={"Content-Type": "application/json", "X-Signature": sign(secret, body)},
    method="POST",
)
with urllib.request.urlopen(request) as response:
    print(response.status)
