# webhook-hmac-verifier

Verify that an incoming webhook really comes from the sender who shares your secret and was signed recently. One small Python module (standard library only) for HMAC-SHA256 signatures in the `t=<unix>,v1=<hex>` header format, with tests for the failure cases that matter.

## Why
In an AI messaging integration, a channel manager pushes guest-message events to a public endpoint. Anyone who finds that URL can post to it. Before an event may trigger an AI agent, the receiver has to prove two things:
- the sender holds the shared secret;
- the request is fresh.

The same check was needed in more than one integration, so here it is as a separate, tested piece.

## How it works
The sender computes

```
signature = hex( HMAC-SHA256( secret, "<t>" + "." + <raw request body> ) )
header    = "t=<t>,v1=<signature>"
```

The receiver (`verify`):
1. parses the header: exactly one `t`, one or more `v1`, unknown schemes ignored, length capped;
2. recomputes the HMAC over the **raw body bytes** and compares in constant time against every `v1` value (several values allow secret rotation);
3. only then checks that `t` is within ±300 seconds of the receiver's clock (configurable).

The signature is checked before the timestamp, so a forged request learns nothing about the time window.

```python
from webhook_hmac_verifier import verify, SignatureError

try:
    verify(secret, raw_body, request.headers["X-Signature"])
except SignatureError:
    return 401          # do not say which check failed
event = json.loads(raw_body)   # parse only after verification
```

`examples/receiver.py` is a runnable receiver built on `http.server`; `examples/send_test_event.py` sends it one signed event.

## Run the tests
```bash
python3 tests/test_verify.py -v
```
No dependencies, no network. 21 tests:
- a known vector;
- acceptance at the edges of the window;
- secret rotation;
- body tampering;
- re-encoded JSON;
- swapped timestamps;
- stale and future timestamps;
- 15 malformed headers;
- wrong input types.

## Status

| | |
|---|---|
| **Original use** | Signature check for channel-manager webhooks in a limited AI guest-messaging pilot (2026). In the pilot, inbound events came in by polling; the webhook path was implemented and tested against a simulator only |
| **This repository** | A clean re-implementation of that check as a standalone module, written for publication. Runnable, tested, version 0.1.0 |
| **Authorship** | I define requirements, coordinate AI coding agents, test behaviour and operate the resulting systems; the agents implement the code. |

## Limitations
- **No replay protection inside the window.** The same signed request is accepted again within ±300 s. To stop that, store each accepted `(t, signature)` or the event ID with an expiry at least as long as the window, and reject repeats. The store must survive restarts.
- **No idempotent processing.** A valid, fresh event can still be delivered twice by the sender. Deduplicate on the event ID in your own processing.
- **One header format.** Providers differ in header names, encodings and signed content. Check the provider's documentation before using this module for it.
- **Clock skew.** The receiver's clock must be roughly correct (NTP).
- The module does not read the request for you. Pass the exact bytes received, before any parsing.

## Licence
MIT
