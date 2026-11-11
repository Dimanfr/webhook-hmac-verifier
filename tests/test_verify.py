import hashlib
import hmac
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webhook_hmac_verifier import (  # noqa: E402
    MalformedHeader,
    NoMatchingSignature,
    TimestampOutOfTolerance,
    parse_header,
    sign,
    verify,
)

SECRET = b"test-secret-not-real"
OTHER_SECRET = b"another-test-secret"
BODY = b'{"event":"message.created","id":"evt_0001"}'
NOW = 1_800_000_000


def manual_signature(secret: bytes, ts: int, body: bytes) -> str:
    return hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()


class KnownVector(unittest.TestCase):
    def test_sign_matches_manual_hmac(self):
        header = sign(SECRET, BODY, timestamp=NOW)
        self.assertEqual(header, f"t={NOW},v1={manual_signature(SECRET, NOW, BODY)}")

    def test_fixed_vector(self):
        # Independent of sign(): computed once with the formula in the README.
        expected = manual_signature(b"whsec_demo", 1700000000, b"hello")
        header = f"t=1700000000,v1={expected}"
        result = verify(b"whsec_demo", b"hello", header, now=1700000000)
        self.assertEqual(result.timestamp, 1700000000)
        self.assertEqual(result.age_seconds, 0)


class Accepts(unittest.TestCase):
    def test_valid_signature(self):
        header = sign(SECRET, BODY, timestamp=NOW)
        self.assertEqual(verify(SECRET, BODY, header, now=NOW + 10).age_seconds, 10)

    def test_edge_of_window(self):
        header = sign(SECRET, BODY, timestamp=NOW)
        verify(SECRET, BODY, header, now=NOW + 300)
        verify(SECRET, BODY, header, now=NOW - 300)

    def test_rotation_second_signature_matches(self):
        good = manual_signature(SECRET, NOW, BODY)
        stale = manual_signature(OTHER_SECRET, NOW, BODY)
        header = f"t={NOW},v1={stale},v1={good}"
        verify(SECRET, BODY, header, now=NOW)

    def test_unknown_scheme_ignored(self):
        header = sign(SECRET, BODY, timestamp=NOW) + ",v0=deadbeef"
        verify(SECRET, BODY, header, now=NOW)

    def test_whitespace_and_uppercase_hex(self):
        sig = manual_signature(SECRET, NOW, BODY).upper()
        verify(SECRET, BODY, f" t={NOW} , v1={sig} ", now=NOW)

    def test_empty_body(self):
        header = sign(SECRET, b"", timestamp=NOW)
        verify(SECRET, b"", header, now=NOW)


class Rejects(unittest.TestCase):
    def test_wrong_secret(self):
        header = sign(OTHER_SECRET, BODY, timestamp=NOW)
        with self.assertRaises(NoMatchingSignature):
            verify(SECRET, BODY, header, now=NOW)

    def test_body_changed(self):
        header = sign(SECRET, BODY, timestamp=NOW)
        with self.assertRaises(NoMatchingSignature):
            verify(SECRET, BODY + b" ", header, now=NOW)

    def test_reencoded_json_is_rejected(self):
        # Parsing and re-serialising the JSON changes the bytes.
        header = sign(SECRET, BODY, timestamp=NOW)
        reencoded = b'{"event": "message.created", "id": "evt_0001"}'
        with self.assertRaises(NoMatchingSignature):
            verify(SECRET, reencoded, header, now=NOW)

    def test_timestamp_swapped(self):
        sig = manual_signature(SECRET, NOW, BODY)
        with self.assertRaises(NoMatchingSignature):
            verify(SECRET, BODY, f"t={NOW + 1},v1={sig}", now=NOW)

    def test_too_old(self):
        header = sign(SECRET, BODY, timestamp=NOW)
        with self.assertRaises(TimestampOutOfTolerance):
            verify(SECRET, BODY, header, now=NOW + 301)

    def test_too_far_in_future(self):
        header = sign(SECRET, BODY, timestamp=NOW)
        with self.assertRaises(TimestampOutOfTolerance):
            verify(SECRET, BODY, header, now=NOW - 301)

    def test_custom_tolerance(self):
        header = sign(SECRET, BODY, timestamp=NOW)
        with self.assertRaises(TimestampOutOfTolerance):
            verify(SECRET, BODY, header, now=NOW + 61, tolerance_seconds=60)

    def test_forged_signature_checked_before_time(self):
        header = f"t={NOW - 10_000},v1={'0' * 64}"
        with self.assertRaises(NoMatchingSignature):
            verify(SECRET, BODY, header, now=NOW)


class MalformedHeaders(unittest.TestCase):
    CASES = [
        "",
        "   ",
        "v1=" + "a" * 64,
        f"t={NOW}",
        f"t={NOW},v0=" + "a" * 64,
        f"t=abc,v1=" + "a" * 64,
        f"t=-5,v1=" + "a" * 64,
        "t=²³,v1=" + "a" * 64,
        f"t={NOW},t={NOW},v1=" + "a" * 64,
        f"t={NOW},v1=xyz",
        f"t={NOW},v1=" + "a" * 63,
        f"t={NOW},v1=" + "g" * 64,
        f"t={NOW},garbage,v1=" + "a" * 64,
        f"t={NOW},v1=",
        "t=1," + "v1=" + "a" * 64 + "," * 5000,
    ]

    def test_parse_rejects(self):
        for header in self.CASES:
            with self.subTest(header=header[:40]):
                with self.assertRaises(MalformedHeader):
                    parse_header(header)

    def test_verify_rejects_non_string(self):
        with self.assertRaises(MalformedHeader):
            verify(SECRET, BODY, None, now=NOW)  # type: ignore[arg-type]


class InputTypes(unittest.TestCase):
    def test_body_must_be_bytes(self):
        header = sign(SECRET, BODY, timestamp=NOW)
        with self.assertRaises(TypeError):
            verify(SECRET, BODY.decode(), header, now=NOW)  # type: ignore[arg-type]

    def test_secret_must_be_non_empty_bytes(self):
        with self.assertRaises(TypeError):
            sign(b"", BODY, timestamp=NOW)
        with self.assertRaises(TypeError):
            sign("text", BODY, timestamp=NOW)  # type: ignore[arg-type]

    def test_negative_tolerance(self):
        header = sign(SECRET, BODY, timestamp=NOW)
        with self.assertRaises(ValueError):
            verify(SECRET, BODY, header, now=NOW, tolerance_seconds=-1)


if __name__ == "__main__":
    unittest.main()
