"""Unit tests for the Codex OAuth provider (CodexOAuth.md §9).

All external calls are mocked; no real tokens or network are used.
"""

import base64
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services.codex_oauth import auth, browser_login, client, constants, device_code
from app.services.codex_oauth.errors import (
    CodexAuthRequiredError,
    CodexConfigError,
    CodexRefreshError,
    CodexUsageLimitError,
)
from app.services.codex_oauth.token_store import (
    Credentials,
    TokenStore,
    decode_jwt_exp,
)


def make_jwt(exp):
    """Build an unsigned JWT-shaped token carrying the given exp claim."""
    def b64(obj):
        raw = json.dumps(obj).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{b64({'alg': 'none'})}.{b64({'exp': exp})}.sig"


class FakeResponse:
    def __init__(self, status_code=200, json_body=None, text="", headers=None, sse_lines=None):
        self.status_code = status_code
        self._json = json_body
        self.text = text or (json.dumps(json_body) if json_body is not None else "")
        self.headers = headers or {}
        self._sse_lines = sse_lines or []

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json

    def iter_lines(self, decode_unicode=False):
        for line in self._sse_lines:
            yield line


def sse(*events, as_bytes=False):
    """Build SSE 'data: {...}' lines from event dicts."""
    lines = [f"data: {json.dumps(e)}" for e in events]
    return [line.encode("utf-8") for line in lines] if as_bytes else lines


class TokenStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sub", "codex_auth.json")
        self.store = TokenStore(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_save_load_roundtrip(self):
        exp = int(time.time()) + 3600
        creds = Credentials(
            access_token=make_jwt(exp),
            refresh_token="r1",
            account_id="acct-1",
        )
        saved = self.store.save(creds)
        # expires_at is derived from the JWT during save.
        self.assertEqual(saved.expires_at, exp)

        loaded = self.store.load()
        self.assertEqual(loaded.access_token, creds.access_token)
        self.assertEqual(loaded.refresh_token, "r1")
        self.assertEqual(loaded.account_id, "acct-1")
        self.assertEqual(loaded.expires_at, exp)

    @unittest.skipIf(sys.platform == "win32", "POSIX permission semantics only")
    def test_saved_file_is_owner_only(self):
        self.store.save(Credentials(access_token="a", refresh_token="r"))
        mode = os.stat(self.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_load_missing_returns_none(self):
        self.assertIsNone(self.store.load())

    def test_load_corrupt_raises(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fp:
            fp.write("{not json")
        with self.assertRaises(CodexConfigError):
            self.store.load()

    def test_quarantine_marks_dead(self):
        self.store.save(Credentials(access_token="a", refresh_token="r"))
        updated = self.store.quarantine("invalid_grant")
        self.assertTrue(updated.quarantined)
        self.assertEqual(updated.quarantine_reason, "invalid_grant")
        self.assertTrue(self.store.load().quarantined)

    def test_secret_safe_repr(self):
        creds = Credentials(access_token="supersecret", refresh_token="alsosecret")
        text = repr(creds)
        self.assertNotIn("supersecret", text)
        self.assertNotIn("alsosecret", text)


class ExpiryTests(unittest.TestCase):
    def test_decode_jwt_exp(self):
        self.assertEqual(decode_jwt_exp(make_jwt(123456)), 123456)
        self.assertIsNone(decode_jwt_exp("opaque-token"))
        self.assertIsNone(decode_jwt_exp(None))

    def test_is_expired_boundaries(self):
        now = 1_000_000
        # exp well in the future -> not expired.
        fresh = Credentials(access_token="t", expires_at=now + 1000)
        self.assertFalse(fresh.is_expired(now=now))
        # within the skew window -> expired.
        edge = Credentials(access_token="t", expires_at=now + constants.EXPIRY_SKEW_SECONDS - 1)
        self.assertTrue(edge.is_expired(now=now))
        # no token -> expired.
        self.assertTrue(Credentials().is_expired(now=now))
        # no exp but recent last_refresh -> not expired.
        recent = Credentials(access_token="t", last_refresh=now)
        self.assertFalse(recent.is_expired(now=now))


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TokenStore(os.path.join(self.tmp.name, "store.json"))

    def tearDown(self):
        self.tmp.cleanup()

    def _write_auth(self, payload):
        path = os.path.join(self.tmp.name, "auth.json")
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp)
        return path

    def test_import_nested_tokens(self):
        path = self._write_auth({
            "tokens": {
                "access_token": make_jwt(int(time.time()) + 3600),
                "refresh_token": "refresh-1",
                "account_id": "acct-9",
            },
            "last_refresh": "2025-01-01T00:00:00Z",
        })
        creds = auth.import_codex_cli_credentials(path, self.store)
        self.assertEqual(creds.refresh_token, "refresh-1")
        self.assertEqual(creds.account_id, "acct-9")
        # persisted into the store.
        self.assertEqual(self.store.load().refresh_token, "refresh-1")

    def test_import_flat_tokens(self):
        path = self._write_auth({
            "access_token": "a-flat",
            "refresh_token": "r-flat",
        })
        creds = auth.import_codex_cli_credentials(path, self.store)
        self.assertEqual(creds.access_token, "a-flat")
        self.assertEqual(creds.refresh_token, "r-flat")

    def test_import_missing_file_requires_auth(self):
        with self.assertRaises(CodexAuthRequiredError):
            auth.import_codex_cli_credentials(
                os.path.join(self.tmp.name, "nope.json"), self.store
            )

    def test_import_empty_payload_raises(self):
        path = self._write_auth({"tokens": {}})
        with self.assertRaises(CodexConfigError):
            auth.import_codex_cli_credentials(path, self.store)


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TokenStore(os.path.join(self.tmp.name, "store.json"))
        self.store.save(Credentials(access_token="old", refresh_token="r-old", account_id="acct"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_refresh_success_rotates_tokens(self):
        new_access = make_jwt(int(time.time()) + 3600)
        resp = FakeResponse(200, {"access_token": new_access, "refresh_token": "r-new"})
        with mock.patch.object(auth.requests, "post", return_value=resp):
            creds = auth.refresh(self.store.load(), self.store, settings={})
        self.assertEqual(creds.access_token, new_access)
        self.assertEqual(creds.refresh_token, "r-new")
        self.assertFalse(creds.quarantined)

    def test_refresh_terminal_quarantines(self):
        resp = FakeResponse(400, {"error": "invalid_grant"})
        with mock.patch.object(auth.requests, "post", return_value=resp):
            with self.assertRaises(CodexRefreshError) as ctx:
                auth.refresh(self.store.load(), self.store, settings={})
        self.assertTrue(ctx.exception.terminal)
        self.assertTrue(self.store.load().quarantined)

    def test_refresh_transient_not_terminal(self):
        resp = FakeResponse(503, text="upstream down")
        with mock.patch.object(auth.requests, "post", return_value=resp):
            with self.assertRaises(CodexRefreshError) as ctx:
                auth.refresh(self.store.load(), self.store, settings={})
        self.assertFalse(ctx.exception.terminal)
        self.assertFalse(self.store.load().quarantined)

    def test_get_valid_access_token_quarantined_blocks(self):
        self.store.quarantine("invalid_grant")
        with self.assertRaises(CodexAuthRequiredError):
            auth.get_valid_access_token(self.store, settings={})


class UrlValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TokenStore(os.path.join(self.tmp.name, "store.json"))
        self.store.save(Credentials(
            access_token=make_jwt(int(time.time()) + 3600),
            refresh_token="r",
        ))

    def tearDown(self):
        self.tmp.cleanup()

    def test_http_base_url_rejected(self):
        with self.assertRaises(CodexConfigError):
            client.generate_text(
                "hi", settings={"base_url": "http://evil.example.com"}, store=self.store
            )

    def test_http_token_url_rejected_on_refresh(self):
        expired = Credentials(access_token="", refresh_token="r")
        with self.assertRaises(CodexConfigError):
            auth.refresh(expired, self.store, settings={"token_url": "http://evil.example.com/t"})


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TokenStore(os.path.join(self.tmp.name, "store.json"))
        self.store.save(Credentials(
            access_token=make_jwt(int(time.time()) + 3600),
            refresh_token="r",
            account_id="acct",
        ))
        # Make backoff instant.
        self._sleep_patch = mock.patch.object(client.time, "sleep", lambda *_: None)
        self._sleep_patch.start()

    def tearDown(self):
        self._sleep_patch.stop()
        self.tmp.cleanup()

    def test_200_output_text_non_stream(self):
        resp = FakeResponse(200, {"output_text": "hello world"})
        with mock.patch.object(client.requests, "post", return_value=resp):
            out = client.generate_text("hi", settings={"stream": False}, store=self.store)
        self.assertEqual(out, "hello world")

    def test_200_structured_output_non_stream(self):
        body = {"output": [{"content": [{"type": "output_text", "text": "abc"}]}]}
        resp = FakeResponse(200, body)
        with mock.patch.object(client.requests, "post", return_value=resp):
            out = client.generate_text("hi", settings={"stream": False}, store=self.store)
        self.assertEqual(out, "abc")

    def test_200_streaming_deltas(self):
        resp = FakeResponse(200, sse_lines=sse(
            {"type": "response.output_text.delta", "delta": "Hello "},
            {"type": "response.output_text.delta", "delta": "world"},
            {"type": "response.completed", "response": {}},
        ))
        with mock.patch.object(client.requests, "post", return_value=resp):
            out = client.generate_text("hi", settings={}, store=self.store)
        self.assertEqual(out, "Hello world")

    def test_200_streaming_bytes_lines(self):
        # requests yields bytes for text/event-stream; the parser must decode.
        resp = FakeResponse(200, sse_lines=sse(
            {"type": "response.output_text.delta", "delta": "byte "},
            {"type": "response.output_text.delta", "delta": "stream"},
            {"type": "response.completed", "response": {}},
            as_bytes=True,
        ))
        with mock.patch.object(client.requests, "post", return_value=resp):
            out = client.generate_text("hi", settings={}, store=self.store)
        self.assertEqual(out, "byte stream")

    def test_401_refreshes_once_then_succeeds(self):
        # client.requests and auth.requests are the SAME module object, so a
        # single patch with an ordered side-effect models the full sequence:
        #   client POST -> 401, auth.refresh POST -> 200, client retry -> 200.
        new_access = make_jwt(int(time.time()) + 3600)
        post_responses = [
            FakeResponse(401, text="unauthorized"),
            FakeResponse(200, {"access_token": new_access}),
            FakeResponse(200, {"output_text": "ok"}),
        ]
        with mock.patch.object(client.requests, "post", side_effect=post_responses):
            out = client.generate_text("hi", settings={"stream": False}, store=self.store)
        self.assertEqual(out, "ok")

    def test_429_usage_limit_no_retry(self):
        resp = FakeResponse(429, text="You have hit your usage limit")
        post = mock.Mock(return_value=resp)
        with mock.patch.object(client.requests, "post", post):
            with self.assertRaises(CodexUsageLimitError):
                client.generate_text("hi", settings={"stream": False}, store=self.store)
        # Called exactly once: no retry on a hard usage limit.
        self.assertEqual(post.call_count, 1)

    def test_400_surfaces_body(self):
        resp = FakeResponse(400, text='{"error":{"message":"Invalid model"}}')
        with mock.patch.object(client.requests, "post", return_value=resp):
            with self.assertRaises(client.CodexError) as ctx:
                client.generate_text("hi", settings={"stream": False}, store=self.store)
        self.assertIn("Invalid model", str(ctx.exception))

    def test_account_id_header_sent(self):
        resp = FakeResponse(200, {"output_text": "x"})
        post = mock.Mock(return_value=resp)
        with mock.patch.object(client.requests, "post", post):
            client.generate_text("hi", settings={"stream": False}, store=self.store)
        _, kwargs = post.call_args
        self.assertEqual(kwargs["headers"]["chatgpt-account-id"], "acct")
        self.assertTrue(kwargs["headers"]["Authorization"].startswith("Bearer "))
        self.assertEqual(kwargs["headers"]["originator"], "codex_cli_rs")


class DeviceCodeTests(unittest.TestCase):
    def test_poll_pending_then_success(self):
        new_access = make_jwt(int(time.time()) + 3600)
        responses = [
            FakeResponse(400, {"error": "authorization_pending"}),
            FakeResponse(400, {"error": "slow_down"}),
            FakeResponse(200, {"access_token": new_access, "refresh_token": "r"}),
        ]
        sleeps = []
        with mock.patch.object(device_code.requests, "post", side_effect=responses):
            creds = device_code.poll_for_token(
                "dev-code",
                settings={},
                interval=1,
                sleeper=sleeps.append,
                now=lambda: 0.0,
            )
        self.assertEqual(creds.access_token, new_access)
        # slow_down should have increased the interval.
        self.assertGreater(sleeps[-1], sleeps[0])

    def test_poll_access_denied_terminal(self):
        with mock.patch.object(
            device_code.requests, "post",
            return_value=FakeResponse(400, {"error": "access_denied"}),
        ):
            with self.assertRaises(CodexAuthRequiredError):
                device_code.poll_for_token(
                    "dev-code", settings={}, sleeper=lambda *_: None, now=lambda: 0.0
                )


class BrowserLoginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TokenStore(os.path.join(self.tmp.name, "store.json"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_pkce_pair_matches_s256(self):
        import hashlib
        verifier, challenge = browser_login._pkce_pair()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
        self.assertEqual(challenge, expected)

    def test_build_authorize_url(self):
        url = browser_login.build_authorize_url(
            {}, challenge="chal", state="st8", redirect_uri="http://localhost:1455/auth/callback"
        )
        self.assertTrue(url.startswith("https://"))
        self.assertIn("code_challenge=chal", url)
        self.assertIn("code_challenge_method=S256", url)
        self.assertIn("state=st8", url)
        self.assertIn("response_type=code", url)

    def test_build_authorize_url_rejects_http(self):
        with self.assertRaises(CodexConfigError):
            browser_login.build_authorize_url(
                {"authorize_url": "http://evil.example.com/a"},
                challenge="c", state="s", redirect_uri="http://localhost:1455/auth/callback",
            )

    def test_exchange_code_success(self):
        access = make_jwt(int(time.time()) + 3600)
        resp = FakeResponse(200, {"access_token": access, "refresh_token": "r"})
        with mock.patch.object(browser_login.requests, "post", return_value=resp):
            creds = browser_login.exchange_code(
                "auth-code", verifier="v", redirect_uri="http://localhost:1455/auth/callback", settings={}
            )
        self.assertEqual(creds.access_token, access)
        self.assertEqual(creds.refresh_token, "r")

    def test_exchange_code_failure_requires_reauth(self):
        resp = FakeResponse(400, {"error": "invalid_grant"})
        with mock.patch.object(browser_login.requests, "post", return_value=resp):
            with self.assertRaises(CodexAuthRequiredError):
                browser_login.exchange_code(
                    "bad", verifier="v", redirect_uri="http://localhost:1455/auth/callback", settings={}
                )


if __name__ == "__main__":
    unittest.main()
