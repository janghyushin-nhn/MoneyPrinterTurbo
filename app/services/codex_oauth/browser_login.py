"""Browser-based PKCE + loopback OAuth login (the real Codex CLI flow).

This sends the user's browser to OpenAI's authorize endpoint, listens on a
localhost callback, and exchanges the returned authorization code (+ PKCE
verifier) for access/refresh tokens.

⚠️ UNVERIFIED (OQ-3): The authorize/token endpoints, client_id, redirect port,
and extra authorize params are modelled on the open-source Codex CLI and have
NOT been confirmed against OpenAI's backend. They are all config-overridable so
the flow can be repaired without a code change. The guaranteed-working path
remains "import" (run `codex login` in a terminal, then import ~/.codex/auth.json).

Loopback note: this only works when the browser and this process run on the
same machine (true for a local WebUI on 127.0.0.1). For remote deployments use
the import path instead.

Attribution: PKCE/loopback shape modelled on the MIT-licensed Hermes
``openai-codex`` provider and the public Codex CLI.
"""

import base64
import hashlib
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from loguru import logger

from app.services.codex_oauth import constants
from app.services.codex_oauth._validation import require_https_url
from app.services.codex_oauth.errors import CodexAuthRequiredError, CodexError
from app.services.codex_oauth.token_store import Credentials, TokenStore, decode_jwt_exp

_TOKEN_TIMEOUT = 30
_DEFAULT_LOGIN_TIMEOUT = 300  # 5 minutes for the user to finish in the browser


def _pkce_pair() -> tuple:
    """Return a (verifier, challenge) PKCE pair using the S256 method."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_authorize_url(settings: dict, *, challenge: str, state: str, redirect_uri: str) -> str:
    """Build the browser authorize URL (validated https)."""
    authorize_url = require_https_url(
        settings.get("authorize_url") or constants.DEFAULT_AUTHORIZE_URL, "authorize_url"
    )
    client_id = settings.get("client_id") or constants.DEFAULT_CLIENT_ID
    scope = settings.get("scope") or constants.DEFAULT_SCOPE
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    params.update(constants.DEFAULT_AUTHORIZE_EXTRA)
    return f"{authorize_url}?{urlencode(params)}"


def exchange_code(
    code: str, *, verifier: str, redirect_uri: str, settings: dict
) -> Credentials:
    """Exchange an authorization code (+ PKCE verifier) for tokens."""
    token_url = require_https_url(
        settings.get("token_url") or constants.DEFAULT_TOKEN_URL, "token_url"
    )
    client_id = settings.get("client_id") or constants.DEFAULT_CLIENT_ID
    try:
        response = requests.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
            },
            timeout=_TOKEN_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise CodexError(f"code exchange request failed: {type(exc).__name__}") from exc

    if response.status_code != 200:
        raise CodexAuthRequiredError(
            f"authorization code exchange failed (http {response.status_code}); "
            "the OAuth endpoints may be unverified (OQ-3) — try the import path."
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise CodexError("code exchange returned a non-JSON body") from exc

    access_token = body.get("access_token")
    if not access_token:
        raise CodexError("code exchange response had no access_token")
    return Credentials(
        access_token=access_token,
        refresh_token=body.get("refresh_token", "") or "",
        id_token=body.get("id_token", "") or "",
        account_id=body.get("account_id", "") or "",
        expires_at=decode_jwt_exp(access_token),
        last_refresh=time.time(),
    )


class _CallbackHandler(BaseHTTPRequestHandler):
    # Set by the server instance before serving.
    captured: dict = {}
    expected_state: str = ""
    callback_path: str = constants.DEFAULT_REDIRECT_PATH

    def do_GET(self):  # noqa: N802 (http.server API)
        parsed = urlparse(self.path)
        if parsed.path != self.callback_path:
            self.send_response(404)
            self.end_headers()
            return
        query = parse_qs(parsed.query)
        self.__class__.captured = {
            "code": (query.get("code") or [""])[0],
            "state": (query.get("state") or [""])[0],
            "error": (query.get("error") or [""])[0],
        }
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        ok = (
            self.__class__.captured["code"]
            and self.__class__.captured["state"] == self.__class__.expected_state
        )
        msg = (
            "Sign-in complete. You can close this tab and return to MoneyPrinterTurbo."
            if ok
            else "Sign-in failed or was cancelled. Return to MoneyPrinterTurbo and retry."
        )
        self.wfile.write(f"<html><body><p>{msg}</p></body></html>".encode("utf-8"))

    def log_message(self, *args):  # silence default stderr logging
        return


def run_browser_login(
    *,
    settings: dict,
    store: Optional[TokenStore] = None,
    timeout: int = _DEFAULT_LOGIN_TIMEOUT,
    open_browser: bool = True,
    on_url: Optional[Callable[[str], None]] = None,
    now: Callable[[], float] = time.monotonic,
) -> Credentials:
    """Drive the full browser PKCE login and persist the resulting credentials.

    ``on_url`` (if given) receives the authorize URL so a UI can render a
    clickable link in addition to (or instead of) auto-opening the browser.
    """
    if store is None:
        store = TokenStore(settings.get("token_store_path") or constants.DEFAULT_TOKEN_STORE_PATH)

    port = int(settings.get("redirect_port") or constants.DEFAULT_REDIRECT_PORT)
    callback_path = settings.get("redirect_path") or constants.DEFAULT_REDIRECT_PATH
    redirect_uri = f"http://localhost:{port}{callback_path}"

    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    authorize_url = build_authorize_url(
        settings, challenge=challenge, state=state, redirect_uri=redirect_uri
    )

    handler = _CallbackHandler
    handler.captured = {}
    handler.expected_state = state
    handler.callback_path = callback_path

    try:
        server = HTTPServer(("127.0.0.1", port), handler)
    except OSError as exc:
        raise CodexError(
            f"could not start the loopback callback server on port {port}: {exc}. "
            "Close whatever is using the port or set redirect_port in config."
        ) from exc

    server.timeout = 1
    thread = threading.Thread(target=_serve_until_captured, args=(server, now, timeout), daemon=True)
    thread.start()

    if on_url:
        on_url(authorize_url)
    if open_browser:
        try:
            webbrowser.open(authorize_url)
        except Exception:  # pragma: no cover - platform dependent
            logger.warning("could not auto-open a browser; use the printed URL instead")

    thread.join(timeout=timeout + 2)
    try:
        server.server_close()
    except Exception:  # pragma: no cover
        pass

    captured = handler.captured or {}
    if not captured:
        raise CodexAuthRequiredError("browser sign-in timed out; please retry")
    if captured.get("error"):
        raise CodexAuthRequiredError(f"browser sign-in failed ({captured['error']})")
    if captured.get("state") != state:
        # CSRF protection: a mismatched state means the response is not ours.
        raise CodexError("browser sign-in state mismatch; aborting for safety")
    if not captured.get("code"):
        raise CodexAuthRequiredError("browser sign-in returned no authorization code")

    creds = exchange_code(
        captured["code"], verifier=verifier, redirect_uri=redirect_uri, settings=settings
    )
    return store.save(creds)


def _serve_until_captured(server: HTTPServer, now: Callable[[], float], timeout: int) -> None:
    deadline = now() + timeout
    while now() < deadline and not _CallbackHandler.captured:
        server.handle_request()
