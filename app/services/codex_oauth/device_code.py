"""Device-code OAuth flow — Path B (CodexOAuth.md §6.2).

⚠️ UNVERIFIED (OQ-3): The production Codex CLI authenticates with PKCE + a
loopback redirect, NOT RFC 8628 device_code. The endpoints/parameters here are
a best-effort implementation of the *device-code* flow the spec requested and
have NOT been confirmed against OpenAI's backend. The authorize endpoint and
client_id live in ``constants.py`` and are config-overridable so this can be
corrected once the real values are confirmed (e.g. from the MIT Hermes source).

This is intentionally shipped as a clearly-flagged scaffold: it implements the
poll loop and token persistence correctly, but will only work if the device
endpoints exist and accept these parameters. Path A (import) is the supported
path until OQ-3 is resolved.
"""

import time
from typing import Callable, Optional

import requests
from loguru import logger

from app.services.codex_oauth import constants
from app.services.codex_oauth._validation import require_https_url
from app.services.codex_oauth.errors import CodexAuthRequiredError, CodexError
from app.services.codex_oauth.token_store import Credentials, TokenStore, decode_jwt_exp

_DEVICE_REQUEST_TIMEOUT = 30
_DEFAULT_POLL_INTERVAL = 5
_MAX_POLL_SECONDS = 900  # 15 minutes
_MAX_POLL_INTERVAL = 60  # cap a single sleep so the thread stays responsive


def request_device_code(*, settings: dict) -> dict:
    """Begin device authorization; returns the device-code response dict."""
    authorize_url = require_https_url(
        settings.get("device_authorize_url") or constants.DEFAULT_DEVICE_AUTHORIZE_URL,
        "device_authorize_url",
    )
    client_id = settings.get("client_id") or constants.DEFAULT_CLIENT_ID
    scope = settings.get("scope") or constants.DEFAULT_SCOPE

    try:
        response = requests.post(
            authorize_url,
            data={"client_id": client_id, "scope": scope},
            timeout=_DEVICE_REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise CodexError(f"device authorization request failed: {type(exc).__name__}") from exc

    if response.status_code != 200:
        raise CodexError(
            f"device authorization failed (http {response.status_code}). "
            "The device-code endpoint may be unverified — see OQ-3."
        )
    try:
        return response.json()
    except ValueError as exc:
        raise CodexError("device authorization returned a non-JSON body") from exc


def poll_for_token(
    device_code: str,
    *,
    settings: dict,
    interval: int = _DEFAULT_POLL_INTERVAL,
    sleeper: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> Credentials:
    """Poll the token endpoint until the user authorizes or the flow expires.

    ``sleeper``/``now`` are injectable for deterministic tests.
    """
    token_url = require_https_url(
        settings.get("token_url") or constants.DEFAULT_TOKEN_URL, "token_url"
    )
    client_id = settings.get("client_id") or constants.DEFAULT_CLIENT_ID
    deadline = now() + _MAX_POLL_SECONDS
    current_interval = max(int(interval or _DEFAULT_POLL_INTERVAL), 1)

    while True:
        if now() >= deadline:
            raise CodexAuthRequiredError("device-code authorization timed out; please retry")

        try:
            response = requests.post(
                token_url,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": client_id,
                },
                timeout=_DEVICE_REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise CodexError(f"device token poll failed: {type(exc).__name__}") from exc

        body = {}
        try:
            body = response.json()
        except ValueError:
            body = {}

        if response.status_code == 200 and body.get("access_token"):
            access_token = body["access_token"]
            return Credentials(
                access_token=access_token,
                refresh_token=body.get("refresh_token", "") or "",
                id_token=body.get("id_token", "") or "",
                account_id=body.get("account_id", "") or "",
                expires_at=decode_jwt_exp(access_token),
                last_refresh=time.time(),
            )

        error = body.get("error", "")
        if error == "authorization_pending":
            sleeper(current_interval)
            continue
        if error == "slow_down":
            current_interval = min(current_interval + 5, _MAX_POLL_INTERVAL)
            sleeper(current_interval)
            continue
        # access_denied / expired_token / anything else -> terminal.
        raise CodexAuthRequiredError(
            f"device-code authorization failed ({error or f'http {response.status_code}'})"
        )


def run_device_code_flow(
    *,
    settings: dict,
    store: Optional[TokenStore] = None,
    prompt: Callable[[str], None] = logger.info,
) -> Credentials:
    """Drive the full device-code flow and persist the resulting credentials."""
    if store is None:
        store = TokenStore(settings.get("token_store_path") or constants.DEFAULT_TOKEN_STORE_PATH)

    device = request_device_code(settings=settings)
    verification_uri = device.get("verification_uri_complete") or device.get("verification_uri", "")
    user_code = device.get("user_code", "")
    device_code = device.get("device_code", "")
    if not device_code:
        raise CodexError("device authorization response missing device_code")

    prompt(
        "To authorize MoneyPrinterTurbo with Codex, open this URL and enter the code:\n"
        f"    URL : {verification_uri}\n"
        f"    Code: {user_code}"
    )

    creds = poll_for_token(
        device_code,
        settings=settings,
        interval=int(device.get("interval", _DEFAULT_POLL_INTERVAL)),
    )
    return store.save(creds)
