"""Codex credential acquisition and lifecycle (CodexOAuth.md §6).

Two acquisition paths:
- Path A (priority): import an existing Codex CLI token from ``~/.codex/auth.json``.
- Path B (secondary): device-code OAuth flow (see ``device_code.py``).

Plus the common refresh logic and the single entry callers use:
``get_valid_access_token`` — load → check quarantine → refresh if expired → return.

Attribution: import + refresh strategy modelled on the MIT-licensed Hermes
``openai-codex`` provider and the public Codex CLI.
"""

import json
import os
import time
from dataclasses import replace
from typing import Optional

import requests
from loguru import logger

from app.services.codex_oauth import constants
from app.services.codex_oauth._validation import require_https_url
from app.services.codex_oauth.errors import (
    CodexAuthRequiredError,
    CodexConfigError,
    CodexRefreshError,
)
from app.services.codex_oauth.token_store import (
    Credentials,
    TokenStore,
    decode_jwt_exp,
)

# OAuth token-endpoint error codes that mean "this grant is dead, stop trying".
_TERMINAL_OAUTH_ERRORS = {
    "invalid_grant",
    "invalid_client",
    "unauthorized_client",
    "access_denied",
    "invalid_request",
}

_REFRESH_TIMEOUT = 30


def _expand(path: str) -> str:
    # expanduser handles ~; we deliberately avoid expandvars so a config path
    # cannot pull in environment-variable values as an extra attack surface.
    return os.path.abspath(os.path.expanduser(path))


def _parse_codex_auth_payload(data: dict) -> Credentials:
    """Parse a Codex CLI ``auth.json`` dict into Credentials.

    The Codex CLI nests OAuth material under a ``tokens`` object, e.g.::

        {"tokens": {"access_token": "...", "refresh_token": "...",
                    "account_id": "...", "id_token": "..."},
         "last_refresh": "2025-..."}

    We also tolerate flat top-level keys for forward/backward compatibility
    (OQ-4: the exact shape is not contractually guaranteed).
    """
    tokens = data.get("tokens") if isinstance(data.get("tokens"), dict) else {}

    def pick(*keys: str) -> str:
        for key in keys:
            for source in (tokens, data):
                value = source.get(key)
                if value:
                    return value
        return ""

    access_token = pick("access_token", "accessToken")
    refresh_token = pick("refresh_token", "refreshToken")
    account_id = pick("account_id", "accountId", "chatgpt_account_id")
    id_token = pick("id_token", "idToken")

    if not access_token and not refresh_token:
        raise CodexConfigError(
            "codex auth file contained no access_token or refresh_token"
        )

    return Credentials(
        access_token=access_token,
        refresh_token=refresh_token,
        account_id=account_id,
        id_token=id_token,
        expires_at=decode_jwt_exp(access_token),
        last_refresh=time.time(),
    )


def import_codex_cli_credentials(codex_auth_path: str, store: TokenStore) -> Credentials:
    """Path A — read ``~/.codex/auth.json`` and persist into ``store``."""
    path = _expand(codex_auth_path)
    if not os.path.isfile(path):
        raise CodexAuthRequiredError(
            f"Codex CLI auth file not found at {path}. "
            "Run `codex login` first, or set auth_mode = \"device_code\"."
        )
    try:
        with open(path, mode="r", encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, json.JSONDecodeError) as exc:
        raise CodexConfigError(
            f"failed to read Codex CLI auth file at {path}: corrupt or unreadable"
        ) from exc
    if not isinstance(data, dict):
        raise CodexConfigError(f"Codex CLI auth file at {path} has an unexpected format")

    creds = _parse_codex_auth_payload(data)
    logger.info(f"imported Codex CLI credentials from {path}")
    return store.save(creds)


def refresh(creds: Credentials, store: TokenStore, *, settings: dict) -> Credentials:
    """Exchange the refresh_token for a fresh access_token.

    On a terminal OAuth failure the credential is quarantined and a terminal
    :class:`CodexRefreshError` is raised. Transient failures raise a
    non-terminal :class:`CodexRefreshError` so callers may back off and retry.
    """
    if not creds.refresh_token:
        raise CodexAuthRequiredError(
            "no refresh_token available; re-authentication is required"
        )

    token_url = require_https_url(
        settings.get("token_url") or constants.DEFAULT_TOKEN_URL, "token_url"
    )
    client_id = settings.get("client_id") or constants.DEFAULT_CLIENT_ID

    payload = {
        "grant_type": "refresh_token",
        "refresh_token": creds.refresh_token,
        "client_id": client_id,
    }
    scope = settings.get("scope") or constants.DEFAULT_SCOPE
    if scope:
        payload["scope"] = scope

    try:
        response = requests.post(token_url, data=payload, timeout=_REFRESH_TIMEOUT)
    except requests.RequestException as exc:
        # Network-level failure is transient — do not quarantine.
        raise CodexRefreshError(
            f"codex token refresh request failed: {type(exc).__name__}", terminal=False
        ) from exc

    if response.status_code == 200:
        try:
            body = response.json()
        except ValueError as exc:
            raise CodexRefreshError(
                "codex token refresh returned a non-JSON body", terminal=False
            ) from exc
        new_access = body.get("access_token")
        if not new_access:
            raise CodexRefreshError(
                "codex token refresh response had no access_token", terminal=False
            )
        # Refresh tokens may rotate; keep the new one when present.
        new_refresh = body.get("refresh_token") or creds.refresh_token
        updated = replace(
            creds,
            access_token=new_access,
            refresh_token=new_refresh,
            id_token=body.get("id_token") or creds.id_token,
            expires_at=decode_jwt_exp(new_access),
            last_refresh=time.time(),
            quarantined=False,
            quarantine_reason="",
        )
        logger.info("codex access token refreshed")
        return store.save(updated)

    # Determine terminality from the OAuth error code when available.
    error_code = ""
    try:
        error_code = (response.json() or {}).get("error", "")
    except ValueError:
        error_code = ""

    terminal = (
        response.status_code in (400, 401, 403)
        or error_code in _TERMINAL_OAUTH_ERRORS
    )
    if terminal:
        # Only store a known OAuth error code; otherwise record the status code.
        # This keeps a server-controlled string out of the user-visible re-auth
        # message that get_valid_access_token surfaces.
        reason = error_code if error_code in _TERMINAL_OAUTH_ERRORS else f"http_{response.status_code}"
        store.quarantine(reason)
        raise CodexRefreshError(
            f"codex refresh token rejected ({reason}); re-authentication required",
            terminal=True,
        )

    # 5xx / 429 / unknown -> transient.
    raise CodexRefreshError(
        f"codex token refresh failed transiently (http {response.status_code})",
        terminal=False,
    )


def get_valid_access_token(store: TokenStore, *, settings: dict) -> Credentials:
    """Return credentials with a usable access token, refreshing if needed.

    Bootstraps from the configured acquisition path when the store is empty:
    Path A imports from the Codex CLI; Path B requires the caller to have run
    the device-code flow already (we only surface a clear instruction here).
    """
    creds = store.load()
    if creds is None:
        creds = _bootstrap_credentials(store, settings=settings)

    if creds.quarantined:
        raise CodexAuthRequiredError(
            "stored Codex credentials are quarantined "
            f"({creds.quarantine_reason or 'unknown'}); re-authentication required. "
            + _reauth_hint(settings)
        )

    if creds.is_expired():
        creds = refresh(creds, store, settings=settings)

    if not creds.access_token:
        raise CodexAuthRequiredError(
            "no Codex access token available. " + _reauth_hint(settings)
        )
    return creds


def _bootstrap_credentials(store: TokenStore, *, settings: dict) -> Credentials:
    auth_mode = (settings.get("auth_mode") or "import").strip().lower()
    if auth_mode == "import":
        codex_auth_path = settings.get("codex_auth_path") or constants.DEFAULT_CODEX_AUTH_PATH
        return import_codex_cli_credentials(codex_auth_path, store)
    if auth_mode == "browser":
        raise CodexAuthRequiredError(
            "no stored Codex credentials. Sign in first via the WebUI "
            "(Basic Settings → LLM → Sign in with browser), then retry."
        )
    if auth_mode == "device_code":
        raise CodexAuthRequiredError(
            "no stored Codex credentials. Run the device-code login first "
            "(see device_code.run_device_code_flow), then retry."
        )
    raise CodexConfigError(
        f"unknown openai_codex auth_mode: {auth_mode!r} "
        "(expected 'import', 'browser', or 'device_code')"
    )


def _reauth_hint(settings: dict) -> str:
    auth_mode = (settings.get("auth_mode") or "import").strip().lower()
    if auth_mode == "browser":
        return "Sign in again via the WebUI (LLM settings → Sign in with browser)."
    if auth_mode == "device_code":
        return "Re-run the device-code login to obtain new credentials."
    return "Run `codex login` again to refresh ~/.codex/auth.json."
