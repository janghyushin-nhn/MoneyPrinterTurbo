"""OpenAI Codex subscription OAuth provider for MoneyPrinterTurbo.

Public entry point: :func:`generate_text` — called from
``app.services.llm._generate_response`` when ``llm_provider == "openai_codex"``.

See ``CodexOAuth.md`` for the full design, risks (§3 — terms-of-service gate),
and open questions. Portions are modelled on the MIT-licensed Hermes
``openai-codex`` provider (NousResearch/hermes-agent); attribution retained.
"""

import time
from typing import Callable, Optional

from app.config import config
from app.services.codex_oauth import auth, browser_login, client, constants
from app.services.codex_oauth.errors import (
    CodexAuthRequiredError,
    CodexConfigError,
    CodexError,
    CodexRefreshError,
    CodexTransientError,
    CodexUsageLimitError,
)
from app.services.codex_oauth.token_store import Credentials, TokenStore

__all__ = [
    "generate_text",
    "get_settings",
    "auth_status",
    "import_from_codex_cli",
    "login_via_browser",
    "sign_out",
    "CodexError",
    "CodexConfigError",
    "CodexAuthRequiredError",
    "CodexRefreshError",
    "CodexUsageLimitError",
    "CodexTransientError",
]


def get_settings() -> dict:
    """Read the ``[openai_codex]`` config section as a plain dict.

    Falls back to an empty dict so callers rely on the documented defaults in
    ``constants.py`` when the section is absent.
    """
    return dict(getattr(config, "openai_codex", {}) or {})


def _store(settings: Optional[dict] = None) -> TokenStore:
    settings = settings if settings is not None else get_settings()
    return TokenStore(settings.get("token_store_path") or constants.DEFAULT_TOKEN_STORE_PATH)


def generate_text(prompt: str) -> str:
    """Generate text from Codex for a single prompt string."""
    return client.generate_text(prompt, settings=get_settings())


def auth_status(settings: Optional[dict] = None) -> dict:
    """Return a non-secret summary of the stored credentials for the UI.

    Never returns token material — only whether we're authenticated, the
    account id, expiry, and quarantine state.
    """
    settings = settings if settings is not None else get_settings()
    creds = _store(settings).load()
    if creds is None:
        return {"authenticated": False, "reason": "no_credentials"}
    if creds.quarantined:
        return {
            "authenticated": False,
            "reason": "quarantined",
            "quarantine_reason": creds.quarantine_reason,
            "account_id": creds.account_id,
        }
    return {
        "authenticated": bool(creds.access_token),
        "account_id": creds.account_id,
        "expires_at": creds.expires_at,
        "expired": creds.is_expired(),
        "seconds_until_expiry": (
            int(creds.expires_at - time.time()) if creds.expires_at else None
        ),
    }


def import_from_codex_cli(settings: Optional[dict] = None) -> Credentials:
    """Path A — import credentials from the Codex CLI's ``auth.json``."""
    settings = settings if settings is not None else get_settings()
    codex_auth_path = settings.get("codex_auth_path") or constants.DEFAULT_CODEX_AUTH_PATH
    return auth.import_codex_cli_credentials(codex_auth_path, _store(settings))


def login_via_browser(
    settings: Optional[dict] = None,
    *,
    on_url: Optional[Callable[[str], None]] = None,
    open_browser: bool = True,
    timeout: int = 300,
) -> Credentials:
    """Browser PKCE login (the real Codex flow). Local machine only."""
    settings = settings if settings is not None else get_settings()
    return browser_login.run_browser_login(
        settings=settings,
        store=_store(settings),
        on_url=on_url,
        open_browser=open_browser,
        timeout=timeout,
    )


def sign_out(settings: Optional[dict] = None) -> bool:
    """Delete the stored credentials. Returns True if a file was removed."""
    import os

    settings = settings if settings is not None else get_settings()
    store = _store(settings)
    if store.exists():
        os.remove(store.path)
        return True
    return False
