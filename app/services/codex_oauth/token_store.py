"""Persistent Codex credential store.

Responsibilities (CodexOAuth.md §5, §6.3):
- Persist access_token / refresh_token / account_id to ``token_store_path``.
- Restrict file permissions to owner-only (0600). refresh_token is a
  long-lived secret and must never leak to logs or the repository.
- Track a ``quarantined`` flag so a dead refresh grant is not replayed.
- Decode the access token's JWT ``exp`` claim to decide when to refresh.

Security: tokens are NEVER included in ``repr``/``str`` or log output. Only
non-secret metadata (expiry, account id, quarantine reason) is loggable.
"""

import base64
import json
import os
import tempfile
import time
from dataclasses import dataclass, field, replace
from typing import Optional

from loguru import logger

from app.services.codex_oauth import constants
from app.services.codex_oauth.errors import CodexConfigError


def _expand(path: str) -> str:
    # expanduser handles ~; avoid expandvars so config paths cannot pull in
    # environment-variable values as an extra attack surface.
    return os.path.abspath(os.path.expanduser(path))


def decode_jwt_exp(token: Optional[str]) -> Optional[int]:
    """Return the ``exp`` (unix seconds) from a JWT access token, or None.

    The signature is intentionally NOT verified — we only read ``exp`` to
    schedule refresh. A malformed/opaque token simply yields None, in which
    case callers fall back to a TTL since the last refresh.
    """
    if not token or not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        data = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return None
    exp = data.get("exp")
    return exp if isinstance(exp, (int, float)) else None


@dataclass(frozen=True)
class Credentials:
    """Immutable Codex credential bundle.

    Following the project's immutability convention, mutations return a new
    instance via :func:`dataclasses.replace`.
    """

    access_token: str = ""
    refresh_token: str = ""
    account_id: str = ""
    id_token: str = ""
    # Unix seconds when the access token expires (from JWT exp), if known.
    expires_at: Optional[int] = None
    # Unix seconds of the last successful refresh/import.
    last_refresh: Optional[float] = None
    quarantined: bool = False
    quarantine_reason: str = ""

    def __repr__(self) -> str:  # pragma: no cover - defensive, secret-safe
        return (
            "Credentials(account_id=%r, expires_at=%r, quarantined=%r, "
            "has_access=%s, has_refresh=%s)"
            % (
                self.account_id,
                self.expires_at,
                self.quarantined,
                bool(self.access_token),
                bool(self.refresh_token),
            )
        )

    def is_expired(self, *, now: Optional[float] = None, skew: int = constants.EXPIRY_SKEW_SECONDS) -> bool:
        """True when the access token is missing, expired, or within ``skew``.

        When no ``exp`` is known, fall back to a TTL since ``last_refresh``.
        """
        current = time.time() if now is None else now
        if not self.access_token:
            return True
        if self.expires_at is not None:
            return current >= (self.expires_at - skew)
        if self.last_refresh is not None:
            return current >= (self.last_refresh + constants.FALLBACK_TOKEN_TTL_SECONDS - skew)
        # No expiry info at all: treat as expired so we refresh defensively.
        return True


def _credentials_to_dict(creds: Credentials) -> dict:
    return {
        "access_token": creds.access_token,
        "refresh_token": creds.refresh_token,
        "account_id": creds.account_id,
        "id_token": creds.id_token,
        "expires_at": creds.expires_at,
        "last_refresh": creds.last_refresh,
        "quarantined": creds.quarantined,
        "quarantine_reason": creds.quarantine_reason,
    }


def _credentials_from_dict(data: dict) -> Credentials:
    return Credentials(
        access_token=data.get("access_token", "") or "",
        refresh_token=data.get("refresh_token", "") or "",
        account_id=data.get("account_id", "") or "",
        id_token=data.get("id_token", "") or "",
        expires_at=data.get("expires_at"),
        last_refresh=data.get("last_refresh"),
        quarantined=bool(data.get("quarantined", False)),
        quarantine_reason=data.get("quarantine_reason", "") or "",
    )


class TokenStore:
    """File-backed credential store with 0600 permissions."""

    def __init__(self, path: str = constants.DEFAULT_TOKEN_STORE_PATH):
        self.path = _expand(path)

    def exists(self) -> bool:
        return os.path.isfile(self.path)

    def load(self) -> Optional[Credentials]:
        if not self.exists():
            return None
        try:
            with open(self.path, mode="r", encoding="utf-8") as fp:
                data = json.load(fp)
        except (OSError, json.JSONDecodeError) as exc:
            raise CodexConfigError(
                f"failed to read codex token store at {self.path}: corrupt or unreadable"
            ) from exc
        if not isinstance(data, dict):
            raise CodexConfigError(
                f"codex token store at {self.path} has an unexpected format"
            )
        return _credentials_from_dict(data)

    def save(self, creds: Credentials) -> Credentials:
        """Persist credentials, refreshing the cached ``expires_at`` from the
        access token, and lock the file down to owner-only."""
        exp = decode_jwt_exp(creds.access_token)
        if exp is not None:
            creds = replace(creds, expires_at=exp)

        directory = os.path.dirname(self.path) or "."
        if not os.path.isdir(directory):
            # Set the restrictive mode at creation time (subject to umask) and
            # tighten again below to avoid a window where the dir is world-readable.
            os.makedirs(directory, mode=0o700, exist_ok=True)
            self._restrict_dir(directory)

        # Write to a unique temp file (O_CREAT|O_EXCL via mkstemp, mode 0600)
        # then atomically move into place, so a crash can't leave a half-written
        # secret behind and a pre-existing/attacker file can't be truncated.
        fd, tmp_path = tempfile.mkstemp(
            dir=directory, prefix=os.path.basename(self.path) + ".", suffix=".tmp"
        )
        try:
            os.chmod(tmp_path, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(_credentials_to_dict(creds), fp)
        except Exception:
            try:
                os.remove(tmp_path)
            finally:
                raise
        os.replace(tmp_path, self.path)
        self._restrict_file(self.path)
        logger.debug(f"codex credentials saved to {self.path} (account_id={creds.account_id!r})")
        return creds

    def quarantine(self, reason: str) -> Optional[Credentials]:
        """Mark the stored credential dead so refresh is not replayed."""
        creds = self.load()
        if creds is None:
            return None
        updated = replace(creds, quarantined=True, quarantine_reason=reason)
        return self.save(updated)

    @staticmethod
    def _restrict_file(path: str) -> None:
        # Best-effort: on POSIX this yields true 0600. On Windows os.chmod only
        # toggles the read-only bit (no per-user ACL), so the guarantee is
        # weaker there — documented limitation, not a silent failure.
        try:
            os.chmod(path, 0o600)
        except OSError as exc:  # pragma: no cover - platform dependent
            logger.warning(f"could not restrict permissions on {path}: {exc}")

    @staticmethod
    def _restrict_dir(path: str) -> None:
        try:
            os.chmod(path, 0o700)
        except OSError as exc:  # pragma: no cover - platform dependent
            logger.warning(f"could not restrict permissions on {path}: {exc}")
