"""URL validation for credential-bearing requests.

The OAuth endpoints are config-overridable (intentionally — OQ-2/OQ-3 mean we
may need to repair them without a code change). But these requests carry the
refresh_token (in the POST body) and access_token (Bearer header), so a
mistyped or malicious URL is a credential-exfiltration path. We therefore:

- HARD-require ``https://`` (never send credentials in plaintext), and
- WARN when the host is outside the known OpenAI/ChatGPT domains (so an
  intentional repair-override still works, but a typo/redirect is visible).
"""

from urllib.parse import urlparse

from loguru import logger

from app.services.codex_oauth.errors import CodexConfigError

# Hosts trusted to receive Codex credentials. A custom host is allowed (for
# repair/override) but logged loudly so it cannot happen silently.
_TRUSTED_HOST_SUFFIXES = (".openai.com", "openai.com", ".chatgpt.com", "chatgpt.com")


def require_https_url(url: str, field_name: str) -> str:
    parsed = urlparse(url or "")
    if parsed.scheme != "https" or not parsed.netloc:
        raise CodexConfigError(
            f"{field_name} must be an https:// URL (got {parsed.scheme or 'empty'} scheme); "
            "credentials are never sent over plaintext."
        )
    host = parsed.hostname or ""
    if not any(host == suffix.lstrip(".") or host.endswith(suffix) for suffix in _TRUSTED_HOST_SUFFIXES):
        logger.warning(
            f"codex {field_name} host {host!r} is outside the known OpenAI/ChatGPT "
            "domains; credentials will be sent there. Verify this is intentional."
        )
    return url
