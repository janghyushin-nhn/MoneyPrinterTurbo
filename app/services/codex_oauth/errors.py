"""Error taxonomy for the Codex OAuth provider.

Mirrors the error-handling matrix in CodexOAuth.md §8. The guiding rule
(borrowed from Hermes' quarantine pattern): never retry a failure that cannot
be resolved by retrying.
"""


class CodexError(Exception):
    """Base class for all Codex OAuth provider errors."""


class CodexConfigError(CodexError):
    """Configuration is missing or invalid (e.g. no auth file, bad path)."""


class CodexAuthRequiredError(CodexError):
    """No usable credentials; the user must (re)authenticate.

    The message should tell the user exactly how to recover, e.g. run
    ``codex login`` (Path A) or restart the device-code flow (Path B).
    """


class CodexRefreshError(CodexError):
    """A refresh_token grant failed.

    ``terminal=True`` means the grant is dead (invalid_grant / revoked) and
    must NOT be retried — the credential should be quarantined. ``terminal``
    False means a transient failure (network/5xx) that may be retried.
    """

    def __init__(self, message: str, *, terminal: bool):
        super().__init__(message)
        self.terminal = terminal


class CodexUsageLimitError(CodexError):
    """Subscription usage limit reached (HTTP 429, usage-limit signal).

    Retrying will not help; callers should surface this clearly and, if a
    fallback provider is configured, switch to it.
    """


class CodexTransientError(CodexError):
    """A transient failure (transient 429, 5xx, timeout) safe to retry."""
