"""Codex OAuth constants.

NOTE ON PROVENANCE & VERIFICATION (see CodexOAuth.md §6.2, OQ-2/OQ-3):

The OpenAI Codex subscription OAuth flow is NOT a publicly documented/stable
API. The values below are derived from the open-source Codex CLI and the
referenced Hermes implementation (NousResearch/hermes-agent, MIT). They are
the *current* best-known constants and may change without notice on OpenAI's
side. Every value here is overridable through the ``[openai_codex]`` config
section so the integration can be repaired without a code change.

Attribution: the OAuth client_id / endpoint shape and the ``~/.codex/auth.json``
import strategy are modelled on the MIT-licensed Hermes ``openai-codex``
provider and the public Codex CLI. Keep this notice if porting further.
"""

# Public OAuth client id used by the Codex CLI (loopback/PKCE app).
# Overridable via config: [openai_codex].client_id
DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

# OAuth issuer + token endpoint used for refresh_token grants.
# Overridable via config: [openai_codex].issuer / token_url
DEFAULT_ISSUER = "https://auth.openai.com"
DEFAULT_TOKEN_URL = f"{DEFAULT_ISSUER}/oauth/token"

# RFC 8628 device-authorization endpoints (Path B, device_code variant).
# IMPORTANT: the production Codex CLI actually uses PKCE + loopback redirect,
# NOT RFC 8628 device_code. These URLs are a best-effort placeholder for the
# device-code flow described in the spec and are flagged unverified (OQ-3).
DEFAULT_DEVICE_AUTHORIZE_URL = f"{DEFAULT_ISSUER}/oauth/device/code"

# Browser PKCE + loopback flow (the REAL Codex CLI login). The browser is sent
# to the authorize endpoint and redirected back to a localhost callback that
# this app listens on. Endpoints/params modelled on the public Codex CLI and
# are UNVERIFIED against OpenAI's backend (OQ-3) — all overridable via config.
DEFAULT_AUTHORIZE_URL = f"{DEFAULT_ISSUER}/oauth/authorize"
DEFAULT_REDIRECT_PORT = 1455
DEFAULT_REDIRECT_PATH = "/auth/callback"
# Extra query params the Codex CLI is known to send on the authorize request.
DEFAULT_AUTHORIZE_EXTRA = {
    "id_token_add_organizations": "true",
    "codex_cli_simplified_flow": "true",
}

# Responses API base (OQ-2: unverified for subscription tokens). The Codex
# backend differs from api.openai.com; keep this overridable.
DEFAULT_BASE_URL = "https://chatgpt.com/backend-api/codex"

# Default model identifier (OQ-2: must be validated against a live account).
DEFAULT_MODEL = "gpt-5.5"

# Default on-disk locations.
DEFAULT_CODEX_AUTH_PATH = "~/.codex/auth.json"
DEFAULT_TOKEN_STORE_PATH = "~/.moneyprinterturbo/codex_auth.json"

# Refresh access tokens this many seconds before their JWT ``exp`` so a request
# never races a just-expired token.
EXPIRY_SKEW_SECONDS = 120

# Fallback access-token lifetime when the token carries no ``exp`` claim.
FALLBACK_TOKEN_TTL_SECONDS = 3600

# OAuth scope requested during device-code authorization (Path B).
DEFAULT_SCOPE = "openid profile email offline_access"
