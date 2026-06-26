"""Codex Responses API client (CodexOAuth.md §4.2, §7, §8).

Wraps a single text request: inject the Bearer access token, POST to the
Responses endpoint, parse the output text, and apply the error-handling
matrix:

    200            -> return text
    401            -> refresh once, retry once; then re-auth required
    429 usage      -> no retry, raise CodexUsageLimitError
    429 transient  -> short backoff, retry (bounded)
    5xx / timeout  -> exponential backoff, retry (bounded)

OQ-2: the Responses API request/response schema for subscription tokens is not
publicly documented. Parsing is defensive and the endpoint/model are
config-overridable so this can be repaired without code changes.
"""

import json
import time
import uuid
from typing import Optional

import requests
from loguru import logger

from app.services.codex_oauth import auth, constants
from app.services.codex_oauth._validation import require_https_url
from app.services.codex_oauth.errors import (
    CodexError,
    CodexTransientError,
    CodexUsageLimitError,
)
from app.services.codex_oauth.token_store import TokenStore

_REQUEST_TIMEOUT = 120
_MAX_TRANSIENT_RETRIES = 2
_BACKOFF_BASE_SECONDS = 1.5

# Substrings that distinguish a hard usage-limit 429 from a transient rate
# limit. Kept liberal because the exact phrasing is not contractual.
_USAGE_LIMIT_MARKERS = ("usage limit", "usage_limit", "quota", "exceeded your")


def _extract_output_text(body: dict) -> str:
    """Pull assistant text out of a Responses API payload, defensively.

    Handles both the convenience ``output_text`` field and the structured
    ``output[].content[]`` array used by the Responses API.
    """
    # 1. Convenience aggregate field (present in SDK-shaped responses).
    text = body.get("output_text")
    if isinstance(text, str) and text.strip():
        return text

    # 2. Structured output array.
    chunks = []
    for item in body.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        for part in item.get("content", []) or []:
            if not isinstance(part, dict):
                continue
            if part.get("type") in ("output_text", "text") and part.get("text"):
                chunks.append(part["text"])
    if chunks:
        return "".join(chunks)

    # 3. Fall back to a Chat-Completions shape in case the backend returns one.
    choices = body.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict) and message.get("content"):
            return message["content"]

    raise CodexError("codex response did not contain any output text")


def _build_codex_payload(prompt: str, model: str, *, stream: bool) -> dict:
    """Build the request body in the ChatGPT/Codex backend's Responses shape.

    The Codex backend (unlike api.openai.com) expects a structured ``input``
    array of message items, not a plain string, and is known to require
    streaming. Modelled on the open-source Codex CLI (OQ-2 — unverified).
    """
    return {
        "model": model,
        "instructions": "",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": prompt}],
            }
        ],
        "tools": [],
        "tool_choice": "auto",
        "parallel_tool_calls": False,
        "store": False,
        "stream": stream,
    }


def _codex_headers(creds, *, stream: bool) -> dict:
    """Headers the Codex backend expects, including the beta/originator flags."""
    headers = {
        "Authorization": f"Bearer {creds.access_token}",
        "Content-Type": "application/json",
        "OpenAI-Beta": "responses=experimental",
        "originator": "codex_cli_rs",
        "session_id": str(uuid.uuid4()),
        "Accept": "text/event-stream" if stream else "application/json",
    }
    if creds.account_id:
        headers["chatgpt-account-id"] = creds.account_id
    return headers


def _short_body(response: requests.Response, limit: int = 800) -> str:
    """Return a truncated, single-line copy of the response body for diagnostics.

    The Codex backend returns a JSON error object (e.g. invalid_request_error)
    on 4xx; surfacing it is what makes a 400 actionable. Token material is not
    echoed in these bodies, and llm._sanitize_error_message scrubs any URL
    credentials before the string reaches the UI.
    """
    try:
        text = (response.text or "").strip().replace("\n", " ").replace("\r", " ")
    except Exception:  # pragma: no cover - stream already consumed/closed
        return ""
    return text[:limit]


def _parse_sse_stream(response: requests.Response) -> str:
    """Accumulate assistant text from a Responses API SSE stream."""
    text_parts = []
    final_body = None
    for raw in response.iter_lines():
        if not raw:
            continue
        # requests yields bytes for text/event-stream (no charset set), so
        # decode defensively rather than relying on decode_unicode.
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if not raw.startswith("data:"):
            continue
        data = raw[len("data:"):].strip()
        if not data or data == "[DONE]":
            continue
        try:
            event = json.loads(data)
        except ValueError:
            continue
        etype = event.get("type", "")
        if etype == "response.output_text.delta":
            delta = event.get("delta")
            if isinstance(delta, str):
                text_parts.append(delta)
        elif etype in ("response.completed", "response.incomplete"):
            final_body = event.get("response")
        elif etype in ("response.failed", "error"):
            err = (event.get("response", {}) or {}).get("error") or event.get("error") or {}
            raise CodexError(f"codex stream error: {err.get('message', etype)}")
    if text_parts:
        return "".join(text_parts)
    if final_body:
        return _extract_output_text(final_body)
    raise CodexError("codex stream produced no output text")


def _is_usage_limit(response: requests.Response) -> bool:
    body_text = (response.text or "").lower()
    if any(marker in body_text for marker in _USAGE_LIMIT_MARKERS):
        return True
    # Some backends signal hard limits via a header.
    limit_header = response.headers.get("x-ratelimit-remaining", "")
    return limit_header.strip() == "0"


def generate_text(prompt: str, *, settings: dict, store: Optional[TokenStore] = None) -> str:
    """Generate text from Codex for a single prompt.

    Returns plain text. Raises a :class:`CodexError` subclass on failure; the
    caller (``llm._generate_response``) wraps these into the standard
    ``"Error: ..."`` string like every other provider.
    """
    if store is None:
        store = TokenStore(settings.get("token_store_path") or constants.DEFAULT_TOKEN_STORE_PATH)

    base_url = require_https_url(
        settings.get("base_url") or constants.DEFAULT_BASE_URL, "base_url"
    ).rstrip("/")
    model = settings.get("model") or constants.DEFAULT_MODEL
    url = f"{base_url}/responses"
    # The Codex backend is known to require streaming; allow opting out via config
    # for OpenAI-compatible gateways that only support non-streaming responses.
    stream = settings.get("stream", True)
    if isinstance(stream, str):
        stream = stream.strip().lower() not in ("false", "0", "no")

    creds = auth.get_valid_access_token(store, settings=settings)
    payload = _build_codex_payload(prompt, model, stream=stream)

    refreshed_after_401 = False
    transient_attempts = 0

    while True:
        headers = _codex_headers(creds, stream=stream)

        try:
            response = requests.post(
                url, headers=headers, json=payload, timeout=_REQUEST_TIMEOUT, stream=stream
            )
        except requests.RequestException as exc:
            transient_attempts += 1
            if transient_attempts > _MAX_TRANSIENT_RETRIES:
                raise CodexTransientError(
                    f"codex request failed after retries: {type(exc).__name__}"
                ) from exc
            _backoff(transient_attempts)
            continue

        status = response.status_code

        if status == 200:
            if stream:
                return _parse_sse_stream(response)
            try:
                body = response.json()
            except ValueError as exc:
                raise CodexError("codex returned a non-JSON 200 response") from exc
            return _extract_output_text(body)

        if status == 401:
            # Refresh exactly once, then retry; otherwise demand re-auth.
            if not refreshed_after_401:
                logger.info("codex returned 401; attempting one token refresh")
                creds = auth.refresh(creds, store, settings=settings)
                refreshed_after_401 = True
                continue
            # auth.refresh quarantines/raises on terminal failure; a second 401
            # means the fresh token is still unauthorized.
            raise CodexError(
                "codex request unauthorized even after refresh; re-authentication required"
            )

        if status == 429:
            if _is_usage_limit(response):
                raise CodexUsageLimitError(
                    "Codex subscription usage limit reached. Retrying will not help; "
                    "wait for the limit to reset or configure a fallback llm_provider."
                )
            transient_attempts += 1
            if transient_attempts > _MAX_TRANSIENT_RETRIES:
                raise CodexTransientError("codex rate-limited (429) after retries")
            _backoff(transient_attempts, retry_after=response.headers.get("retry-after"))
            continue

        if status >= 500:
            transient_attempts += 1
            if transient_attempts > _MAX_TRANSIENT_RETRIES:
                raise CodexTransientError(f"codex server error (http {status}) after retries")
            _backoff(transient_attempts)
            continue

        # Other 4xx: terminal. Surface the backend's error body — it's what
        # makes a 400 actionable (e.g. invalid model / bad input schema). Token
        # material is not echoed here and URL creds are scrubbed downstream.
        detail = _short_body(response)
        raise CodexError(
            f"codex request failed with http {status}" + (f": {detail}" if detail else "")
        )


def _backoff(attempt: int, *, retry_after: Optional[str] = None) -> None:
    if retry_after:
        try:
            time.sleep(min(float(retry_after), 30.0))
            return
        except (TypeError, ValueError):
            pass
    time.sleep(_BACKOFF_BASE_SECONDS * attempt)
