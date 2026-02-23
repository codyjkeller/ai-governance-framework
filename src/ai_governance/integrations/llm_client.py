"""Upstream LLM client.

Handles communication with the upstream LLM provider (OpenAI, Azure, etc.).
Isolates HTTP details and error handling from the server logic.
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class LLMClientError(Exception):
    """Raised when the upstream LLM call fails.

    Wraps the underlying HTTP error with a sanitized message
    that is safe to return to the end user (no internal details).
    """

    def __init__(self, user_message: str, internal_detail: str) -> None:
        self.user_message = user_message
        self.internal_detail = internal_detail
        super().__init__(user_message)


async def call_upstream_llm(
    url: str,
    api_key: str,
    request_payload: dict[str, Any],
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Send a chat completion request to the upstream LLM provider.

    Args:
        url: Upstream API endpoint URL.
        api_key: Bearer token for the upstream API.
        request_payload: The sanitized request body (from ChatRequest.to_upstream_dict()).
        timeout: Request timeout in seconds.

    Returns:
        The full JSON response from the upstream provider.

    Raises:
        LLMClientError: If the upstream call fails for any reason.
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=request_payload, headers=headers)
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            return data

    except httpx.HTTPStatusError as e:
        # Log the real error internally, return a safe message to the user
        logger.error(
            "Upstream LLM returned HTTP %d: %s",
            e.response.status_code,
            e.response.text[:500],
        )
        raise LLMClientError(
            user_message="The upstream model provider returned an error. Please try again.",
            internal_detail=f"HTTP {e.response.status_code}: {e.response.text[:500]}",
        ) from e

    except httpx.TimeoutException as e:
        logger.error("Upstream LLM request timed out after %ss", timeout)
        raise LLMClientError(
            user_message="The upstream model provider timed out. Please try again.",
            internal_detail=f"Timeout after {timeout}s",
        ) from e

    except httpx.RequestError as e:
        logger.error("Upstream LLM request failed: %s", e)
        raise LLMClientError(
            user_message="Unable to reach the upstream model provider.",
            internal_detail=str(e),
        ) from e
