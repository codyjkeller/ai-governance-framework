"""Pydantic models for API request and response validation.

These models enforce structure and constraints on all data
entering and leaving the proxy.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ChatMessage(BaseModel):
    """A single message in a chat conversation.

    Other fields the OpenAI format allows (tool_calls, tool_call_id, name, ...)
    are accepted and passed on. Their text is scanned like everything else.
    """

    model_config = ConfigDict(extra="allow")

    role: str = Field(
        ...,
        description="Message role.",
        pattern=r"^(system|developer|user|assistant|tool|function)$",
    )
    # Text, a list of content parts, or nothing at all (an assistant message
    # that only carries tool calls has no content).
    content: str | list[dict[str, Any]] | None = Field(
        default=None,
        description="Message content.",
    )

    @field_validator("content")
    @classmethod
    def limit_text_length(cls, v: str | list[dict[str, Any]] | None) -> str | list[dict[str, Any]] | None:
        if isinstance(v, str) and len(v) > 128_000:
            msg = "message content must be at most 128000 characters"
            raise ValueError(msg)
        return v


class ChatRequest(BaseModel):
    """Incoming chat completion request.

    Mirrors the OpenAI API schema with additional governance fields.
    Internal fields (user_id) are stripped before forwarding upstream.

    Any other field the OpenAI format allows (max_tokens, tools,
    response_format, ...) is accepted, scanned, and passed on unchanged.
    """

    model_config = ConfigDict(extra="allow")

    model: str = Field(
        ...,
        description="Model identifier to use for the completion.",
        min_length=1,
        max_length=256,
    )
    messages: list[ChatMessage] = Field(
        ...,
        description="Conversation messages.",
        min_length=1,
    )
    user_id: str = Field(
        default="anonymous",
        description="Internal: identity of the requesting user/service.",
        max_length=256,
    )
    # Only forwarded when the caller sets it. The proxy used to add 0.7 to every
    # request, which changes results and is rejected by some models.
    temperature: float | None = Field(
        default=None,
        description="Sampling temperature.",
        ge=0.0,
        le=2.0,
    )

    @field_validator("messages")
    @classmethod
    def must_have_at_least_one_user_message(cls, v: list[ChatMessage]) -> list[ChatMessage]:
        """Ensure at least one user message exists in the conversation."""
        if not any(m.role == "user" for m in v):
            msg = "messages must contain at least one message with role 'user'"
            raise ValueError(msg)
        return v

    def to_upstream_dict(self) -> dict[str, Any]:
        """Serialize for the upstream LLM provider, stripping internal fields.

        The upstream API (OpenAI, Azure, etc.) does not know about user_id
        and will reject unknown fields. Everything else the caller sent is
        returned exactly as sent; nothing is added.
        """
        return self.model_dump(exclude={"user_id"}, exclude_unset=True)


class ScanResult(BaseModel):
    """Result of a single scan operation (input or output)."""

    status: str = Field(
        ...,
        description="Scan outcome: BLOCKED, REDACTED, or CLEAN.",
        pattern=r"^(BLOCKED|REDACTED|CLEAN)$",
    )
    text: str | None = Field(
        default=None,
        description="The processed text (sanitized or original). None if blocked.",
    )
    violations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of detected violations with type, sensitivity, and action.",
    )
