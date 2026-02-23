"""Pydantic models for API request and response validation.

These models enforce structure and constraints on all data
entering and leaving the proxy.
"""

from pydantic import BaseModel, Field, field_validator


class ChatMessage(BaseModel):
    """A single message in a chat conversation."""

    role: str = Field(
        ...,
        description="Message role.",
        pattern=r"^(system|user|assistant|tool)$",
    )
    content: str = Field(
        ...,
        description="Message content.",
        min_length=1,
        max_length=128_000,
    )


class ChatRequest(BaseModel):
    """Incoming chat completion request.

    Mirrors the OpenAI API schema with additional governance fields.
    Internal fields (user_id) are stripped before forwarding upstream.
    """

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
    temperature: float = Field(
        default=0.7,
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

    def to_upstream_dict(self) -> dict:
        """Serialize for the upstream LLM provider, stripping internal fields.

        The upstream API (OpenAI, Azure, etc.) does not know about user_id
        and will reject unknown fields. This method returns only the fields
        the upstream provider expects.
        """
        return {
            "model": self.model,
            "messages": [m.model_dump() for m in self.messages],
            "temperature": self.temperature,
        }


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
    violations: list[dict] = Field(
        default_factory=list,
        description="List of detected violations with type, sensitivity, and action.",
    )
