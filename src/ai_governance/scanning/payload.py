"""Scans whole request and response bodies, not just one text field.

An OpenAI-style request carries text in many places: message content,
content parts, tool-call arguments, tool results, tool descriptions and
more. Rather than list every field and miss the next one the API adds,
these helpers walk the entire body and scan every piece of text in it.

Two things are treated specially in a request:

- `model` is not scanned. It is checked against the allowlist instead.
- Content parts that are not text (images, audio, files) cannot be scanned
  by pattern matching. They are reported as unscannable so the caller can
  refuse them.
"""

from dataclasses import dataclass, field
from typing import Any

from ai_governance.scanning.base import BaseScanner

# Top-level request fields that are never scanned as text.
UNSCANNED_REQUEST_FIELDS = {"model"}

# Short structural values that the API matches exactly (a tool result must
# carry the same tool_call_id as the call it answers). They are left alone:
# rewriting one would break the request without protecting anything.
STRUCTURAL_KEYS = {"role", "type", "id", "tool_call_id", "object", "finish_reason", "system_fingerprint"}

# Content part types whose text can be scanned.
TEXT_PART_TYPES = {"text", "input_text", "output_text", "refusal"}


@dataclass
class PayloadScan:
    """Outcome of scanning a whole request or response body."""

    status: str  # BLOCKED, REDACTED or CLEAN
    payload: Any  # The body with redactions applied (the original if nothing changed)
    violations: list[dict[str, Any]] = field(default_factory=list)
    unscannable: list[str] = field(default_factory=list)  # Content part types that could not be scanned


class _Walker:
    def __init__(self, scanner: BaseScanner) -> None:
        self.scanner = scanner
        self.violations: list[dict[str, Any]] = []
        self.unscannable: list[str] = []
        self.blocked = False
        self.redacted = False

    def text(self, value: str) -> str:
        if not value:
            return value
        result = self.scanner.scan(value)
        self.violations.extend(result.violations)
        if result.status == "BLOCKED":
            self.blocked = True
        elif result.status == "REDACTED" and result.text is not None:
            self.redacted = True
            return result.text
        return value

    def walk(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.walk(item) for item in value]
        if isinstance(value, dict):
            return {
                key: item if key in STRUCTURAL_KEYS and isinstance(item, str) else self.walk(item)
                for key, item in value.items()
            }
        return value

    def message(self, message: Any) -> Any:
        """Walk one chat message, setting aside content parts that are not text."""
        if not isinstance(message, dict) or not isinstance(message.get("content"), list):
            return self.walk(message)
        scanned = self.walk({key: item for key, item in message.items() if key != "content"})
        parts = []
        for part in message["content"]:
            part_type = part.get("type") if isinstance(part, dict) else None
            if isinstance(part, dict) and part_type not in TEXT_PART_TYPES:
                self.unscannable.append(str(part_type))
                parts.append(part)  # Left as is; the caller decides whether to allow it
            else:
                parts.append(self.walk(part))
        scanned["content"] = parts
        return scanned

    def result(self, payload: Any) -> PayloadScan:
        status = "BLOCKED" if self.blocked else "REDACTED" if self.redacted else "CLEAN"
        return PayloadScan(status=status, payload=payload, violations=self.violations, unscannable=self.unscannable)


def scan_request_payload(payload: dict[str, Any], scanner: BaseScanner) -> PayloadScan:
    """Scan every piece of text in a chat completion request."""
    walker = _Walker(scanner)
    scanned: dict[str, Any] = {}
    for key, value in payload.items():
        if key in UNSCANNED_REQUEST_FIELDS:
            scanned[key] = value
        elif key == "messages" and isinstance(value, list):
            scanned[key] = [walker.message(message) for message in value]
        else:
            scanned[key] = walker.walk(value)
    return walker.result(scanned)


def scan_response_payload(response: Any, scanner: BaseScanner) -> PayloadScan:
    """Scan every piece of text in a model response: all choices, tool calls and refusals."""
    walker = _Walker(scanner)
    if isinstance(response, dict):
        # The model name the provider echoes back is not model output.
        return walker.result({k: v if k == "model" else walker.walk(v) for k, v in response.items()})
    return walker.result(walker.walk(response))
