"""Output scanner (Layer 5).

Scans LLM-generated responses for data leakage (secrets, PII the model
may have memorized from training data) and suspicious content before
returning to the user.

Responses are checked against the same patterns as prompts. What happens
on a match comes from the policy file:

- `output_rules` in the policy sets the action for a pattern in responses.
- A pattern with no output rule is blocked in responses if prompts
  containing it are blocked, and otherwise allowed. Models routinely write
  example e-mail addresses and IP addresses, so redact-level data is not
  touched in responses unless the policy asks for it.

Like the input scanner, this module has NO Rich dependency.
"""

import logging
from typing import Any

from ai_governance.models import ScanResult
from ai_governance.policy.loader import get_data_rule
from ai_governance.scanning.base import BaseScanner
from ai_governance.scanning.patterns import INPUT_PATTERNS, OUTPUT_ONLY_PATTERNS, find_matches

logger = logging.getLogger(__name__)


class OutputScanner(BaseScanner):
    """Scans outbound LLM responses for data leakage and policy violations."""

    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy

    def action_for(self, pattern_key: str) -> str:
        """The action the policy sets for a pattern when it appears in a response."""
        explicit = self.policy.get("output_rules", {}).get(pattern_key)
        if isinstance(explicit, dict) and explicit.get("action"):
            return str(explicit["action"])
        if pattern_key in OUTPUT_ONLY_PATTERNS:
            return "BLOCK"
        return "BLOCK" if get_data_rule(self.policy, pattern_key).get("action") == "BLOCK" else "ALLOW"

    def scan(self, text: str) -> ScanResult:
        """Scan an LLM response for data leakage.

        Args:
            text: The raw LLM response.

        Returns:
            ScanResult with:
              - status: BLOCKED if any block-action pattern matched,
                        REDACTED if any redact-action pattern matched,
                        CLEAN otherwise.
              - text: The response (redacted if needed), or a blocked message.
              - violations: List of all matches.
        """
        violations: list[dict[str, Any]] = []
        modified_text = text
        is_blocked = False
        is_redacted = False

        patterns = [(key, definition, f"LEAKED_{definition.name}") for key, definition in INPUT_PATTERNS.items()]
        patterns += [(key, definition, definition.name) for key, definition in OUTPUT_ONLY_PATTERNS.items()]

        for pattern_key, pattern_def, violation_type in patterns:
            action = self.action_for(pattern_key)
            if action == "ALLOW":
                continue

            for match_value in find_matches(pattern_def, text):
                violations.append(
                    {
                        "type": violation_type,
                        "action": action,
                        "matched_value": _mask_for_logging(match_value),
                    }
                )
                if action == "REDACT":
                    modified_text = modified_text.replace(match_value, f"[{pattern_def.name}_REDACTED]")
                    is_redacted = True
                else:
                    # BLOCK, and anything unrecognized: never let it through.
                    is_blocked = True

                logger.warning("Output scan: %s detected in LLM response (action=%s).", violation_type, action)

        if is_blocked:
            return ScanResult(
                status="BLOCKED",
                text="[BLOCKED_BY_POLICY] Response contained prohibited content.",
                violations=violations,
            )
        if is_redacted:
            return ScanResult(status="REDACTED", text=modified_text, violations=violations)

        return ScanResult(status="CLEAN", text=text, violations=[])


def _mask_for_logging(value: str) -> str:
    """Partially mask a matched value for safe inclusion in logs."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * (len(value) - 5)}{value[-2:]}"
