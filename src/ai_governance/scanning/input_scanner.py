"""Input scanner (Layer 1).

Scans user prompts against regex patterns and applies policy actions
(BLOCK, REDACT, ALLOW) based on the YAML policy rules.

This module has NO dependency on Rich or any terminal UI library.
It returns structured data that the caller (server or CLI) can
format however it needs to.
"""

import logging
from typing import Any

from ai_governance.models import ScanResult
from ai_governance.policy.loader import get_data_rule
from ai_governance.scanning.base import BaseScanner
from ai_governance.scanning.patterns import INPUT_PATTERNS

logger = logging.getLogger(__name__)


class InputScanner(BaseScanner):
    """Scans inbound prompts for PII, PHI, and secrets.

    Uses regex patterns from the pattern registry and enforces
    actions defined in the YAML policy file.
    """

    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy

    def scan(self, text: str) -> ScanResult:
        """Scan a prompt for sensitive data.

        Args:
            text: The raw user prompt.

        Returns:
            ScanResult with:
              - status: BLOCKED if any BLOCK-action pattern matched,
                        REDACTED if any REDACT-action pattern matched,
                        CLEAN if nothing matched.
              - text: The sanitized prompt (None if blocked).
              - violations: List of all matches with metadata.
        """
        violations: list[dict] = []
        modified_text = text
        is_blocked = False

        for pattern_key, pattern_def in INPUT_PATTERNS.items():
            rule = get_data_rule(self.policy, pattern_key)
            action = rule.get("action", "REDACT")
            sensitivity = rule.get("sensitivity", "HIGH")

            matches = pattern_def.regex.findall(text)
            if not matches:
                continue

            # Deduplicate matches
            unique_matches = list(set(matches))

            for match_value in unique_matches:
                # If findall returns tuples (from capture groups), take the full match
                if isinstance(match_value, tuple):
                    match_value = match_value[0]

                violation = {
                    "type": pattern_def.name,
                    "sensitivity": sensitivity,
                    "action": action,
                    "matched_value": _mask_for_logging(match_value),
                }
                violations.append(violation)

                logger.info(
                    "Input scan: %s detected (sensitivity=%s, action=%s)",
                    pattern_def.name,
                    sensitivity,
                    action,
                )

                if action == "BLOCK":
                    is_blocked = True
                elif action == "REDACT":
                    modified_text = modified_text.replace(match_value, f"[{pattern_def.name}_REDACTED]")
                # ALLOW = do nothing

        if is_blocked:
            return ScanResult(status="BLOCKED", text=None, violations=violations)

        if violations:
            return ScanResult(status="REDACTED", text=modified_text, violations=violations)

        return ScanResult(status="CLEAN", text=text, violations=[])


def _mask_for_logging(value: str) -> str:
    """Partially mask a matched value for safe inclusion in logs.

    We never want the full sensitive value appearing in log files.
    Shows first 3 and last 2 characters for values > 8 chars,
    otherwise fully masks.
    """
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * (len(value) - 5)}{value[-2:]}"
