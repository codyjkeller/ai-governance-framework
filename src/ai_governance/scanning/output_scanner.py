"""Output scanner (Layer 5).

Scans LLM-generated responses for data leakage (secrets, PII the model
may have memorized from training data) and suspicious content before
returning to the user.

Like the input scanner, this module has NO Rich dependency.
"""

import logging
from typing import Any

from ai_governance.models import ScanResult
from ai_governance.scanning.base import BaseScanner
from ai_governance.scanning.patterns import OUTPUT_PATTERNS

logger = logging.getLogger(__name__)


class OutputScanner(BaseScanner):
    """Scans outbound LLM responses for data leakage and policy violations.

    All output pattern matches result in BLOCK by default — if the LLM
    is leaking secrets or PII, we do not pass that to the user.
    """

    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy

    def scan(self, text: str) -> ScanResult:
        """Scan an LLM response for data leakage.

        Args:
            text: The raw LLM response.

        Returns:
            ScanResult with:
              - status: BLOCKED if any leak pattern matched, CLEAN otherwise.
              - text: The original response if clean, a blocked message if not.
              - violations: List of all matches.
        """
        violations: list[dict] = []

        for pattern_key, pattern_def in OUTPUT_PATTERNS.items():
            matches = pattern_def.regex.findall(text)
            if not matches:
                continue

            for match_value in set(matches):
                if isinstance(match_value, tuple):
                    match_value = match_value[0]

                violation = {
                    "type": pattern_def.name,
                    "action": "BLOCK",
                    "matched_value": _mask_for_logging(match_value),
                }
                violations.append(violation)

                logger.warning(
                    "Output scan: %s detected in LLM response — blocking.",
                    pattern_def.name,
                )

        if violations:
            return ScanResult(
                status="BLOCKED",
                text="[BLOCKED_BY_POLICY] Response contained prohibited content.",
                violations=violations,
            )

        return ScanResult(status="CLEAN", text=text, violations=[])


def _mask_for_logging(value: str) -> str:
    """Partially mask a matched value for safe inclusion in logs."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * (len(value) - 5)}{value[-2:]}"
