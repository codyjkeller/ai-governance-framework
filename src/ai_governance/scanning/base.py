"""Abstract base class for all scanners.

Defines the interface that every scanner (input, output, future ML-based)
must implement. This is the Strategy pattern — the server doesn't care
which scanner implementation it's using, only that it returns a ScanResult.
"""

from abc import ABC, abstractmethod

from ai_governance.models import ScanResult


class BaseScanner(ABC):
    """Interface for prompt/response scanners.

    All scanners must implement the `scan` method and return
    a standardized ScanResult.
    """

    @abstractmethod
    def scan(self, text: str) -> ScanResult:
        """Scan the provided text and return a result.

        Args:
            text: The text to scan (prompt or LLM response).

        Returns:
            ScanResult with status (BLOCKED/REDACTED/CLEAN),
            the processed text, and any violations found.
        """
        ...
