"""Sends a copy of the audit log's head record to another system.

The head record says how many entries the log has and the hash of the
newest one. A copy kept on a system the proxy host cannot change is the
one thing an attacker on the host cannot rewrite, so it is what proves
later that entries were removed or an older log was put back.

Any HTTPS endpoint that accepts a JSON POST works: a SIEM's HTTP collector,
a logging service, or a small function that writes to write-once storage.

Sending happens on a background thread, so a slow or unreachable endpoint
never delays a request. Only the newest head record matters, so if several
are waiting, only the latest is sent.
"""

import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)

Send = Callable[[dict[str, Any]], None]


class AnchorPublisher:
    """Posts the newest audit head record to a URL, retrying until it succeeds."""

    def __init__(self, url: str, send: Send | None = None, retry_seconds: float = 30.0) -> None:
        self.url = url
        self._send = send or self._post
        self._retry_seconds = retry_seconds
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._latest: dict[str, Any] | None = None
        self._last_success: str | None = None
        self._last_entries = 0
        self._failures = 0
        threading.Thread(target=self._run, name="audit-anchor", daemon=True).start()

    def submit(self, head: dict[str, Any]) -> None:
        """Queue a head record for sending. Returns immediately."""
        with self._lock:
            self._latest = head
        self._wake.set()

    def status(self) -> dict[str, Any]:
        """What /health reports about anchoring."""
        with self._lock:
            return {
                "configured": True,
                "last_success": self._last_success,
                "last_entries_anchored": self._last_entries,
                "consecutive_failures": self._failures,
            }

    def _post(self, payload: dict[str, Any]) -> None:
        httpx.post(self.url, json=payload, timeout=10.0).raise_for_status()

    def _run(self) -> None:
        while True:
            self._wake.wait()
            self._wake.clear()
            with self._lock:
                head, self._latest = self._latest, None
            if head is None:
                continue
            try:
                self._send({"source": "ai-governance-proxy", "type": "audit_head", **head})
            except Exception as e:
                with self._lock:
                    self._failures += 1
                    if self._latest is None:
                        self._latest = head  # Keep it for the retry unless a newer one arrived
                logger.warning("Audit anchor could not be sent (%s). Will retry.", type(e).__name__)
                time.sleep(self._retry_seconds)
                self._wake.set()
                continue
            with self._lock:
                self._failures = 0
                self._last_success = datetime.now(UTC).isoformat()
                self._last_entries = int(head.get("entries", 0))
