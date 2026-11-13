"""Audit logger with integrity verification.

Records every governance decision (BLOCK, REDACT, CLEAN) to a JSONL file.
Each log entry includes a SHA-256 hash of the previous entry, creating
a tamper-evident chain. If any entry is modified or deleted, the chain
breaks and verification will detect it.

This is NOT true immutability (that requires write-once storage like
S3 Object Lock). This is tamper-evidence — you can detect modification
after the fact. For production, ship these logs to a SIEM or write-once
store in addition to local file output.

Two additions make the chain hold up in practice:

- Several server workers can share one log file. Each write takes a file
  lock and reads the current end of the file, so the chain never forks.
- A small "head" file next to the log records how many entries there are
  and the hash of the newest one. Deleting entries from the end of the log
  leaves the chain itself intact, and the head record is what exposes it.

Hashes alone can be recomputed by anyone who can write the files, so two
further protections close that gap:

- Signing. With a secret key (AUDIT_HMAC_KEY) every entry and the head
  record carry an HMAC. Without the key nobody can produce a valid entry
  or a valid head record, so rewriting both files no longer works.
- Anchoring. The newest head record can be sent to another system after
  every write (see anchor.py). A copy held somewhere the proxy host cannot
  change is what defeats the remaining trick: putting back an older, validly
  signed log and head record. verify_anchor() checks any stored copy
  against the log.
"""

import hashlib
import hmac
import json
import logging
import os
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # File locking between processes. Not available on Windows.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class AuditWriteError(Exception):
    """An audit entry could not be recorded. The caller must not continue the request."""


class AuditLogger:
    """Tamper-evident JSONL audit logger.

    Each entry includes a `prev_hash` field containing the SHA-256
    hash of the previous entry's JSON string. The first entry uses
    a well-known genesis hash.
    """

    GENESIS_HASH = "0" * 64  # SHA-256 of "nothing" — the start of the chain

    def __init__(
        self,
        log_path: Path,
        hmac_key: str | None = None,
        on_head: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        """Create a logger.

        Args:
            log_path: The JSONL file to append to.
            hmac_key: Secret used to sign entries and the head record. Keep it
                out of the log directory. None leaves the log unsigned.
            on_head: Called with the new head record after every write, for
                sending a copy to another system.
        """
        self._key = hmac_key.encode("utf-8") if hmac_key else None
        self._on_head = on_head
        self._highest_seen = 0  # Most entries this process has ever seen in the log
        self.log_path = log_path
        self.head_path = log_path.with_name(log_path.name + ".head")
        self._lock_path = log_path.with_name(log_path.name + ".lock")
        self._thread_lock = threading.Lock()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._recover_chain_head()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Hold the log for one writer at a time, across threads and worker processes."""
        with self._thread_lock, open(self._lock_path, "a") as lock_file:
            if fcntl is not None:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

    def _read_last_line(self) -> str:
        """Return the newest entry in the log file ('' if there is none)."""
        if not self.log_path.exists():
            return ""
        with open(self.log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            window = 65536
            while True:
                start = max(0, size - window)
                f.seek(start)
                lines = [line for line in f.read().splitlines() if line.strip()]
                # The first line of a partial read may be cut off, so keep widening
                # until a whole last line is certain to be in the window.
                if start == 0 or len(lines) > 1:
                    return lines[-1].decode("utf-8").strip() if lines else ""
                window *= 2

    def _mac(self, text: str) -> str:
        """Sign text with the secret key."""
        if self._key is None:  # pragma: no cover - callers check first
            msg = "No signing key is configured."
            raise ValueError(msg)
        return hmac.new(self._key, text.encode("utf-8"), hashlib.sha256).hexdigest()

    def _head_mac(self, entries: int, last_hash: str) -> str:
        return self._mac(f"head:{entries}:{last_hash}")

    def _entry_is_signed_correctly(self, entry: dict[str, Any]) -> bool:
        """Check an entry's signature. The signature covers every other field."""
        unsigned = {k: v for k, v in entry.items() if k != "mac"}
        expected = self._mac(json.dumps(unsigned, separators=(",", ":")))
        return hmac.compare_digest(str(entry.get("mac", "")), expected)

    def _read_head(self) -> tuple[int, str] | None:
        """Return (entry count, newest hash) from the head record, or None if absent.

        Raises:
            ValueError: If signing is on and the head record's signature is wrong.
        """
        if not self.head_path.exists():
            return None
        head = json.loads(self.head_path.read_text())
        entries, last_hash = int(head["entries"]), str(head["last_hash"])
        if self._key is not None and not hmac.compare_digest(
            str(head.get("mac", "")), self._head_mac(entries, last_hash)
        ):
            msg = "The audit head record is not signed with the configured key."
            raise ValueError(msg)
        return entries, last_hash

    def _count_entries(self) -> int:
        if not self.log_path.exists():
            return 0
        with open(self.log_path) as f:
            return sum(1 for line in f if line.strip())

    def _entries_before_write(self, last_line: str) -> int:
        """Work out how many entries exist, and refuse to continue if the log was altered."""
        count = self._entries_from_head(last_line)
        if count < self._highest_seen:
            # This process has already seen a longer log. A shorter one with a
            # valid head record means an older copy was put back.
            msg = "The audit log is shorter than it was. An older copy may have been restored."
            raise AuditWriteError(msg)
        return count

    def _entries_from_head(self, last_line: str) -> int:
        try:
            last_entry = json.loads(last_line) if last_line else {}
        except json.JSONDecodeError:
            last_entry = {}

        head = self._read_head()
        if head is None:
            if self._key is not None and "mac" in last_entry:
                # A signed log always has a head record. Its absence means it was removed.
                msg = "The audit head record is missing."
                raise AuditWriteError(msg)
            return self._count_entries()  # First write, or a log from before head records existed
        head_count, head_hash = head
        last_hash = self._hash_entry(last_line) if last_line else self.GENESIS_HASH
        if head_hash == last_hash:
            return head_count
        if last_entry.get("prev_hash") == head_hash:
            # A crash between writing an entry and updating the head record.
            return head_count + 1
        msg = "The audit log does not match its head record. Entries may have been removed or changed."
        raise AuditWriteError(msg)

    def _recover_chain_head(self) -> str:
        """Read the last entry's hash to continue the chain on restart.

        If the log file doesn't exist or is empty, start a new chain.
        """
        if not self.log_path.exists():
            return self.GENESIS_HASH

        try:
            last_line = ""
            with open(self.log_path) as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
            if last_line:
                return self._hash_entry(last_line)
        except Exception:
            logger.warning("Could not recover audit chain head. Starting new chain.")

        return self.GENESIS_HASH

    def log_event(
        self,
        event_type: str,
        transaction_id: str,
        status: str,
        details: str | list[Any],
        user_id: str = "unknown",
        policy_version: str = "unknown",
        enforced: bool = True,
        client_user_id: str | None = None,
    ) -> None:
        """Append a tamper-evident audit entry.

        Args:
            event_type: Category of event (INPUT_SCAN, OUTPUT_SCAN, TRANSACTION_COMPLETE).
            transaction_id: Unique ID for this request.
            status: Outcome (BLOCKED, REDACTED, CLEAN, SUCCESS).
            details: Human-readable description or list of violations.
            user_id: Identity of the requester.
            policy_version: Version string from the active policy.
            enforced: False in monitoring mode, where the status records what
                would have happened and the request was not actually changed.
            client_user_id: The user_id the caller put in the request, if any.
                It is not verified, so it is kept apart from user_id.

        Raises:
            AuditWriteError: If the entry could not be written. The caller must
                treat the request as failed: nothing goes through unaudited.
        """
        try:
            with self._locked():
                # Read the end of the file every time: another worker may have written since.
                last_line = self._read_last_line()
                count = self._entries_before_write(last_line)
                entry: dict[str, Any] = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "event_type": event_type,
                    "transaction_id": transaction_id,
                    "user_id": user_id,
                    "status": status,
                    "policy_version": policy_version,
                    "details": details,
                    "enforced": enforced,
                    "prev_hash": self._hash_entry(last_line) if last_line else self.GENESIS_HASH,
                }
                if client_user_id is not None:
                    entry["client_user_id"] = client_user_id
                if self._key is not None:
                    # Added last: the signature covers every field above it.
                    entry["mac"] = self._mac(json.dumps(entry, separators=(",", ":")))

                entry_json = json.dumps(entry, separators=(",", ":"))
                with open(self.log_path, "a") as f:
                    f.write(entry_json + "\n")
                    f.flush()
                    os.fsync(f.fileno())

                self._prev_hash = self._hash_entry(entry_json)
                head = self._write_head(count + 1, self._prev_hash)
                self._highest_seen = count + 1
        except (OSError, ValueError, KeyError) as e:
            logger.error("Failed to write audit log: %s", e)
            msg = "The audit entry could not be written."
            raise AuditWriteError(msg) from e

        logger.info("audit_head entries=%d last_hash=%s", head["entries"], head["last_hash"])
        if self._on_head is not None:
            self._on_head({**head, "timestamp": entry["timestamp"]})

    def _write_head(self, entries: int, last_hash: str) -> dict[str, Any]:
        """Replace the head record in one step, so it is never left half written."""
        head: dict[str, Any] = {"entries": entries, "last_hash": last_hash}
        if self._key is not None:
            head["mac"] = self._head_mac(entries, last_hash)
        temporary = self.head_path.with_name(self.head_path.name + ".tmp")
        temporary.write_text(json.dumps(head))
        os.replace(temporary, self.head_path)
        return head

    @staticmethod
    def _hash_entry(entry_json: str) -> str:
        """Compute SHA-256 hash of a JSON log entry string."""
        return hashlib.sha256(entry_json.encode("utf-8")).hexdigest()

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the integrity of the entire audit log.

        Reads every entry and checks that each entry's prev_hash
        matches the hash of the preceding entry.

        It then compares the result with the head record, which catches
        entries deleted from the end of the log. When a signing key is
        configured, every entry's signature and the head record's signature
        are checked as well.

        Returns:
            Tuple of (is_valid, entries_checked).
            If is_valid is False, the chain was tampered with.
        """
        with self._locked():
            return self._verify_chain_locked()

    def _verify_chain_locked(self) -> tuple[bool, int]:
        if not self.log_path.exists():
            if self.head_path.exists():
                logger.error("Audit log is missing but its head record exists.")
                return False, 0
            return True, 0

        prev_hash = self.GENESIS_HASH
        count = 0
        seen_signed = False

        with open(self.log_path) as f:
            for line_num, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError:
                    logger.error("Audit chain broken: invalid JSON at line %d", line_num)
                    return False, count

                if entry.get("prev_hash") != prev_hash:
                    logger.error(
                        "Audit chain broken at line %d: expected prev_hash=%s, got=%s",
                        line_num,
                        prev_hash[:16] + "...",
                        str(entry.get("prev_hash", ""))[:16] + "...",
                    )
                    return False, count

                if self._key is not None:
                    # Entries written before signing was turned on have no signature.
                    # After the first signed entry, every entry must be signed.
                    if "mac" in entry:
                        seen_signed = True
                        if not self._entry_is_signed_correctly(entry):
                            logger.error("Audit entry at line %d has an invalid signature.", line_num)
                            return False, count
                    elif seen_signed:
                        logger.error("Audit entry at line %d is not signed.", line_num)
                        return False, count

                prev_hash = self._hash_entry(stripped)
                count += 1

        try:
            head = self._read_head()
        except (OSError, ValueError, KeyError):
            logger.error("Audit head record is unreadable.")
            return False, count
        if head is None:
            if count:
                # Without a head record there is no way to tell whether the newest entries were removed.
                logger.error("Audit log has entries but no head record.")
                return False, count
            return True, 0
        if head != (count, prev_hash):
            logger.error(
                "Audit log does not match its head record: log has %d entries, head record says %d.",
                count,
                head[0],
            )
            return False, count

        return True, count

    def verify_anchor(self, entries: int, last_hash: str) -> bool:
        """Check that a head record saved elsewhere still matches this log.

        Give it the entry count and hash from any copy of the head record that
        was stored outside this machine. It returns True only if the log still
        has that many entries and entry number `entries` has that hash. A log
        that was cut back, or replaced with an older copy, fails.
        """
        if entries < 1:
            return False
        with self._locked():
            if not self.log_path.exists():
                return False
            count = 0
            with open(self.log_path) as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    count += 1
                    if count == entries:
                        return hmac.compare_digest(self._hash_entry(stripped), last_hash)
        return False
