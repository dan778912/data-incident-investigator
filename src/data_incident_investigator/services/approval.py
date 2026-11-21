"""HMAC-bound approvals and replay ledgers."""

from __future__ import annotations

import hmac
import secrets
import sqlite3
import time
from hashlib import sha256
from pathlib import Path
from typing import Protocol

from data_incident_investigator.workflow.security import (
    ApprovalBindingMismatchError,
    ApprovalExpiredError,
    ApprovalReplayError,
    ApprovalValidationError,
    canonical_json,
)
from data_incident_investigator.workflow.state import (
    ApprovalDecisionRecord,
    ApprovalRecord,
    ApprovalRequestRecord,
)


class ApprovalLedger(Protocol):
    """Atomic storage contract for one-time approval nonces."""

    def reserve(self, *, nonce: str, expires_at: int) -> None: ...

    def consume(self, *, nonce: str, consumed_at: int) -> bool: ...


class Clock(Protocol):
    def now_epoch_seconds(self) -> int: ...


class NonceFactory(Protocol):
    def create(self) -> str: ...


class SystemClock:
    """Wall-clock implementation used outside deterministic tests."""

    def now_epoch_seconds(self) -> int:
        return int(time.time())


class SecureNonceFactory:
    """Generate unpredictable nonces with at least 256 bits of entropy."""

    def create(self) -> str:
        return secrets.token_urlsafe(32)


class SQLiteApprovalLedger:
    """File-backed nonce ledger with atomic single-use consumption."""

    def __init__(self, database_path: str | Path) -> None:
        self._path = Path(database_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_nonces (
                    nonce TEXT PRIMARY KEY,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def reserve(self, *, nonce: str, expires_at: int) -> None:
        connection = self._connect()
        try:
            connection.execute(
                "INSERT INTO approval_nonces (nonce, expires_at) VALUES (?, ?)",
                (nonce, expires_at),
            )
            connection.commit()
        except sqlite3.IntegrityError as exc:
            raise ApprovalValidationError("approval nonce collision") from exc
        finally:
            connection.close()

    def consume(self, *, nonce: str, consumed_at: int) -> bool:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE approval_nonces
                SET consumed_at = ?
                WHERE nonce = ?
                  AND consumed_at IS NULL
                  AND expires_at >= ?
                """,
                (consumed_at, nonce, consumed_at),
            )
            connection.commit()
            return cursor.rowcount == 1
        finally:
            connection.close()


class HMACApprovalBindingService:
    """Create and verify tamper-evident, expiring, single-use approvals."""

    def __init__(
        self,
        *,
        secret_key: bytes,
        ledger: ApprovalLedger,
        clock: Clock | None = None,
        nonce_factory: NonceFactory | None = None,
        ttl_seconds: int = 900,
    ) -> None:
        if len(secret_key) < 32:
            raise ValueError("approval HMAC key must contain at least 32 bytes")
        if ttl_seconds <= 0:
            raise ValueError("approval TTL must be positive")
        self._secret_key = secret_key
        self._ledger = ledger
        self._clock = clock or SystemClock()
        self._nonce_factory = nonce_factory or SecureNonceFactory()
        self._ttl_seconds = ttl_seconds

    def _mac(self, request: ApprovalRequestRecord) -> str:
        unsigned = {key: value for key, value in request.items() if key != "binding_mac"}
        return hmac.new(self._secret_key, canonical_json(unsigned), sha256).hexdigest()

    @staticmethod
    def _same(left: str, right: str) -> bool:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))

    def issue(
        self,
        *,
        case_id: str,
        proposal_hash: str,
        plan_hash: str,
        source_hash: str,
    ) -> ApprovalRequestRecord:
        now = self._clock.now_epoch_seconds()
        nonce = self._nonce_factory.create()
        if len(nonce) < 16:
            raise ApprovalValidationError("approval nonce must contain at least 16 characters")
        request: ApprovalRequestRecord = {
            "binding_version": "v1",
            "case_id": case_id,
            "proposal_hash": proposal_hash,
            "plan_hash": plan_hash,
            "source_hash": source_hash,
            "nonce": nonce,
            "issued_at": now,
            "expires_at": now + self._ttl_seconds,
            "binding_mac": "",
        }
        request["binding_mac"] = self._mac(request)
        self._ledger.reserve(nonce=nonce, expires_at=request["expires_at"])
        return request

    def validate_and_consume(
        self,
        *,
        request: ApprovalRequestRecord,
        decision: ApprovalDecisionRecord,
        current_proposal_hash: str,
        current_plan_hash: str,
        current_source_hash: str,
    ) -> ApprovalRecord:
        expected_mac = self._mac(request)
        if not self._same(request["binding_mac"], expected_mac):
            raise ApprovalBindingMismatchError("stored approval request failed HMAC validation")

        current_bindings = (
            ("proposal_hash", request["proposal_hash"], current_proposal_hash),
            ("plan_hash", request["plan_hash"], current_plan_hash),
            ("source_hash", request["source_hash"], current_source_hash),
        )
        for field, requested_value, current_value in current_bindings:
            if not self._same(requested_value, current_value):
                raise ApprovalBindingMismatchError(f"current {field} differs from approved context")

        echoed_fields = (
            "binding_version",
            "case_id",
            "proposal_hash",
            "plan_hash",
            "source_hash",
            "nonce",
            "issued_at",
            "expires_at",
            "binding_mac",
        )
        request_values: dict[str, object] = dict(request)
        decision_values: dict[str, object] = dict(decision)
        for field in echoed_fields:
            request_value = request_values[field]
            decision_value = decision_values[field]
            if isinstance(request_value, str) and isinstance(decision_value, str):
                matches = self._same(request_value, decision_value)
            else:
                matches = request_value == decision_value
            if not matches:
                raise ApprovalBindingMismatchError(f"resume payload changed signed field {field}")

        now = self._clock.now_epoch_seconds()
        if now > request["expires_at"]:
            raise ApprovalExpiredError("approval request has expired")
        if not self._ledger.consume(nonce=request["nonce"], consumed_at=now):
            raise ApprovalReplayError("approval nonce is unknown, expired, or already consumed")

        return {
            **decision,
            "decided_at": now,
        }
