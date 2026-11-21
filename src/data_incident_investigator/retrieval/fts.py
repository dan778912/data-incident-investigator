from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Self

from data_incident_investigator.security.redaction import redact_secrets

_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{1,63}")


@dataclass(frozen=True, slots=True)
class EvidenceHit:
    evidence_id: str
    document_id: str
    source_id: str
    source: str
    excerpt: str
    locator: str
    version: str
    effective_date: str | None
    is_current: bool
    relevance_score: float

    def as_workflow_record(self) -> dict[str, str | float]:
        return {
            "evidence_id": self.evidence_id,
            "source_id": self.source_id,
            "source": f"{self.source} ({self.locator})",
            "excerpt": self.excerpt,
            "relevance_score": self.relevance_score,
        }


class FtsRunbookRepository:
    """SQLite FTS5 index that keeps source metadata separate from untrusted text."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self._connection.row_factory = sqlite3.Row

    @classmethod
    def open(cls, path: Path) -> Self:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, check_same_thread=False)
        repository = cls(connection)
        repository.setup()
        return repository

    def close(self) -> None:
        self._connection.close()

    def setup(self) -> None:
        self._connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS documents (
                document_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                version TEXT NOT NULL,
                effective_date TEXT,
                superseded_by TEXT
            );

            CREATE TABLE IF NOT EXISTS document_chunks (
                chunk_id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
                chunk_index INTEGER NOT NULL,
                content TEXT NOT NULL
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS document_chunks_fts USING fts5(
                chunk_id UNINDEXED,
                content,
                tokenize = 'unicode61'
            );
            """
        )
        columns = {
            row[1] for row in self._connection.execute("PRAGMA table_info(documents)").fetchall()
        }
        if "source_id" not in columns:
            self._connection.execute(
                "ALTER TABLE documents ADD COLUMN source_id TEXT NOT NULL DEFAULT ''"
            )
            self._connection.execute(
                "UPDATE documents SET source_id = document_id WHERE source_id = ''"
            )
        self._connection.commit()

    def index_document(
        self,
        *,
        document_id: str,
        source_id: str | None = None,
        source_name: str,
        text: str,
        version: str,
        effective_date: date | None = None,
        superseded_by: str | None = None,
    ) -> int:
        if not document_id.strip() or not source_name.strip() or not version.strip():
            raise ValueError("document identifiers, source name, and version are required")
        clean_text, _ = redact_secrets(text)
        chunks = self._chunk_text(clean_text)
        if not chunks:
            raise ValueError("document contains no indexable text")

        with self._connection:
            previous = self._connection.execute(
                "SELECT chunk_id FROM document_chunks WHERE document_id = ?", (document_id,)
            ).fetchall()
            if previous:
                self._connection.executemany(
                    "DELETE FROM document_chunks_fts WHERE chunk_id = ?",
                    [(row["chunk_id"],) for row in previous],
                )
            self._connection.execute(
                "DELETE FROM document_chunks WHERE document_id = ?", (document_id,)
            )
            self._connection.execute(
                """
                INSERT INTO documents(
                    document_id, source_id, source_name, version, effective_date, superseded_by
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(document_id) DO UPDATE SET
                    source_id = excluded.source_id,
                    source_name = excluded.source_name,
                    version = excluded.version,
                    effective_date = excluded.effective_date,
                    superseded_by = excluded.superseded_by
                """,
                (
                    document_id,
                    source_id or document_id,
                    source_name,
                    version,
                    effective_date.isoformat() if effective_date else None,
                    superseded_by,
                ),
            )
            for index, chunk in enumerate(chunks):
                chunk_id = f"{document_id}:chunk:{index}"
                self._connection.execute(
                    """
                    INSERT INTO document_chunks(chunk_id, document_id, chunk_index, content)
                    VALUES (?, ?, ?, ?)
                    """,
                    (chunk_id, document_id, index, chunk),
                )
                self._connection.execute(
                    "INSERT INTO document_chunks_fts(chunk_id, content) VALUES (?, ?)",
                    (chunk_id, chunk),
                )
        return len(chunks)

    def search(
        self,
        query: str,
        *,
        document_ids: list[str] | None = None,
        limit: int = 5,
    ) -> list[EvidenceHit]:
        if limit < 1 or limit > 20:
            raise ValueError("retrieval limit must be between 1 and 20")
        match_query = self._safe_match_query(query)
        filters = ""
        parameters: list[str | int] = [match_query]
        if document_ids:
            placeholders = ",".join("?" for _ in document_ids)
            filters = f" AND d.document_id IN ({placeholders})"
            parameters.extend(document_ids)
        parameters.append(limit)

        rows = self._connection.execute(
            f"""
            SELECT
                c.chunk_id,
                c.document_id,
                c.chunk_index,
                c.content,
                d.source_id,
                d.source_name,
                d.version,
                d.effective_date,
                d.superseded_by,
                bm25(document_chunks_fts) AS rank
            FROM document_chunks_fts
            JOIN document_chunks AS c ON c.chunk_id = document_chunks_fts.chunk_id
            JOIN documents AS d ON d.document_id = c.document_id
            WHERE document_chunks_fts MATCH ?{filters}
            ORDER BY rank ASC
            LIMIT ?
            """,
            parameters,
        ).fetchall()
        return [
            EvidenceHit(
                evidence_id=row["chunk_id"],
                document_id=row["document_id"],
                source_id=row["source_id"],
                source=row["source_name"],
                excerpt=row["content"],
                locator=f"chunk-{row['chunk_index']}",
                version=row["version"],
                effective_date=row["effective_date"],
                is_current=row["superseded_by"] is None,
                relevance_score=round(1.0 / (1.0 + abs(float(row["rank"]))), 6),
            )
            for row in rows
        ]

    @staticmethod
    def _safe_match_query(query: str) -> str:
        tokens = _TOKEN_PATTERN.findall(query)[:12]
        if not tokens:
            raise ValueError("retrieval query contains no searchable terms")
        escaped = [token.replace('"', '""') for token in tokens]
        return " OR ".join(f'"{token}"' for token in escaped)

    @staticmethod
    def _chunk_text(text: str, *, max_chars: int = 1200) -> list[str]:
        paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text) if part.strip()]
        chunks: list[str] = []
        current = ""
        for paragraph in paragraphs:
            if len(paragraph) > max_chars:
                if current:
                    chunks.append(current)
                    current = ""
                chunks.extend(
                    paragraph[index : index + max_chars]
                    for index in range(0, len(paragraph), max_chars)
                )
            elif not current:
                current = paragraph
            elif len(current) + len(paragraph) + 2 <= max_chars:
                current = f"{current}\n\n{paragraph}"
            else:
                chunks.append(current)
                current = paragraph
        if current:
            chunks.append(current)
        return chunks
