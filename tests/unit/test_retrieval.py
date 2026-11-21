from __future__ import annotations

import sqlite3
from datetime import date

import pytest

from data_incident_investigator.retrieval import FtsRunbookRepository


@pytest.fixture
def repository() -> FtsRunbookRepository:
    connection = sqlite3.connect(":memory:")
    repo = FtsRunbookRepository(connection)
    repo.setup()
    yield repo
    repo.close()


def test_index_and_search_preserve_provenance(repository: FtsRunbookRepository) -> None:
    count = repository.index_document(
        document_id="timestamp-v2",
        source_name="Timestamp Handling Runbook",
        text=(
            "All event timestamps must be normalized to UTC before watermark comparison.\n\n"
            "Naive local timestamps can appear late and be rejected by the ingestion window."
        ),
        version="2.0",
        effective_date=date(2026, 9, 1),
    )

    hits = repository.search("watermark UTC timestamps")

    assert count == 1
    assert hits[0].document_id == "timestamp-v2"
    assert hits[0].is_current is True
    assert hits[0].effective_date == "2026-09-01"
    assert hits[0].as_workflow_record()["evidence_id"] == hits[0].evidence_id


def test_search_filters_documents_and_marks_stale_sources(
    repository: FtsRunbookRepository,
) -> None:
    repository.index_document(
        document_id="schema-v1",
        source_name="Old Schema",
        text="The legacy field is customer_id.",
        version="1",
        superseded_by="schema-v2",
    )
    repository.index_document(
        document_id="schema-v2",
        source_name="Current Schema",
        text="The current field is customerId after the rename.",
        version="2",
    )

    old_hits = repository.search("customer field", document_ids=["schema-v1"])
    current_hits = repository.search("customer field", document_ids=["schema-v2"])

    assert old_hits[0].is_current is False
    assert current_hits[0].is_current is True


def test_reindex_replaces_old_chunks_and_redacts_secrets(
    repository: FtsRunbookRepository,
) -> None:
    repository.index_document(
        document_id="runbook",
        source_name="Runbook",
        text="old duplicate-key advice sk-abcdefghijklmnopqrstuvwxyz123456",
        version="1",
    )
    repository.index_document(
        document_id="runbook",
        source_name="Runbook",
        text="new join-cardinality advice",
        version="2",
    )

    assert repository.search("join cardinality")[0].version == "2"
    assert repository.search("duplicate") == []


@pytest.mark.parametrize("query", ["", "! @ #"])
def test_search_rejects_non_searchable_queries(
    repository: FtsRunbookRepository,
    query: str,
) -> None:
    with pytest.raises(ValueError, match="searchable"):
        repository.search(query)


def test_search_rejects_unsafe_limits(repository: FtsRunbookRepository) -> None:
    with pytest.raises(ValueError, match="limit"):
        repository.search("timestamp", limit=0)
