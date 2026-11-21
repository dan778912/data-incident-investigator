from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from data_incident_investigator.llm import (
    RecordingProvider,
    StructuredResult,
    UsageLedger,
    UsageRecord,
)


class Answer(BaseModel):
    value: str


class FixedProvider:
    def generate(
        self,
        *,
        schema: type[BaseModel],
        instructions: str,
        user_input: str,
        max_output_tokens: int = 2000,
        safety_identifier: str | None = None,
    ) -> StructuredResult[Any]:
        return StructuredResult(
            value=Answer(value="ok"),
            response_id="response",
            model="model",
            usage=UsageRecord(
                input_tokens=100,
                output_tokens=20,
                cached_input_tokens=40,
                total_tokens=120,
            ),
        )


def test_recording_provider_tracks_token_cost_and_snapshot_delta() -> None:
    ledger = UsageLedger(
        input_cost_per_million=8,
        cached_input_cost_per_million=0.4,
        output_cost_per_million=40,
    )
    before = ledger.snapshot()
    provider = RecordingProvider(FixedProvider(), ledger)

    result = provider.generate(
        schema=Answer,
        instructions="Return the typed answer.",
        user_input="Test input.",
    )
    delta = ledger.snapshot().delta(before)

    assert result.value.value == "ok"
    assert delta.call_count == 1
    assert delta.input_tokens == 100
    assert delta.cached_input_tokens == 40
    assert delta.output_tokens == 20
    assert delta.estimated_cost_usd == 0.001296
