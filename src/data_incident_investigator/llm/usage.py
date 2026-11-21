"""Thread-safe token and cost accounting around structured model providers."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock

from pydantic import BaseModel

from .base import StructuredModelProvider, StructuredResult, UsageRecord


@dataclass(frozen=True, slots=True)
class UsageSnapshot:
    call_count: int
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    estimated_cost_usd: float

    def delta(self, earlier: UsageSnapshot) -> UsageSnapshot:
        return UsageSnapshot(
            call_count=self.call_count - earlier.call_count,
            input_tokens=self.input_tokens - earlier.input_tokens,
            output_tokens=self.output_tokens - earlier.output_tokens,
            cached_input_tokens=self.cached_input_tokens - earlier.cached_input_tokens,
            estimated_cost_usd=self.estimated_cost_usd - earlier.estimated_cost_usd,
        )


class UsageLedger:
    def __init__(
        self,
        *,
        input_cost_per_million: float,
        cached_input_cost_per_million: float,
        output_cost_per_million: float,
    ) -> None:
        self._input_rate = input_cost_per_million
        self._cached_rate = cached_input_cost_per_million
        self._output_rate = output_cost_per_million
        self._lock = Lock()
        self._records: list[UsageRecord] = []

    def record(self, usage: UsageRecord) -> None:
        with self._lock:
            self._records.append(usage)

    def snapshot(self) -> UsageSnapshot:
        with self._lock:
            records = tuple(self._records)
        input_tokens = sum(item.input_tokens for item in records)
        output_tokens = sum(item.output_tokens for item in records)
        cached_tokens = sum(item.cached_input_tokens for item in records)
        uncached_tokens = max(input_tokens - cached_tokens, 0)
        cost = (
            uncached_tokens * self._input_rate
            + cached_tokens * self._cached_rate
            + output_tokens * self._output_rate
        ) / 1_000_000
        return UsageSnapshot(
            call_count=len(records),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_input_tokens=cached_tokens,
            estimated_cost_usd=cost,
        )


class RecordingProvider:
    def __init__(self, provider: StructuredModelProvider, ledger: UsageLedger) -> None:
        self._provider = provider
        self._ledger = ledger

    def generate[T: BaseModel](
        self,
        *,
        schema: type[T],
        instructions: str,
        user_input: str,
        max_output_tokens: int = 2000,
        safety_identifier: str | None = None,
    ) -> StructuredResult[T]:
        result = self._provider.generate(
            schema=schema,
            instructions=instructions,
            user_input=user_input,
            max_output_tokens=max_output_tokens,
            safety_identifier=safety_identifier,
        )
        self._ledger.record(result.usage)
        return result
