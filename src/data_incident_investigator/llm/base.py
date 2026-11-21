from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class UsageRecord:
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    total_tokens: int


@dataclass(frozen=True, slots=True)
class StructuredResult[T: BaseModel]:
    value: T
    response_id: str
    model: str
    usage: UsageRecord


class StructuredModelProvider(Protocol):
    def generate(
        self,
        *,
        schema: type[T],
        instructions: str,
        user_input: str,
        max_output_tokens: int = 2000,
        safety_identifier: str | None = None,
    ) -> StructuredResult[T]: ...
