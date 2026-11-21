from __future__ import annotations

from typing import Any, Literal, Protocol, TypeVar, cast

from openai import APIConnectionError, APITimeoutError, OpenAI, RateLimitError
from pydantic import BaseModel
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

from .base import StructuredResult, UsageRecord

T = TypeVar("T", bound=BaseModel)


class StructuredOutputError(RuntimeError):
    """Raised when the API completes without a parsed structured value."""


class _ResponsesResource(Protocol):
    def parse(self, **kwargs: Any) -> Any: ...


class _Client(Protocol):
    responses: _ResponsesResource


class OpenAIProvider:
    """Thin Responses API adapter with typed outputs and usage accounting."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        reasoning_effort: Literal["low", "medium", "high", "xhigh", "max"] = "low",
        client: _Client | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("OpenAI API key is required for the live provider")
        if not model.strip():
            raise ValueError("OpenAI model name is required")
        self._model = model
        self._reasoning_effort = reasoning_effort
        self._client = client or cast(_Client, OpenAI(api_key=api_key))

    @retry(
        retry=retry_if_exception_type((APIConnectionError, APITimeoutError, RateLimitError)),
        wait=wait_exponential_jitter(multiplier=0.5, max=8),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def generate(
        self,
        *,
        schema: type[T],
        instructions: str,
        user_input: str,
        max_output_tokens: int = 2000,
        safety_identifier: str | None = None,
    ) -> StructuredResult[T]:
        if not instructions.strip() or not user_input.strip():
            raise ValueError("instructions and user input must be non-empty")
        if max_output_tokens < 1 or max_output_tokens > 16_000:
            raise ValueError("max_output_tokens must be between 1 and 16000")

        response = self._client.responses.parse(
            model=self._model,
            instructions=instructions,
            input=user_input,
            text_format=schema,
            max_output_tokens=max_output_tokens,
            reasoning={"effort": self._reasoning_effort},
            safety_identifier=safety_identifier,
            store=False,
        )
        parsed = response.output_parsed
        if parsed is None or not isinstance(parsed, schema):
            raise StructuredOutputError("OpenAI response did not contain the expected parsed value")
        usage = response.usage
        usage_record = UsageRecord(
            input_tokens=usage.input_tokens if usage else 0,
            output_tokens=usage.output_tokens if usage else 0,
            cached_input_tokens=usage.input_tokens_details.cached_tokens if usage else 0,
            total_tokens=usage.total_tokens if usage else 0,
        )
        return StructuredResult(
            value=parsed,
            response_id=response.id,
            model=response.model,
            usage=usage_record,
        )
