from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel

from data_incident_investigator.llm.openai_provider import (
    OpenAIProvider,
    StructuredOutputError,
)


class Answer(BaseModel):
    root_cause: str
    confidence: float


class FakeResponses:
    def __init__(self, parsed: object) -> None:
        self.parsed = parsed
        self.calls: list[dict[str, Any]] = []

    def parse(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        usage = SimpleNamespace(
            input_tokens=100,
            output_tokens=20,
            total_tokens=120,
            input_tokens_details=SimpleNamespace(cached_tokens=40),
        )
        return SimpleNamespace(
            output_parsed=self.parsed,
            usage=usage,
            id="resp_test",
            model="test-model",
        )


class FakeClient:
    def __init__(self, responses: FakeResponses) -> None:
        self.responses = responses


def test_provider_returns_typed_result_without_storing_response() -> None:
    resource = FakeResponses(Answer(root_cause="timezone_mismatch", confidence=0.92))
    provider = OpenAIProvider(api_key="test", model="test-model", client=FakeClient(resource))

    result = provider.generate(
        schema=Answer,
        instructions="Return a structured diagnosis.",
        user_input="The UTC watermark rejected local timestamps.",
        safety_identifier="case-hash",
    )

    assert result.value.root_cause == "timezone_mismatch"
    assert result.usage.total_tokens == 120
    assert result.usage.cached_input_tokens == 40
    assert resource.calls[0]["store"] is False
    assert resource.calls[0]["text_format"] is Answer


def test_provider_rejects_missing_or_wrong_structured_value() -> None:
    provider = OpenAIProvider(
        api_key="test",
        model="test-model",
        client=FakeClient(FakeResponses(None)),
    )
    with pytest.raises(StructuredOutputError):
        provider.generate(schema=Answer, instructions="Diagnose.", user_input="Incident.")


@pytest.mark.parametrize(
    ("api_key", "model"),
    [("", "model"), ("key", "")],
)
def test_provider_requires_credentials_and_model(api_key: str, model: str) -> None:
    with pytest.raises(ValueError):
        OpenAIProvider(api_key=api_key, model=model)


def test_provider_validates_prompt_and_output_limit() -> None:
    provider = OpenAIProvider(
        api_key="test",
        model="test-model",
        client=FakeClient(FakeResponses(Answer(root_cause="x", confidence=1))),
    )
    with pytest.raises(ValueError, match="non-empty"):
        provider.generate(schema=Answer, instructions="", user_input="Incident.")
    with pytest.raises(ValueError, match="max_output_tokens"):
        provider.generate(
            schema=Answer,
            instructions="Diagnose.",
            user_input="Incident.",
            max_output_tokens=0,
        )
