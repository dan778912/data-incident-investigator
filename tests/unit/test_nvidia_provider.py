from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from openai import APITimeoutError
from openai.lib._pydantic import to_strict_json_schema
from pydantic import BaseModel

from data_incident_investigator.llm.nvidia_provider import (
    NvidiaProvider,
    NvidiaStructuredOutputError,
)
from data_incident_investigator.services.live import (
    EvidenceAssessmentDraft,
    HypothesesDraft,
    QueryDraft,
    RemediationDraft,
    VerificationDraft,
)


class Answer(BaseModel):
    root_cause: str
    confidence: float


class DefaultedAnswer(BaseModel):
    value: str
    explanation: str = "default"


class FakeCompletions:
    def __init__(
        self,
        content: str | None,
        *,
        choices: bool = True,
        finish_reason: str = "stop",
        response_id: str | None = "chatcmpl_test",
        response_model: str | None = "nvidia/test-model",
        include_usage: bool = True,
    ) -> None:
        self.content = content
        self.include_choices = choices
        self.finish_reason = finish_reason
        self.response_id = response_id
        self.response_model = response_model
        self.include_usage = include_usage
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        usage = SimpleNamespace(
            prompt_tokens=100,
            completion_tokens=20,
            total_tokens=120,
            prompt_tokens_details=SimpleNamespace(cached_tokens=40),
        )
        completion_choices = (
            [
                SimpleNamespace(
                    message=SimpleNamespace(content=self.content),
                    finish_reason=self.finish_reason,
                )
            ]
            if self.include_choices
            else []
        )
        return SimpleNamespace(
            choices=completion_choices,
            usage=usage if self.include_usage else None,
            id=self.response_id,
            model=self.response_model,
        )


class FakeClient:
    def __init__(self, completions: Any) -> None:
        self.chat = SimpleNamespace(completions=completions)


def test_provider_returns_typed_json_object_result() -> None:
    resource = FakeCompletions('{"root_cause":"timezone_mismatch","confidence":0.92}')
    provider = NvidiaProvider(
        api_key="test",
        model="nvidia/test-model",
        client=FakeClient(resource),
    )

    result = provider.generate(
        schema=Answer,
        instructions="Return a structured diagnosis.",
        user_input="The UTC watermark rejected local timestamps.",
        max_output_tokens=1234,
        safety_identifier="case-hash",
    )

    assert result.value.root_cause == "timezone_mismatch"
    assert result.usage.total_tokens == 120
    assert result.usage.cached_input_tokens == 40
    request = resource.calls[0]
    assert request["temperature"] == 0.0
    assert request["stream"] is False
    assert request["max_tokens"] == 1234
    assert request["messages"][1] == {
        "role": "user",
        "content": "The UTC watermark rejected local timestamps.",
    }
    system_content = request["messages"][0]["content"]
    assert system_content.startswith("Return a structured diagnosis.")
    assert '"additionalProperties":false' in system_content
    assert '"root_cause"' in system_content
    assert request["response_format"] == {"type": "json_object"}
    assert request["extra_body"] == {"chat_template_kwargs": {"enable_thinking": False}}
    assert "safety_identifier" not in request


def test_provider_can_opt_into_strict_json_schema_format() -> None:
    resource = FakeCompletions('{"root_cause":"x","confidence":1}')
    provider = NvidiaProvider(
        api_key="test",
        model="nvidia/test-model",
        response_format_mode="json_schema",
        client=FakeClient(resource),
    )

    provider.generate(schema=Answer, instructions="Diagnose.", user_input="Incident.")

    response_format = resource.calls[0]["response_format"]
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["name"] == "Answer"
    assert response_format["json_schema"]["strict"] is True
    assert response_format["json_schema"]["schema"] == to_strict_json_schema(Answer)


@pytest.mark.parametrize(
    "schema",
    [
        QueryDraft,
        EvidenceAssessmentDraft,
        HypothesesDraft,
        VerificationDraft,
        RemediationDraft,
    ],
)
def test_real_model_schemas_are_strict_at_every_object(schema: type[BaseModel]) -> None:
    resource = FakeCompletions("{}")
    provider = NvidiaProvider(
        api_key="test",
        model="nvidia/test-model",
        response_format_mode="json_schema",
        client=FakeClient(resource),
    )

    with pytest.raises(NvidiaStructuredOutputError):
        provider.generate(schema=schema, instructions="Return JSON.", user_input="Incident.")

    strict_schema = resource.calls[0]["response_format"]["json_schema"]["schema"]

    def assert_strict(value: object) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
                assert set(value.get("properties", {})) == set(value.get("required", []))
            for child in value.values():
                assert_strict(child)
        elif isinstance(value, list):
            for child in value:
                assert_strict(child)

    assert_strict(strict_schema)


@pytest.mark.parametrize(
    ("schema", "content"),
    [
        (Answer, '{"root_cause":"x","confidence":1,"extra":true}'),
        (DefaultedAnswer, '{"value":"x"}'),
    ],
)
def test_provider_enforces_strict_schema_before_pydantic(
    schema: type[BaseModel],
    content: str,
) -> None:
    resource = FakeCompletions(content)
    provider = NvidiaProvider(
        api_key="test",
        model="nvidia/test-model",
        client=FakeClient(resource),
    )

    with pytest.raises(NvidiaStructuredOutputError):
        provider.generate(schema=schema, instructions="Return JSON.", user_input="Incident.")

    assert len(resource.calls) == 1


@pytest.mark.parametrize(
    ("content", "choices"),
    [
        ("not-json", True),
        ('{"root_cause":"x"}', True),
        (None, True),
        ('{"root_cause":"x","confidence":1}', False),
    ],
)
def test_provider_rejects_missing_or_invalid_structured_output_without_retry(
    content: str | None,
    choices: bool,
) -> None:
    resource = FakeCompletions(content, choices=choices)
    provider = NvidiaProvider(
        api_key="test",
        model="nvidia/test-model",
        client=FakeClient(resource),
    )

    with pytest.raises(NvidiaStructuredOutputError):
        provider.generate(schema=Answer, instructions="Diagnose.", user_input="Incident.")

    assert len(resource.calls) == 1


def test_provider_rejects_truncated_completion_without_retry() -> None:
    resource = FakeCompletions(
        '{"root_cause":"x","confidence":1}',
        finish_reason="length",
    )
    provider = NvidiaProvider(
        api_key="test",
        model="nvidia/test-model",
        client=FakeClient(resource),
    )

    with pytest.raises(NvidiaStructuredOutputError, match="finish normally"):
        provider.generate(schema=Answer, instructions="Diagnose.", user_input="Incident.")

    assert len(resource.calls) == 1


@pytest.mark.parametrize(
    ("response_id", "response_model", "include_usage"),
    [
        (None, "nvidia/test-model", True),
        ("chatcmpl_test", None, True),
        ("chatcmpl_test", "nvidia/test-model", False),
    ],
)
def test_provider_rejects_missing_response_metadata(
    response_id: str | None,
    response_model: str | None,
    include_usage: bool,
) -> None:
    resource = FakeCompletions(
        '{"root_cause":"x","confidence":1}',
        response_id=response_id,
        response_model=response_model,
        include_usage=include_usage,
    )
    provider = NvidiaProvider(
        api_key="test",
        model="nvidia/test-model",
        client=FakeClient(resource),
    )

    with pytest.raises(NvidiaStructuredOutputError):
        provider.generate(schema=Answer, instructions="Diagnose.", user_input="Incident.")


class TimeoutCompletions:
    def __init__(self) -> None:
        self.calls = 0

    def create(self, **kwargs: Any) -> SimpleNamespace:
        self.calls += 1
        raise APITimeoutError(request=httpx.Request("POST", "https://example.test/v1"))


def test_provider_retries_transient_errors_exactly_three_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resource = TimeoutCompletions()
    provider = NvidiaProvider(
        api_key="test",
        model="nvidia/test-model",
        client=FakeClient(resource),
    )
    monkeypatch.setattr(NvidiaProvider.generate.retry, "sleep", lambda _: None)

    with pytest.raises(APITimeoutError):
        provider.generate(schema=Answer, instructions="Diagnose.", user_input="Incident.")

    assert resource.calls == 4


@pytest.mark.parametrize(
    ("api_key", "model", "base_url"),
    [
        ("", "model", "https://example.test/v1"),
        ("key", "", "https://example.test/v1"),
        ("key", "model", ""),
    ],
)
def test_provider_requires_credentials_model_and_base_url(
    api_key: str,
    model: str,
    base_url: str,
) -> None:
    with pytest.raises(ValueError):
        NvidiaProvider(api_key=api_key, model=model, base_url=base_url)


@pytest.mark.parametrize("max_output_tokens", [0, 32_769])
def test_provider_validates_prompt_and_output_limit(max_output_tokens: int) -> None:
    provider = NvidiaProvider(
        api_key="test",
        model="nvidia/test-model",
        client=FakeClient(FakeCompletions('{"root_cause":"x","confidence":1}')),
    )
    with pytest.raises(ValueError, match="max_output_tokens"):
        provider.generate(
            schema=Answer,
            instructions="Diagnose.",
            user_input="Incident.",
            max_output_tokens=max_output_tokens,
        )


def test_provider_validates_nonempty_prompt() -> None:
    provider = NvidiaProvider(
        api_key="test",
        model="nvidia/test-model",
        client=FakeClient(FakeCompletions('{"root_cause":"x","confidence":1}')),
    )
    with pytest.raises(ValueError, match="non-empty"):
        provider.generate(schema=Answer, instructions="", user_input="Incident.")
