from __future__ import annotations

import json
import re
from typing import Any, Literal, Protocol, TypeVar, cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import (  # type: ignore[import-untyped]
    ValidationError as JsonSchemaValidationError,
)
from openai import (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
    OpenAI,
    RateLimitError,
)
from openai.lib._pydantic import to_strict_json_schema
from pydantic import BaseModel, ValidationError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

from .base import StructuredResult, UsageRecord

T = TypeVar("T", bound=BaseModel)

DEFAULT_NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
_SCHEMA_NAME = re.compile(r"[^A-Za-z0-9_-]")


class NvidiaStructuredOutputError(RuntimeError):
    """Raised when NVIDIA NIM does not return a schema-valid completion."""


class _CompletionsResource(Protocol):
    def create(self, **kwargs: Any) -> Any: ...


class _ChatResource(Protocol):
    completions: _CompletionsResource


class _Client(Protocol):
    chat: _ChatResource


class NvidiaProvider:
    """NVIDIA NIM chat-completions adapter with constrained JSON output."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = DEFAULT_NVIDIA_BASE_URL,
        response_format_mode: Literal["json_object", "json_schema"] = "json_object",
        client: _Client | None = None,
    ) -> None:
        if not api_key.strip():
            raise ValueError("NVIDIA API key is required for the live provider")
        if not model.strip():
            raise ValueError("NVIDIA model name is required")
        if not base_url.strip():
            raise ValueError("NVIDIA base URL is required")
        self._model = model.strip()
        self._response_format_mode = response_format_mode
        self._client = client or cast(
            _Client,
            OpenAI(
                api_key=api_key,
                base_url=base_url.rstrip("/"),
                max_retries=0,
                timeout=120.0,
            ),
        )

    @retry(
        retry=retry_if_exception_type(
            (APIConnectionError, APITimeoutError, RateLimitError, InternalServerError)
        ),
        wait=wait_exponential_jitter(multiplier=0.5, max=8),
        stop=stop_after_attempt(4),
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
        if max_output_tokens < 1 or max_output_tokens > 32_768:
            raise ValueError("max_output_tokens must be between 1 and 32768")

        # The hosted Chat Completions API does not define OpenAI's safety_identifier.
        # Accept the provider-agnostic argument without transmitting a case identifier.
        _ = safety_identifier
        schema_document = to_strict_json_schema(schema)
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        f"{instructions}\n\nReturn only one JSON object that validates against "
                        "this JSON Schema:\n"
                        f"{json.dumps(schema_document, sort_keys=True, separators=(',', ':'))}"
                    ),
                },
                {"role": "user", "content": user_input},
            ],
            max_tokens=max_output_tokens,
            temperature=0.0,
            stream=False,
            response_format=_response_format(
                self._response_format_mode,
                schema=schema,
                schema_document=schema_document,
            ),
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
        value = _parse_response(response, schema, schema_document)
        usage = getattr(response, "usage", None)
        if usage is None:
            raise NvidiaStructuredOutputError("NVIDIA response did not contain token usage")
        input_tokens = _required_token_count(usage, "prompt_tokens")
        output_tokens = _required_token_count(usage, "completion_tokens")
        total_tokens = _required_token_count(usage, "total_tokens")
        details = getattr(usage, "prompt_tokens_details", None)
        cached_tokens = min(_token_count(details, "cached_tokens"), input_tokens)
        response_id = getattr(response, "id", None)
        response_model = getattr(response, "model", None)
        if not isinstance(response_id, str) or not response_id:
            raise NvidiaStructuredOutputError("NVIDIA response did not contain an identifier")
        if not isinstance(response_model, str) or not response_model:
            raise NvidiaStructuredOutputError("NVIDIA response did not identify its model")
        return StructuredResult(
            value=value,
            response_id=response_id,
            model=response_model,
            usage=UsageRecord(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cached_input_tokens=cached_tokens,
                total_tokens=total_tokens,
            ),
        )


def _parse_response[T: BaseModel](
    response: object,
    schema: type[T],
    schema_document: dict[str, Any],
) -> T:
    choices = getattr(response, "choices", None)
    if not isinstance(choices, list) or not choices:
        raise NvidiaStructuredOutputError("NVIDIA response did not contain a completion")
    choice = choices[0]
    if getattr(choice, "finish_reason", None) != "stop":
        raise NvidiaStructuredOutputError("NVIDIA response did not finish normally")
    message = getattr(choice, "message", None)
    content = getattr(message, "content", None)
    if not isinstance(content, str) or not content.strip():
        raise NvidiaStructuredOutputError("NVIDIA response did not contain structured content")
    try:
        decoded = json.loads(content)
        Draft202012Validator(schema_document).validate(decoded)
        return schema.model_validate(decoded)
    except (json.JSONDecodeError, JsonSchemaValidationError, ValidationError) as exc:
        raise NvidiaStructuredOutputError(
            "NVIDIA response did not satisfy the requested schema"
        ) from exc


def _response_format(
    mode: Literal["json_object", "json_schema"],
    *,
    schema: type[BaseModel],
    schema_document: dict[str, Any],
) -> dict[str, object]:
    if mode == "json_object":
        return {"type": "json_object"}
    return {
        "type": "json_schema",
        "json_schema": {
            "name": _schema_name(schema),
            "strict": True,
            "schema": schema_document,
        },
    }


def _schema_name(schema: type[BaseModel]) -> str:
    name = _SCHEMA_NAME.sub("_", schema.__name__).strip("_-")[:64]
    return name or "structured_response"


def _token_count(source: object, attribute: str) -> int:
    value = getattr(source, attribute, 0)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(value, 0)


def _required_token_count(source: object, attribute: str) -> int:
    value = getattr(source, attribute, None)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NvidiaStructuredOutputError("NVIDIA response contained invalid token usage")
    return value
