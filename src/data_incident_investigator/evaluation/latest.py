"""Read the latest real evaluation summary for the API dashboard."""

from __future__ import annotations

import json
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field

MetricTone = Literal["good", "warn", "neutral"]
AttackStatus = Literal["blocked", "contained", "failed"]


class EvaluationMetricView(BaseModel):
    """One frontend-compatible quantitative metric."""

    label: str
    value: str
    detail: str
    score: float = Field(ge=0, le=100)
    tone: MetricTone


class AttackResultView(BaseModel):
    """One actually executed adversarial result, never a planned attack."""

    id: str
    surface: str
    attack: str
    outcome: str
    status: AttackStatus


class EvaluationCategoryView(BaseModel):
    """Optional category-level counts supplied by an evaluation summary."""

    label: str
    passed: int = Field(ge=0)
    total: int = Field(ge=0)


class EvaluationSummaryView(BaseModel):
    """Response shape consumed by the existing frontend."""

    model_config = ConfigDict(populate_by_name=True)

    run_date: str = Field(alias="runDate")
    sample_size: int = Field(alias="sampleSize", ge=0)
    metrics: list[EvaluationMetricView]
    attacks: list[AttackResultView]
    categories: list[EvaluationCategoryView]


class EvaluationReadError(ValueError):
    """Raised when a present summary cannot be read honestly."""


@dataclass(frozen=True, slots=True)
class MetricSnapshot:
    """Normalized metric values from the harness summary."""

    value: float | None
    numerator: float | None
    denominator: float | None
    sample_size: int


@dataclass(frozen=True, slots=True)
class LatestEvaluationReader:
    """Locate and adapt the most recently written real summary."""

    results_root: Path

    def read(self) -> EvaluationSummaryView:
        """Return the latest real result or an explicit zero-sample state."""

        summary_path = self.latest_summary_path()
        if summary_path is None:
            return not_yet_run_summary()
        payload = _load_summary(summary_path)
        run_count = _nonnegative_int(payload, "run_count")
        if run_count == 0:
            return not_yet_run_summary()
        metrics = _mapping(payload, "metrics")
        return EvaluationSummaryView(
            runDate=_summary_date(payload, summary_path),
            sampleSize=run_count,
            metrics=_metric_views(metrics, run_count),
            attacks=_attack_views(payload),
            categories=_category_views(payload),
        )

    def latest_summary_path(self) -> Path | None:
        """Return the newest summary by modification time, if one exists."""

        if not self.results_root.is_dir():
            return None
        candidates = [path for path in self.results_root.rglob("summary.json") if path.is_file()]
        if not candidates:
            return None
        return max(candidates, key=lambda path: (path.stat().st_mtime_ns, str(path)))


def default_results_root() -> Path:
    """Return the configured or repository-local evaluation results directory."""

    configured = os.getenv("DII_EVALUATION_RESULTS_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    working_root = Path.cwd()
    source_root = Path(__file__).resolve().parents[3]
    project_root = working_root if (working_root / "evals").is_dir() else source_root
    return project_root / "evals" / "results"


def not_yet_run_summary() -> EvaluationSummaryView:
    """Return a truthful frontend-compatible state before any live suite run."""

    return EvaluationSummaryView(
        runDate="Not yet run",
        sampleSize=0,
        metrics=[
            _not_reported_metric("Root-cause accuracy", "No incidents have been evaluated."),
            _not_reported_metric("Remediation success", "No repairs have been evaluated."),
            _not_reported_metric("Citation precision", "No citations have been evaluated."),
            _not_reported_metric("Median latency", "No completed runs are available."),
        ],
        attacks=[],
        categories=[],
    )


def _load_summary(path: Path) -> Mapping[str, object]:
    try:
        parsed: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationReadError(f"could not read evaluation summary {path}: {exc}") from exc
    if not isinstance(parsed, Mapping):
        raise EvaluationReadError(f"evaluation summary must be a JSON object: {path}")
    return cast(Mapping[str, object], parsed)


def _metric_views(
    metrics: Mapping[str, object],
    run_count: int,
) -> list[EvaluationMetricView]:
    root_cause = _metric(metrics, "diagnosis", "cause_exact_set_accuracy")
    remediation = _metric(metrics, "repair", "repair_postcondition_rate")
    citation = _metric(metrics, "rag", "citation_precision")
    latency_p50 = _metric(metrics, "performance", "latency_p50_ms")
    latency_p95 = _metric(metrics, "performance", "latency_p95_ms")
    return [
        _percentage_metric(
            "Root-cause accuracy",
            root_cause,
            count_label="incidents correctly classified",
        ),
        _percentage_metric(
            "Remediation success",
            remediation,
            count_label="repairs passed all post-fix checks",
        ),
        _percentage_metric(
            "Citation precision",
            citation,
            count_label="citations supported their claims",
        ),
        _latency_metric(latency_p50, latency_p95, run_count),
    ]


def _percentage_metric(
    label: str,
    snapshot: MetricSnapshot | None,
    *,
    count_label: str,
) -> EvaluationMetricView:
    if snapshot is None or snapshot.value is None:
        return _not_reported_metric(label, "This metric was not reported by the latest run.")
    if not 0 <= snapshot.value <= 1:
        raise EvaluationReadError(f"{label} must be between zero and one")
    percentage = snapshot.value * 100
    if snapshot.numerator is not None and snapshot.denominator is not None:
        detail = (
            f"{_format_count(snapshot.numerator)} of "
            f"{_format_count(snapshot.denominator)} {count_label}"
        )
    else:
        detail = f"Measured across {snapshot.sample_size} samples"
    tone: MetricTone = "good" if percentage >= 80 else "warn"
    return EvaluationMetricView(
        label=label,
        value=f"{percentage:.1f}%",
        detail=detail,
        score=round(percentage, 1),
        tone=tone,
    )


def _latency_metric(
    median: MetricSnapshot | None,
    p95: MetricSnapshot | None,
    run_count: int,
) -> EvaluationMetricView:
    if median is None or median.value is None:
        return _not_reported_metric(
            "Median latency",
            "This metric was not reported by the latest run.",
        )
    if median.value < 0:
        raise EvaluationReadError("median latency cannot be negative")
    detail = f"Measured across {run_count} completed runs"
    if p95 is not None and p95.value is not None:
        if p95.value < 0:
            raise EvaluationReadError("p95 latency cannot be negative")
        detail = f"p95: {_format_duration(p95.value)} across {run_count} completed runs"
    return EvaluationMetricView(
        label="Median latency",
        value=_format_duration(median.value),
        detail=detail,
        score=0,
        tone="neutral",
    )


def _not_reported_metric(label: str, detail: str) -> EvaluationMetricView:
    return EvaluationMetricView(
        label=label,
        value="Not run",
        detail=detail,
        score=0,
        tone="neutral",
    )


def _metric(
    metrics: Mapping[str, object],
    group_name: str,
    metric_name: str,
) -> MetricSnapshot | None:
    group_value = metrics.get(group_name)
    if group_value is None:
        return None
    if not isinstance(group_value, Mapping):
        raise EvaluationReadError(f"metrics.{group_name} must be an object")
    metric_value = group_value.get(metric_name)
    if metric_value is None:
        return None
    if not isinstance(metric_value, Mapping):
        raise EvaluationReadError(f"metrics.{group_name}.{metric_name} must be an object")
    metric_mapping = cast(Mapping[str, object], metric_value)
    return MetricSnapshot(
        value=_optional_number(metric_mapping, "value"),
        numerator=_optional_number(metric_mapping, "numerator"),
        denominator=_optional_number(metric_mapping, "denominator"),
        sample_size=_nonnegative_int(metric_mapping, "sample_size"),
    )


def _attack_views(payload: Mapping[str, object]) -> list[AttackResultView]:
    raw = payload.get("attacks", [])
    if not isinstance(raw, list):
        raise EvaluationReadError("attacks must be a list when provided")
    attacks: list[AttackResultView] = []
    for index, value in enumerate(raw):
        if not isinstance(value, Mapping):
            raise EvaluationReadError(f"attacks[{index}] must be an object")
        item = cast(Mapping[str, object], value)
        status = _required_string(item, "status")
        if status not in {"blocked", "contained", "failed"}:
            raise EvaluationReadError(f"attacks[{index}].status is invalid")
        attacks.append(
            AttackResultView(
                id=_required_string(item, "id"),
                surface=_required_string(item, "surface"),
                attack=_required_string(item, "attack"),
                outcome=_required_string(item, "outcome"),
                status=cast(AttackStatus, status),
            )
        )
    return attacks


def _category_views(payload: Mapping[str, object]) -> list[EvaluationCategoryView]:
    raw = payload.get("categories", [])
    if not isinstance(raw, list):
        raise EvaluationReadError("categories must be a list when provided")
    categories: list[EvaluationCategoryView] = []
    for index, value in enumerate(raw):
        if not isinstance(value, Mapping):
            raise EvaluationReadError(f"categories[{index}] must be an object")
        item = cast(Mapping[str, object], value)
        passed = _nonnegative_int(item, "passed")
        total = _nonnegative_int(item, "total")
        if passed > total:
            raise EvaluationReadError(f"categories[{index}].passed cannot exceed total")
        categories.append(
            EvaluationCategoryView(
                label=_required_string(item, "label"),
                passed=passed,
                total=total,
            )
        )
    return categories


def _summary_date(payload: Mapping[str, object], summary_path: Path) -> str:
    for key in ("evaluation_date", "generated_at"):
        value = payload.get(key)
        if isinstance(value, str):
            parsed = _parse_date(value)
            if parsed is not None:
                return _display_date(parsed)
    parsed_parent = _parse_date(summary_path.parent.name)
    if parsed_parent is not None:
        return _display_date(parsed_parent)
    modified = datetime.fromtimestamp(summary_path.stat().st_mtime, tz=UTC).date()
    return _display_date(modified)


def _parse_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _display_date(value: date) -> str:
    return f"{value:%B} {value.day}, {value.year}"


def _format_duration(milliseconds: float) -> str:
    if milliseconds < 1_000:
        return f"{milliseconds:.0f} ms"
    seconds = milliseconds / 1_000
    if seconds < 60:
        return f"{seconds:.1f} sec"
    return f"{seconds / 60:.1f} min"


def _format_count(value: float) -> str:
    return str(int(value)) if value.is_integer() else f"{value:.2f}"


def _mapping(data: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise EvaluationReadError(f"{key} must be an object")
    return cast(Mapping[str, object], value)


def _required_string(data: Mapping[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise EvaluationReadError(f"{key} must be a non-empty string")
    return value


def _nonnegative_int(data: Mapping[str, object], key: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvaluationReadError(f"{key} must be a nonnegative integer")
    return value


def _optional_number(data: Mapping[str, object], key: str) -> float | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise EvaluationReadError(f"{key} must be a number or null")
    result = float(value)
    if not math.isfinite(result):
        raise EvaluationReadError(f"{key} must be finite")
    return result
