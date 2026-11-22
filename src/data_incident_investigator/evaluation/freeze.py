"""Freeze reviewed evaluation evidence into a safe, commit-ready directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

EvidenceFormat = Literal["json", "jsonl", "text"]


class EvidenceFreezeError(ValueError):
    """Raised when generated evidence is incomplete or unsafe to commit."""


@dataclass(frozen=True)
class EvidenceFile:
    source: Path
    destination: Path
    format: EvidenceFormat


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "OpenAI API key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b", re.IGNORECASE),
    ),
    (
        "NVIDIA API key",
        re.compile(r"\bnvapi-[A-Za-z0-9_-]{12,}\b", re.IGNORECASE),
    ),
    (
        "bearer token",
        re.compile(r"\b(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9._~-]{12,}", re.IGNORECASE),
    ),
    (
        "credential assignment",
        re.compile(
            r"\b(?:OPENAI_API_KEY|NVIDIA_API_KEY|APPROVAL_HMAC_KEY)\s*[:=]\s*"
            r"(?!<REDACTED>\b|$)[^\s\"']+",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
)
_WINDOWS_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]")
_UNIX_HOME_PATH = re.compile(r"/(?:home|Users)/[^/\s\"']+", re.IGNORECASE)
_RELATIVE_WINDOWS_PATH = re.compile(
    r"(?<![A-Za-z0-9])(?:live|adversarial|\.)\\[^\s`\"']+(?:\\[^\s`\"']+)*"
)
_FROZEN_LIVE_SUMMARY = Path("live/summary.json")
_FROZEN_ADVERSARIAL_RESULTS_LINK = "../adversarial/adversarial_results.json"


def freeze_evaluation(
    *,
    live_run: Path,
    adversarial_run: Path,
    output_dir: Path,
    repository_root: Path,
    frozen_at: datetime | None = None,
    git_commit: str | None = None,
) -> Path:
    """Sanitize and atomically freeze the grade-relevant evaluation artifacts."""

    live = _require_directory(live_run, label="live run")
    adversarial = _require_directory(adversarial_run, label="adversarial run")
    repository = _require_directory(repository_root, label="repository root")
    destination = output_dir.resolve()
    if destination.exists():
        raise EvidenceFreezeError(f"output directory already exists: {destination}")
    if destination.is_relative_to(live) or destination.is_relative_to(adversarial):
        raise EvidenceFreezeError("output directory must not be inside an evaluation run")

    files = _collect_evidence(live, adversarial)
    replacements = _path_replacements(live, adversarial, repository)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}-staging-",
            dir=destination.parent,
        )
    )
    try:
        for evidence in files:
            target = staging / evidence.destination
            target.parent.mkdir(parents=True, exist_ok=True)
            content = _sanitize_evidence(evidence, replacements)
            _assert_safe(content, evidence.destination)
            target.write_text(content, encoding="utf-8", newline="\n")

        manifest = _build_manifest(
            staging=staging,
            live_run=live,
            adversarial_run=adversarial,
            repository_root=repository,
            frozen_at=frozen_at or datetime.now(UTC),
            git_commit=git_commit or _read_git_commit(repository),
        )
        manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        _assert_safe(manifest_text, Path("MANIFEST.json"))
        (staging / "MANIFEST.json").write_text(
            manifest_text,
            encoding="utf-8",
            newline="\n",
        )
        if destination.exists():
            raise EvidenceFreezeError(f"output directory appeared during freeze: {destination}")
        staging.rename(destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def _collect_evidence(live: Path, adversarial: Path) -> tuple[EvidenceFile, ...]:
    files: list[EvidenceFile] = [
        _evidence_file(live, "summary.json", Path("live/summary.json"), "json"),
        _evidence_file(live, "report.md", Path("live/report.md"), "text"),
        _evidence_file(
            live,
            "observations.jsonl",
            Path("live/observations.jsonl"),
            "jsonl",
        ),
        _evidence_file(
            adversarial,
            "adversarial_results.json",
            Path("adversarial/adversarial_results.json"),
            "json",
        ),
        _evidence_file(
            adversarial,
            "adversarial_results.jsonl",
            Path("adversarial/adversarial_results.jsonl"),
            "jsonl",
        ),
        _evidence_file(
            adversarial,
            "adversarial_report.md",
            Path("adversarial/adversarial_report.md"),
            "text",
        ),
    ]
    files.extend(
        _trace_files(
            live,
            pattern="*.jsonl",
            destination_root=Path("live/traces"),
            format="jsonl",
        )
    )
    files.extend(
        _trace_files(
            adversarial,
            pattern="*.json",
            destination_root=Path("adversarial/traces"),
            format="json",
        )
    )
    return tuple(sorted(files, key=lambda item: item.destination.as_posix()))


def _evidence_file(
    root: Path,
    relative_source: str,
    destination: Path,
    format: EvidenceFormat,
) -> EvidenceFile:
    source = root / relative_source
    if not source.is_file() or source.is_symlink():
        raise EvidenceFreezeError(f"required evidence file is missing or unsafe: {source}")
    return EvidenceFile(source=source, destination=destination, format=format)


def _trace_files(
    root: Path,
    *,
    pattern: str,
    destination_root: Path,
    format: EvidenceFormat,
) -> list[EvidenceFile]:
    trace_root = root / "traces"
    if not trace_root.is_dir() or trace_root.is_symlink():
        raise EvidenceFreezeError(f"required trace directory is missing or unsafe: {trace_root}")
    traces = sorted(trace_root.glob(pattern), key=lambda path: path.name)
    if not traces:
        raise EvidenceFreezeError(f"no {pattern} traces found below {trace_root}")
    if any(not path.is_file() or path.is_symlink() for path in traces):
        raise EvidenceFreezeError(f"trace directory contains an unsafe entry: {trace_root}")
    return [
        EvidenceFile(
            source=path,
            destination=destination_root / path.name,
            format=format,
        )
        for path in traces
    ]


def _path_replacements(
    live: Path,
    adversarial: Path,
    repository: Path,
) -> tuple[tuple[str, str], ...]:
    replacements: dict[str, str] = {}
    for path, label in (
        (live, "live"),
        (adversarial, "adversarial"),
        (repository, "."),
        (Path.home().resolve(), "<USER_HOME>"),
    ):
        native = str(path)
        replacements[native] = label
        replacements[native.replace("\\", "/")] = label
    return tuple(sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True))


def _sanitize_evidence(
    evidence: EvidenceFile,
    replacements: tuple[tuple[str, str], ...],
) -> str:
    text = evidence.source.read_text(encoding="utf-8")
    if evidence.format == "text":
        sanitized = _sanitize_text(text, replacements)
        return sanitized.rstrip("\r\n") + "\n"
    if evidence.format == "json":
        raw: object = json.loads(text)
        cleaned = _sanitize_json_value(raw, replacements)
        cleaned = _canonicalize_json_links(cleaned, evidence.destination)
        return (
            json.dumps(cleaned, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            + "\n"
        )

    records: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw_record: object = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceFreezeError(
                f"invalid JSONL in {evidence.source} at line {line_number}"
            ) from exc
        cleaned_record = _sanitize_json_value(raw_record, replacements)
        records.append(
            json.dumps(
                cleaned_record,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        )
    if not records:
        raise EvidenceFreezeError(f"JSONL evidence is empty: {evidence.source}")
    return "\n".join(records) + "\n"


def _sanitize_json_value(
    value: object,
    replacements: tuple[tuple[str, str], ...],
) -> object:
    if isinstance(value, str):
        return _sanitize_text(value, replacements)
    if isinstance(value, list):
        return [_sanitize_json_value(item, replacements) for item in cast(list[object], value)]
    if isinstance(value, dict):
        cleaned: dict[str, object] = {}
        for key, item in cast(dict[object, object], value).items():
            if not isinstance(key, str):
                raise EvidenceFreezeError("JSON evidence contains a non-string object key")
            cleaned[key] = _sanitize_json_value(item, replacements)
        return cleaned
    if value is None or isinstance(value, bool | int | float):
        return value
    raise EvidenceFreezeError(f"unsupported JSON evidence value: {type(value).__name__}")


def _canonicalize_json_links(value: object, destination: Path) -> object:
    if destination != _FROZEN_LIVE_SUMMARY or not isinstance(value, dict):
        return value
    summary = cast(dict[str, object], value)
    if "adversarial_results_path" in summary:
        summary["adversarial_results_path"] = _FROZEN_ADVERSARIAL_RESULTS_LINK
    return summary


def _sanitize_text(
    text: str,
    replacements: tuple[tuple[str, str], ...],
) -> str:
    sanitized = text
    for source, destination in replacements:
        sanitized = re.sub(
            re.escape(source),
            lambda _, replacement=destination: replacement,
            sanitized,
            flags=re.IGNORECASE if os.name == "nt" else 0,
        )
    return _RELATIVE_WINDOWS_PATH.sub(
        lambda match: match.group(0).replace("\\", "/"),
        sanitized,
    )


def _assert_safe(content: str, relative_path: Path) -> None:
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(content):
            raise EvidenceFreezeError(f"{relative_path.as_posix()} contains a likely {label}")
    if _WINDOWS_ABSOLUTE_PATH.search(content) or _UNIX_HOME_PATH.search(content):
        raise EvidenceFreezeError(
            f"{relative_path.as_posix()} contains an unresolved absolute local path"
        )


def _build_manifest(
    *,
    staging: Path,
    live_run: Path,
    adversarial_run: Path,
    repository_root: Path,
    frozen_at: datetime,
    git_commit: str,
) -> dict[str, object]:
    if frozen_at.tzinfo is None:
        raise EvidenceFreezeError("freeze timestamp must be timezone-aware")
    commit = git_commit.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit, re.IGNORECASE):
        raise EvidenceFreezeError("git commit must be a 40-character hexadecimal hash")
    entries: list[dict[str, object]] = []
    for path in sorted(staging.rglob("*"), key=lambda item: item.relative_to(staging).as_posix()):
        if not path.is_file():
            continue
        content = path.read_bytes()
        entries.append(
            {
                "bytes": len(content),
                "path": path.relative_to(staging).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return {
        "schema_version": "1.0",
        "frozen_at": frozen_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "git_commit": commit.lower(),
        "source_runs": {
            "adversarial": adversarial_run.name,
            "live": live_run.name,
        },
        "files": entries,
        "repository": repository_root.name,
    }


def _read_git_commit(repository_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise EvidenceFreezeError("could not resolve the repository Git commit") from exc
    return completed.stdout.strip()


def _require_directory(path: Path, *, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_dir() or resolved.is_symlink():
        raise EvidenceFreezeError(f"{label} directory is missing or unsafe: {resolved}")
    return resolved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-run", type=Path, required=True)
    parser.add_argument("--adversarial-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("submission/evaluation"))
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        output = freeze_evaluation(
            live_run=args.live_run,
            adversarial_run=args.adversarial_run,
            output_dir=args.output,
            repository_root=args.repository_root,
        )
    except EvidenceFreezeError as exc:
        print(f"Evaluation freeze refused: {exc}")
        return 1
    print(f"Frozen sanitized evaluation evidence at {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
