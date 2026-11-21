"""Repository evaluation-harness entry point."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path


def main(argv: Sequence[str] | None = None) -> int:
    """Delegate to the frozen, repository-level evaluation harness."""

    candidates = (Path.cwd(), Path(__file__).resolve().parents[3])
    checkout = next((path for path in candidates if (path / "evals" / "harness").is_dir()), None)
    if checkout is not None and str(checkout) not in sys.path:
        sys.path.insert(0, str(checkout))
    try:
        from evals.harness.cli import main as harness_main
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "the evaluation corpus is unavailable; run this command from the project checkout"
        ) from exc
    return harness_main(argv)
