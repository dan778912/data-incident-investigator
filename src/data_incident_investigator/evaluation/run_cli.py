"""Console entry point for the repository-level live evaluator."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path


def main(argv: Sequence[str] | None = None) -> int:
    candidates = (Path.cwd(), Path(__file__).resolve().parents[3])
    checkout = next((path for path in candidates if (path / "evals").is_dir()), None)
    if checkout is None:
        raise RuntimeError(
            "the evaluation corpus is unavailable; run this command from the project checkout"
        )
    if str(checkout) not in sys.path:
        sys.path.insert(0, str(checkout))
    from evals.live_runner import main as runner_main

    return runner_main(argv)
