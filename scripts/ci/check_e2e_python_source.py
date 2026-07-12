"""Playwright e2e webServer preflight: fail closed unless ``hallu_defense``
imports from the exact expected worktree source root.

Setting ``PYTHONPATH`` prioritizes the intended source directory, but a stray
editable install, a `.pth` file, or an inherited environment variable could
still make an unrelated checkout's ``hallu_defense`` win. This script is the
last-resort guard: it imports ``hallu_defense`` with whatever interpreter and
environment the caller configured and refuses to proceed unless the resolved
module file sits under the exact expected source root.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_API_SRC_ROOT = ROOT / "apps" / "api" / "src"


class PythonSourceMismatchError(RuntimeError):
    pass


def check_hallu_defense_source_root(
    expected_src_root: str, *, module: ModuleType | None = None
) -> str:
    """Return the resolved ``hallu_defense`` file path if it is under
    ``expected_src_root``.

    Raises ``PythonSourceMismatchError`` otherwise. ``module`` is injectable
    so this check can be unit tested without importing the real package.
    """
    requested_root = Path(expected_src_root)
    if not requested_root.is_absolute():
        raise PythonSourceMismatchError("expected source root must be absolute")
    expected_root = os.path.realpath(requested_root)
    if not os.path.isdir(expected_root):
        raise PythonSourceMismatchError(
            f"expected source root does not exist: {expected_root}"
        )
    if module is None:
        try:
            module = importlib.import_module("hallu_defense")
        except ImportError as exc:
            raise PythonSourceMismatchError(
                f"hallu_defense is not importable: {exc}"
            ) from exc
    module_file = getattr(module, "__file__", None)
    if not module_file:
        raise PythonSourceMismatchError("hallu_defense.__file__ is unavailable")
    resolved = os.path.realpath(module_file)
    resolved_dir = os.path.dirname(resolved)
    try:
        common = os.path.commonpath([resolved_dir, expected_root])
    except ValueError as exc:
        raise PythonSourceMismatchError(
            "hallu_defense resolved on a different filesystem root than expected:\n"
            f"  expected root: {expected_root}\n"
            f"  resolved file: {resolved}"
        ) from exc
    if os.path.normcase(common) != os.path.normcase(expected_root):
        raise PythonSourceMismatchError(
            "hallu_defense resolved outside the expected worktree source root:\n"
            f"  expected root: {expected_root}\n"
            f"  resolved file: {resolved}"
        )
    return resolved


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: check_e2e_python_source.py <expected_src_root>", file=sys.stderr)
        return 2
    try:
        resolved = check_hallu_defense_source_root(args[0])
    except PythonSourceMismatchError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"hallu_defense resolved correctly: {resolved}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
