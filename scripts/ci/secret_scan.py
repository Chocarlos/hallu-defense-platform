from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {
    ".git",
    ".venv",
    ".codex-fable-work",
    "node_modules",
    ".next",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
SKIP_FILES = {"package-lock.json"}
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
]


def should_skip(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return True
    return any(part in SKIP_DIRS for part in path.parts)


def main() -> None:
    findings: list[str] = []
    unreadable: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or should_skip(path.relative_to(ROOT)):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        except OSError:
            unreadable.append(str(path.relative_to(ROOT)))
            continue
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(str(path.relative_to(ROOT)))
                break

    if unreadable:
        print("Could not read files during secret scan:")
        for path in unreadable:
            print(f"- {path}")
        raise SystemExit(1)

    if findings:
        print("Potential secrets found:")
        for finding in findings:
            print(f"- {finding}")
        raise SystemExit(1)

    print("No obvious secrets found.")


if __name__ == "__main__":
    main()
