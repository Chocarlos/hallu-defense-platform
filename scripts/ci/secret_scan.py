from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {
    ".git",
    ".claude",
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
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |)PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*"
        r"(?P<quote>['\"])[A-Za-z0-9_./+=-]{16,}(?P=quote)"
    ),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
]
KNOWN_FIXTURE_MARKERS = (
    "fixture",
    "local-only",
    "redacted",
    "example",
    "signed.access.token",
    "test-password",
)


@dataclass(frozen=True)
class SecretScanResult:
    findings: list[str]
    unreadable: list[str]

    @property
    def ok(self) -> bool:
        return not self.findings and not self.unreadable


def should_skip(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return True
    return any(part in SKIP_DIRS for part in path.parts)


def scan_tree(root: Path = ROOT) -> SecretScanResult:
    findings: list[str] = []
    unreadable: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or should_skip(path.relative_to(root)):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        except OSError:
            unreadable.append(str(path.relative_to(root)))
            continue
        for pattern in SECRET_PATTERNS:
            match = pattern.search(text)
            if match is not None and not _known_fixture_match(match.group(0)):
                findings.append(str(path.relative_to(root)))
                break

    return SecretScanResult(findings=sorted(findings), unreadable=sorted(unreadable))


def _known_fixture_match(value: str) -> bool:
    normalized = value.casefold()
    return any(marker in normalized for marker in KNOWN_FIXTURE_MARKERS)


def main() -> None:
    result = scan_tree(ROOT)

    if result.unreadable:
        print("Could not read files during secret scan:")
        for path in result.unreadable:
            print(f"- {path}")
        raise SystemExit(1)

    if result.findings:
        print("Potential secrets found:")
        for finding in result.findings:
            print(f"- {finding}")
        raise SystemExit(1)

    print("No obvious secrets found.")


if __name__ == "__main__":
    main()
