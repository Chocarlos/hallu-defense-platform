from __future__ import annotations

import hashlib
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.ci.run_gitleaks import (  # noqa: E402
    FIXTURE_MANIFEST_PATH,
    FixtureFingerprint,
    GitleaksExecutionError,
    _prepare_snapshot_source,
    load_fixture_fingerprints,
)


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    regex: re.Pattern[str]


SECRET_PATTERNS = (
    SecretPattern(
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |)PRIVATE KEY-----"),
    ),
    SecretPattern(
        "credential-assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*"
            r"(?P<quote>['\"])[A-Za-z0-9_./+=-]{16,}(?P=quote)"
        ),
    ),
    SecretPattern("openai-api-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
)

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@dataclass(frozen=True)
class SecretScanResult:
    findings: list[str]
    unreadable: list[str]

    @property
    def ok(self) -> bool:
        return not self.findings and not self.unreadable


def scan_tree(
    root: Path = ROOT,
    *,
    fixture_manifest_path: Path = FIXTURE_MANIFEST_PATH,
) -> SecretScanResult:
    fixture_fingerprints = load_fixture_fingerprints(
        "secret_scan_fixtures",
        manifest_path=fixture_manifest_path,
    )
    with tempfile.TemporaryDirectory(prefix="hallu-secret-scan-") as temporary:
        scan_root = _prepare_snapshot_source(
            root.resolve(),
            Path(temporary) / "snapshot",
        )
        findings, unreadable = _scan_snapshot(
            scan_root,
            fixture_fingerprints=fixture_fingerprints,
        )

    return SecretScanResult(
        findings=sorted(findings),
        unreadable=sorted(unreadable),
    )


def _scan_snapshot(
    root: Path,
    *,
    fixture_fingerprints: frozenset[FixtureFingerprint],
) -> tuple[set[str], set[str]]:
    findings: set[str] = set()
    unreadable: set[str] = set()
    for path in root.rglob("*"):
        relative_path = path.relative_to(root)
        normalized_path = relative_path.as_posix()
        if path.is_symlink() or path.is_junction():
            unreadable.add(normalized_path)
            continue
        if not path.is_file():
            continue
        try:
            payload = path.read_bytes()
        except OSError:
            unreadable.add(normalized_path)
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            if path.suffix.casefold() != ".png" or not payload.startswith(PNG_SIGNATURE):
                unreadable.add(normalized_path)
                continue
            # PNG chunks may contain textual metadata. Latin-1 preserves every
            # byte so the ASCII-oriented secret patterns still inspect it.
            text = payload.decode("latin-1")
        for pattern in SECRET_PATTERNS:
            for match in pattern.regex.finditer(text):
                fingerprint = FixtureFingerprint(
                    path=normalized_path,
                    rule_id=pattern.rule_id,
                    match_sha256=hashlib.sha256(
                        match.group(0).encode("utf-8")
                    ).hexdigest(),
                )
                if fingerprint not in fixture_fingerprints:
                    findings.add(normalized_path)
    return findings, unreadable


def main() -> None:
    try:
        result = scan_tree(ROOT)
    except GitleaksExecutionError as exc:
        print(f"Secret scan configuration error: {exc}")
        raise SystemExit(1) from None

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
