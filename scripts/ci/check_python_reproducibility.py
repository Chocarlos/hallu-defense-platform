from __future__ import annotations

import base64
import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = ROOT / "apps" / "api" / "pyproject.toml"
LOCK_DIR = ROOT / "requirements" / "python"
LOCK_MANIFEST_PATH = LOCK_DIR / "lock-manifest.json"
LOCK_PATHS = {
    "runtime": LOCK_DIR / "runtime-linux-py312.lock",
    "dev": LOCK_DIR / "dev-linux-py312.lock",
    "build-tools": LOCK_DIR / "build-tools-linux-py312.lock",
    "sandbox": LOCK_DIR / "sandbox-linux-py312.lock",
}
INPUT_PATHS = {
    "build-tools": LOCK_DIR / "build-tools.in",
    "sandbox": LOCK_DIR / "sandbox.in",
}
API_DOCKERFILE = ROOT / "infra" / "docker" / "api.Dockerfile"
SANDBOX_DOCKERFILE = ROOT / "infra" / "docker" / "sandbox.Dockerfile"
SANDBOX_NPM_LOCK = ROOT / "infra" / "docker" / "sandbox-npm.lock.json"
PACKAGE_JSON_PATH = ROOT / "package.json"
PACKAGE_LOCK_PATH = ROOT / "package-lock.json"
NPMRC_PATH = ROOT / ".npmrc"
WHEEL_BUILD_SCRIPT = ROOT / "scripts" / "ci" / "build_reproducible_wheel.py"
SANDBOX_NPM_VERIFY_SCRIPT = ROOT / "scripts" / "ci" / "verify_sandbox_npm_archive.mjs"
WORKFLOW_PATHS = (
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "security.yml",
    ROOT / ".github" / "workflows" / "evals.yml",
    ROOT / ".github" / "workflows" / "live.yml",
    ROOT / ".github" / "workflows" / "release.yml",
    ROOT / ".github" / "workflows" / "verify-release-encryption.yml",
)
LOCK_ENTRY_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)\s*\\$")
HASH_RE = re.compile(r"^--hash=sha256:([0-9a-f]{64})(?:\s*\\)?$")
ACTION_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
ACTION_SHA_RE = re.compile(r"^[^@]+@[0-9a-f]{40}$")
MAINTAINED_ACTION_REFS = {
    "actions/checkout": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    "actions/setup-python": "a309ff8b426b58ec0e2a45f0f869d46889d02405",
    "actions/setup-node": "48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact": "018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
    "actions/attest-build-provenance": "977bb373ede98d70efdf65b84cb5f73e068dcc2a",
    "actions/attest-sbom": "4651f806c01d8637787e274ac3bdf724ef169f34",
}


class ReproducibilityConfigError(ValueError):
    pass


@dataclass(frozen=True)
class LockedRequirement:
    name: str
    version: str
    hashes: tuple[str, ...]


def _normalized_bytes(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def parse_hashed_lock(path: Path) -> dict[str, LockedRequirement]:
    entries: dict[str, LockedRequirement] = {}
    current_name: str | None = None
    current_version = ""
    hashes: list[str] = []

    def finish() -> None:
        nonlocal current_name, current_version, hashes
        if current_name is None:
            return
        if not hashes:
            raise ReproducibilityConfigError(
                f"{path.relative_to(ROOT)} entry {current_name} has no SHA-256 hash."
            )
        if current_name in entries:
            raise ReproducibilityConfigError(
                f"{path.relative_to(ROOT)} duplicates {current_name}."
            )
        entries[current_name] = LockedRequirement(
            name=current_name,
            version=current_version,
            hashes=tuple(hashes),
        )
        current_name = None
        current_version = ""
        hashes = []

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        stripped = raw_line.strip()
        match = LOCK_ENTRY_RE.fullmatch(raw_line)
        if match is not None:
            finish()
            current_name = canonicalize_name(match.group(1))
            current_version = match.group(2)
            continue
        hash_match = HASH_RE.fullmatch(stripped)
        if hash_match is not None:
            if current_name is None:
                raise ReproducibilityConfigError(
                    f"{path.relative_to(ROOT)}:{line_number} has an orphan hash."
                )
            hashes.append(hash_match.group(1))
            continue
        if not stripped or stripped.startswith("#"):
            continue
        raise ReproducibilityConfigError(
            f"{path.relative_to(ROOT)}:{line_number} is not an exact hashed requirement."
        )
    finish()
    if not entries:
        raise ReproducibilityConfigError(f"{path.relative_to(ROOT)} is empty.")
    return entries


def _input_requirements(path: Path) -> list[str]:
    requirements: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if stripped and not stripped.startswith("#"):
            requirements.append(stripped)
    return requirements


def _require_direct_dependencies(
    requirements: Iterable[str],
    locked: Mapping[str, LockedRequirement],
    *,
    label: str,
    errors: list[str],
) -> None:
    for raw_requirement in requirements:
        requirement = Requirement(raw_requirement)
        name = canonicalize_name(requirement.name)
        entry = locked.get(name)
        if entry is None:
            errors.append(
                f"{label} lock is missing direct dependency {requirement.name}."
            )
            continue
        if requirement.url is not None:
            errors.append(
                f"{label} direct dependency {requirement.name} must not use a URL."
            )
        if requirement.specifier and not requirement.specifier.contains(
            Version(entry.version),
            prereleases=True,
        ):
            errors.append(
                f"{label} locks {requirement.name}=={entry.version}, outside "
                f"{requirement.specifier}."
            )


def _validate_manifest(
    locks: Mapping[str, Mapping[str, LockedRequirement]],
    errors: list[str],
) -> None:
    del locks
    try:
        manifest = json.loads(LOCK_MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        errors.append("requirements/python/lock-manifest.json is invalid.")
        return
    if manifest.get("schema_version") != "python-lock-manifest.v1":
        errors.append("Python lock manifest schema version is invalid.")
    if manifest.get("target") != {
        "implementation": "CPython",
        "python": "3.12.13",
        "os": "linux",
    }:
        errors.append("Python lock manifest must target Linux CPython 3.12.13 exactly.")
    if manifest.get("compiler") != {"name": "pip-tools", "version": "7.5.3"}:
        errors.append("Python lock manifest must pin pip-tools 7.5.3.")
    recorded = manifest.get("locks")
    if not isinstance(recorded, Mapping):
        errors.append("Python lock manifest locks must be an object.")
        return
    expected_names = {path.name for path in LOCK_PATHS.values()}
    if set(recorded) != expected_names:
        errors.append(
            "Python lock manifest inventory does not match required lock files."
        )
    for path in LOCK_PATHS.values():
        observed = hashlib.sha256(_normalized_bytes(path)).hexdigest()
        if recorded.get(path.name) != observed:
            errors.append(f"Python lock manifest digest drifted for {path.name}.")


def _validate_npm_lock(dockerfile: str, errors: list[str]) -> None:
    try:
        lock = json.loads(SANDBOX_NPM_LOCK.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        errors.append("sandbox npm integrity lock is invalid.")
        return
    if lock.get("schema_version") != "sandbox-npm-lock.v1":
        errors.append("sandbox npm lock schema is invalid.")
    if lock.get("package") != "npm" or lock.get("version") != "12.0.0":
        errors.append("sandbox npm lock must pin npm 12.0.0.")
    if lock.get("bytes") != 3_087_816:
        errors.append("sandbox npm lock archive byte size is invalid.")
    tarball = lock.get("tarball")
    if not isinstance(tarball, str):
        errors.append("sandbox npm lock tarball is missing.")
        return
    parsed = urlsplit(tarball)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "registry.npmjs.org"
        or parsed.username is not None
        or parsed.password is not None
    ):
        errors.append("sandbox npm tarball must use the official HTTPS registry.")
    sha256 = lock.get("sha256")
    if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        errors.append("sandbox npm lock SHA-256 is invalid.")
    integrity = lock.get("integrity")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        errors.append("sandbox npm lock registry integrity is invalid.")
    else:
        try:
            decoded = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
        except ValueError:
            decoded = b""
        if len(decoded) != 64:
            errors.append("sandbox npm lock SHA-512 integrity is invalid.")
    if f"ADD --checksum=sha256:{sha256} {tarball}" not in dockerfile:
        errors.append("sandbox Dockerfile must fetch npm with its locked SHA-256.")
    for marker in (
        "COPY infra/docker/sandbox-npm.lock.json /tmp/sandbox-npm.lock.json",
        "COPY scripts/ci/verify_sandbox_npm_archive.mjs",
        "node /tmp/verify-sandbox-npm-archive.mjs",
    ):
        if marker not in dockerfile:
            errors.append(
                f"sandbox Dockerfile is missing executed npm integrity marker `{marker}`."
            )
    verifier = SANDBOX_NPM_VERIFY_SCRIPT.read_text(encoding="utf-8")
    for marker in (
        'createHash("sha256")',
        'createHash("sha512")',
        "lock.integrity",
        "lock.sha256",
        "lock.bytes",
        "lock.tarball",
        "lock.version",
        'new URL(lock.tarball).origin !== "https://registry.npmjs.org"',
    ):
        if marker not in verifier:
            errors.append(f"sandbox npm archive verifier is missing `{marker}`.")
    if "npm install" in dockerfile:
        errors.append("sandbox Dockerfile must not mutate npm through npm install.")


def _validate_workflows(errors: list[str]) -> None:
    for path in WORKFLOW_PATHS:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        if "runs-on: ubuntu-latest" in text or "runs-on: ubuntu-24.04" not in text:
            errors.append(
                f"{relative} must pin the hosted runner label to ubuntu-24.04."
            )
        if 'python-version: "3.12.13"' not in text:
            errors.append(f"{relative} must pin Python 3.12.13.")
        if 'pip-version: "26.1.2"' not in text:
            errors.append(f"{relative} must pin pip 26.1.2.")
        if "permissions:\n  contents: read" not in text:
            errors.append(f"{relative} must use read-only contents permission.")
        checkout_count = text.count("actions/checkout@")
        if text.count("persist-credentials: false") != checkout_count:
            errors.append(f"{relative} must disable credentials for every checkout.")
        if text.count("timeout-minutes:") != text.count("runs-on:"):
            errors.append(f"{relative} must bound every job with timeout-minutes.")
        if "python scripts/ci/install_python_lock.py" not in text:
            errors.append(f"{relative} must install Python from an exact hashed lock.")
        if "npm ci" in text and 'test "$(npm --version)" = "11.16.0"' not in text:
            errors.append(f"{relative} must verify npm 11.16.0 before npm ci.")
        for action in ACTION_RE.findall(text):
            if action.startswith("./"):
                continue
            if ACTION_SHA_RE.fullmatch(action) is None:
                errors.append(
                    f"{relative} action {action} is not pinned by commit SHA."
                )
                continue
            action_name, action_ref = action.rsplit("@", 1)
            expected_ref = MAINTAINED_ACTION_REFS.get(action_name)
            if expected_ref is not None and action_ref != expected_ref:
                errors.append(
                    f"{relative} action {action_name} is not at the maintained commit."
                )
        for forbidden in (
            "pip install --upgrade pip",
            'pip install -e "apps/api[dev]"',
            "npm install\n",
            "--ignore-scripts",
            "--dangerously-allow-all-scripts",
        ):
            if forbidden in text:
                errors.append(
                    f"{relative} contains non-reproducible install `{forbidden}`."
                )


def _validate_node_reproducibility(errors: list[str]) -> None:
    package = json.loads(PACKAGE_JSON_PATH.read_text(encoding="utf-8"))
    package_lock = json.loads(PACKAGE_LOCK_PATH.read_text(encoding="utf-8"))
    required_versions = {"next": "16.2.10", "eslint-config-next": "16.2.10"}
    root_dev = package.get("devDependencies", {})
    for name, version in required_versions.items():
        if root_dev.get(name) != version:
            errors.append(f"package.json must pin {name} {version} exactly.")
    if package.get("overrides") != {"next": {"postcss": "8.5.10"}}:
        errors.append(
            "package.json must contain only the scoped Next PostCSS 8.5.10 override."
        )
    if package.get("packageManager") != "npm@11.16.0":
        errors.append("package.json must pin packageManager npm@11.16.0.")
    engines = package.get("engines")
    if (
        not isinstance(engines, Mapping)
        or engines.get("node") != "24.18.0"
        or engines.get("npm") != "11.16.0"
    ):
        errors.append("package.json engines must pin Node 24.18.0 and npm 11.16.0.")
    if package.get("allowScripts") != {
        "esbuild": False,
        "fsevents": False,
        "sharp": False,
        "unrs-resolver": False,
    }:
        errors.append(
            "package.json must explicitly deny every reviewed dependency install script."
        )
    try:
        npmrc = NPMRC_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        npmrc = ""
    if npmrc.splitlines() != ["ignore-scripts=true", "strict-allow-scripts=true"]:
        errors.append(
            ".npmrc must fail closed for old and current npm with "
            "ignore-scripts=true and strict-allow-scripts=true only."
        )
    serialized_package = json.dumps(package, sort_keys=True)
    for forbidden in ("--ignore-scripts", "--dangerously-allow-all-scripts"):
        if forbidden in serialized_package:
            errors.append(f"package.json must not bypass npm policy with {forbidden}.")
    if package.get("resolutions") not in (None, {}):
        errors.append("package.json must not contain resolutions.")
    packages = package_lock.get("packages", {})
    root_package = packages.get("", {})
    if root_package.get("engines") != {"node": "24.18.0", "npm": "11.16.0"}:
        errors.append(
            "package-lock.json root engines must pin Node 24.18.0 and npm 11.16.0."
        )
    if packages.get("node_modules/next", {}).get("version") != "16.2.10":
        errors.append("package-lock.json must resolve Next 16.2.10.")
    if (
        packages.get("node_modules/next/node_modules/postcss", {}).get("version")
        != "8.5.10"
    ):
        errors.append(
            "package-lock.json must resolve Next's PostCSS 8.5.10 correction."
        )


def validate_python_reproducibility() -> None:
    errors: list[str] = []
    locks: dict[str, dict[str, LockedRequirement]] = {}
    for name, path in LOCK_PATHS.items():
        try:
            locks[name] = parse_hashed_lock(path)
        except (OSError, ReproducibilityConfigError) as exc:
            errors.append(str(exc))
    if len(locks) != len(LOCK_PATHS):
        raise ReproducibilityConfigError("\n".join(errors))

    pyproject = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    project = pyproject["project"]
    runtime_requirements = list(project["dependencies"])
    dev_requirements = list(project["optional-dependencies"]["dev"])
    _require_direct_dependencies(
        runtime_requirements,
        locks["runtime"],
        label="runtime",
        errors=errors,
    )
    _require_direct_dependencies(
        [*runtime_requirements, *dev_requirements],
        locks["dev"],
        label="dev",
        errors=errors,
    )
    _require_direct_dependencies(
        _input_requirements(INPUT_PATHS["build-tools"]),
        locks["build-tools"],
        label="build-tools",
        errors=errors,
    )
    _require_direct_dependencies(
        _input_requirements(INPUT_PATHS["sandbox"]),
        locks["sandbox"],
        label="sandbox",
        errors=errors,
    )
    for name, runtime_entry in locks["runtime"].items():
        dev_entry = locks["dev"].get(name)
        if dev_entry is None or dev_entry.version != runtime_entry.version:
            errors.append(
                f"dev lock does not preserve runtime pin {name}=={runtime_entry.version}."
            )
    build_requires = list(pyproject["build-system"]["requires"])
    _require_direct_dependencies(
        build_requires,
        locks["build-tools"],
        label="build-system",
        errors=errors,
    )
    _validate_manifest(locks, errors)

    api_dockerfile = API_DOCKERFILE.read_text(encoding="utf-8")
    sandbox_dockerfile = SANDBOX_DOCKERFILE.read_text(encoding="utf-8")
    for label, text in (("API", api_dockerfile), ("sandbox", sandbox_dockerfile)):
        if "python:3.12.13-" not in text:
            errors.append(f"{label} Dockerfile must use Python 3.12.13 exactly.")
        if "pip install --upgrade" in text or "pip install --no-cache-dir -e" in text:
            errors.append(f"{label} Dockerfile contains a mutable pip install.")
    for marker in (
        "runtime-linux-py312.lock",
        "build-tools-linux-py312.lock",
        "COPY infra/docker/opa-no-oci.patch /tmp/opa-no-oci.patch",
        "git -C /src/opa apply --check /tmp/opa-no-oci.patch",
        'go version -m /out/opa | grep -F "oras.land/oras-go"',
        "SOURCE_DATE_EPOCH",
        "--no-index",
        "--no-deps",
        "pip check",
    ):
        if marker not in api_dockerfile:
            errors.append(
                f"API Dockerfile is missing reproducibility marker `{marker}`."
            )
    console_dockerfile = (ROOT / "infra" / "docker" / "console.Dockerfile").read_text(
        encoding="utf-8"
    )
    for marker in (
        "COPY .npmrc /app/.npmrc",
        'test "$(node --version)" = "v24.18.0"',
        'test "$(npm --version)" = "11.16.0"',
        "npm ci",
    ):
        if marker not in console_dockerfile:
            errors.append(
                f"console Dockerfile is missing npm policy marker `{marker}`."
            )
    for forbidden in ("--ignore-scripts", "--dangerously-allow-all-scripts"):
        if forbidden in console_dockerfile:
            errors.append(
                f"console Dockerfile must not bypass npm policy with {forbidden}."
            )
    if "--no-isolation" not in WHEEL_BUILD_SCRIPT.read_text(encoding="utf-8"):
        errors.append("reproducible wheel build must disable build isolation.")
    for marker in ("sandbox-linux-py312.lock", "--require-hashes", "--no-index"):
        if marker not in sandbox_dockerfile:
            errors.append(
                f"sandbox Dockerfile is missing reproducibility marker `{marker}`."
            )
    _validate_npm_lock(sandbox_dockerfile, errors)
    _validate_node_reproducibility(errors)
    _validate_workflows(errors)

    if errors:
        raise ReproducibilityConfigError("\n".join(errors))


def main() -> None:
    validate_python_reproducibility()
    print(
        "Validated platform-explicit hashed locks and reproducible build configuration."
    )


if __name__ == "__main__":
    main()
