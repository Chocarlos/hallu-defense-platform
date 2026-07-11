from __future__ import annotations

import hashlib
from pathlib import Path

KEYCLOAK_ROOT = Path("/opt/keycloak")
LEGACY_NAME = b"com.fasterxml.jackson.core.jackson-databind-2.21.2.jar"
CORRECTED_NAME = b"com.fasterxml.jackson.core.jackson-databind-2.21.4.jar"
CORRECTED_SHA256 = "3888e9e69ab66fbacaacc9aea0e9ffbf15368288e4aca468b024dba11c09fbf9"
METADATA_PATHS = (
    Path("lib/quarkus/quarkus-application.dat"),
    Path("lib/lib/deployment/deployment-class-path.dat"),
    Path("lib/lib/deployment/appmodel.dat"),
)


def patch_metadata(root: Path = KEYCLOAK_ROOT) -> None:
    if len(LEGACY_NAME) != len(CORRECTED_NAME):
        raise RuntimeError("Keycloak metadata replacement must preserve byte length")
    replacements = 0
    for relative_path in METADATA_PATHS:
        path = root / relative_path
        if not path.is_file():
            raise RuntimeError(f"Keycloak metadata lacks legacy Jackson path: {relative_path}")
        content = path.read_bytes()
        count = content.count(LEGACY_NAME)
        if count < 1:
            raise RuntimeError(f"Keycloak metadata lacks legacy Jackson path: {relative_path}")
        path.write_bytes(content.replace(LEGACY_NAME, CORRECTED_NAME))
        replacements += count

    library = root / "lib" / "lib" / "main"
    legacy = library / LEGACY_NAME.decode("ascii")
    corrected = library / CORRECTED_NAME.decode("ascii")
    if not legacy.is_symlink():
        raise RuntimeError("Legacy Jackson compatibility path must be a symlink before patching")
    legacy.unlink()
    observed = hashlib.sha256(corrected.read_bytes()).hexdigest()
    if observed != CORRECTED_SHA256:
        raise RuntimeError("Corrected Jackson JAR SHA-256 drifted")

    stale_paths: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        if LEGACY_NAME in path.read_bytes():
            stale_paths.append(str(path.relative_to(root)))
    if stale_paths:
        raise RuntimeError(f"Legacy Jackson path remains in: {stale_paths}")
    if legacy.exists() or legacy.is_symlink():
        raise RuntimeError("Legacy Jackson filesystem path remains after metadata patch")
    if replacements < len(METADATA_PATHS):
        raise RuntimeError("Keycloak metadata replacement count is incomplete")


if __name__ == "__main__":
    patch_metadata()
