from __future__ import annotations

import hashlib
from pathlib import Path

KEYCLOAK_ROOT = Path("/opt/keycloak")
REPLACEMENTS = (
    (
        b"com.fasterxml.jackson.core.jackson-databind-2.21.2.jar",
        b"com.fasterxml.jackson.core.jackson-databind-2.21.4.jar",
        "3888e9e69ab66fbacaacc9aea0e9ffbf15368288e4aca468b024dba11c09fbf9",
    ),
    (
        b"org.postgresql.postgresql-42.7.11.jar",
        b"org.postgresql.postgresql-42.7.12.jar",
        "31fbf6f06b2217fb51d5100cee51b22625cc81640da0679b47914e54c1e6377c",
    ),
)
METADATA_PATHS = (
    Path("lib/quarkus/quarkus-application.dat"),
    Path("lib/lib/deployment/deployment-class-path.dat"),
    Path("lib/lib/deployment/appmodel.dat"),
)


def patch_metadata(root: Path = KEYCLOAK_ROOT) -> None:
    replacement_counts = {legacy: 0 for legacy, _, _ in REPLACEMENTS}
    for relative_path in METADATA_PATHS:
        path = root / relative_path
        if not path.is_file():
            raise RuntimeError(f"Keycloak metadata is missing: {relative_path}")
        content = path.read_bytes()
        for legacy_name, corrected_name, _ in REPLACEMENTS:
            if len(legacy_name) != len(corrected_name):
                raise RuntimeError("Keycloak metadata replacement must preserve byte length")
            count = content.count(legacy_name)
            if count < 1:
                raise RuntimeError(
                    f"Keycloak metadata lacks {legacy_name.decode('ascii')}: {relative_path}"
                )
            content = content.replace(legacy_name, corrected_name)
            replacement_counts[legacy_name] += count
        path.write_bytes(content)

    library = root / "lib" / "lib" / "main"
    for legacy_name, corrected_name, corrected_sha256 in REPLACEMENTS:
        legacy = library / legacy_name.decode("ascii")
        corrected = library / corrected_name.decode("ascii")
        if not legacy.is_symlink():
            raise RuntimeError(
                f"Legacy compatibility path must be a symlink: {legacy.name}"
            )
        legacy.unlink()
        observed = hashlib.sha256(corrected.read_bytes()).hexdigest()
        if observed != corrected_sha256:
            raise RuntimeError(f"Corrected JAR SHA-256 drifted: {corrected.name}")

    stale_paths: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        content = path.read_bytes()
        if any(legacy_name in content for legacy_name, _, _ in REPLACEMENTS):
            stale_paths.append(str(path.relative_to(root)))
    if stale_paths:
        raise RuntimeError(f"Legacy paths remain in: {stale_paths}")
    for legacy_name, _, _ in REPLACEMENTS:
        legacy = library / legacy_name.decode("ascii")
        if legacy.exists() or legacy.is_symlink():
            raise RuntimeError(
                f"Legacy filesystem path remains after metadata patch: {legacy.name}"
            )
        if replacement_counts[legacy_name] < len(METADATA_PATHS):
            raise RuntimeError(
                f"Keycloak metadata replacement count is incomplete: {legacy.name}"
            )


if __name__ == "__main__":
    patch_metadata()
