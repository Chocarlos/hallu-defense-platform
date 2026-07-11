from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path

MAX_RUNTIME_SECRET_BYTES = 64 * 1024
MAX_MOUNTINFO_BYTES = 1024 * 1024
KUBERNETES_DATA_DIRECTORY_RE = re.compile(r"^\.\.[A-Za-z0-9_.-]{1,255}$")


class RuntimeSecretError(ValueError):
    """Raised when a file-backed runtime secret is unavailable or unsafe."""


def read_runtime_secret_file(path_value: str, *, variable_name: str) -> str:
    path = Path(path_value)
    if not path.is_absolute():
        raise RuntimeSecretError(f"{variable_name} must reference an absolute path.")
    descriptor: int | None = None
    try:
        link_stat = path.lstat()
        opened_path, expected_stat = _runtime_secret_open_path(
            path,
            link_stat=link_stat,
            variable_name=variable_name,
        )
        descriptor = os.open(
            opened_path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise RuntimeSecretError(f"{variable_name} must reference a regular file.")
        if os.name != "nt" and (
            file_stat.st_dev != expected_stat.st_dev
            or file_stat.st_ino != expected_stat.st_ino
        ):
            raise RuntimeSecretError(f"{variable_name} changed while it was opened.")
        mode = stat.S_IMODE(file_stat.st_mode)
        if os.name != "nt" and mode not in {0o400, 0o440}:
            raise RuntimeSecretError(
                f"{variable_name} must use mode 0400 or 0440 with no access for others."
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            payload = handle.read(MAX_RUNTIME_SECRET_BYTES + 1)
    except RuntimeSecretError:
        raise
    except OSError as exc:
        raise RuntimeSecretError(f"{variable_name} could not be read.") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(payload) > MAX_RUNTIME_SECRET_BYTES:
        raise RuntimeSecretError(f"{variable_name} exceeds the 64 KiB limit.")
    if b"\x00" in payload:
        raise RuntimeSecretError(f"{variable_name} contains a NUL byte.")
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeSecretError(f"{variable_name} must contain UTF-8 text.") from exc
    value = decoded.rstrip("\r\n")
    if not value or value != value.strip() or "\n" in value or "\r" in value:
        raise RuntimeSecretError(
            f"{variable_name} must contain one non-empty line without surrounding whitespace."
        )
    return value


def _runtime_secret_open_path(
    path: Path,
    *,
    link_stat: os.stat_result,
    variable_name: str,
) -> tuple[Path, os.stat_result]:
    if not stat.S_ISLNK(link_stat.st_mode):
        return path, link_stat
    if not _is_root_owned(link_stat):
        raise RuntimeSecretError(
            f"{variable_name} projected secret link must be root-owned."
        )
    try:
        key_target = Path(os.readlink(path))
    except OSError as exc:
        raise RuntimeSecretError(
            f"{variable_name} projected secret link could not be inspected."
        ) from exc
    if key_target.is_absolute() or key_target.parts != ("..data", path.name):
        raise RuntimeSecretError(
            f"{variable_name} must be a regular file or a Kubernetes projected secret symlink."
        )
    mount_root = path.parent
    data_link = mount_root / "..data"
    try:
        mount_stat = mount_root.lstat()
        data_link_stat = data_link.lstat()
        data_target = Path(os.readlink(data_link))
    except OSError as exc:
        raise RuntimeSecretError(
            f"{variable_name} projected secret layout could not be inspected."
        ) from exc
    if (
        not stat.S_ISDIR(mount_stat.st_mode)
        or stat.S_ISLNK(mount_stat.st_mode)
        or not _is_root_owned(mount_stat)
        or not stat.S_ISLNK(data_link_stat.st_mode)
        or not _is_root_owned(data_link_stat)
        or data_target.is_absolute()
        or len(data_target.parts) != 1
        or KUBERNETES_DATA_DIRECTORY_RE.fullmatch(data_target.name) is None
        or data_target.name == "..data"
    ):
        raise RuntimeSecretError(
            f"{variable_name} projected secret layout is not trusted."
        )
    version_directory = mount_root / data_target
    target = version_directory / path.name
    try:
        version_stat = version_directory.lstat()
        target_stat = target.lstat()
    except OSError as exc:
        raise RuntimeSecretError(
            f"{variable_name} projected secret target is unavailable."
        ) from exc
    if (
        not stat.S_ISDIR(version_stat.st_mode)
        or stat.S_ISLNK(version_stat.st_mode)
        or not _is_root_owned(version_stat)
        or not stat.S_ISREG(target_stat.st_mode)
        or stat.S_ISLNK(target_stat.st_mode)
        or not _is_root_owned(target_stat)
        or not _path_is_on_read_only_mount(path)
    ):
        raise RuntimeSecretError(
            f"{variable_name} projected secret must be root-owned on a read-only mount."
        )
    return target, target_stat


def _is_root_owned(metadata: os.stat_result) -> bool:
    return os.name == "nt" or metadata.st_uid == 0


def _path_is_on_read_only_mount(path: Path) -> bool:
    if os.name == "nt":
        return False
    try:
        with Path("/proc/self/mountinfo").open("rb") as handle:
            payload = handle.read(MAX_MOUNTINFO_BYTES + 1)
    except OSError:
        return False
    if len(payload) > MAX_MOUNTINFO_BYTES:
        return False
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return False
    normalized_path = str(path.resolve(strict=False))
    best_length = -1
    best_read_only = False
    for line in lines:
        left, separator, _right = line.partition(" - ")
        if not separator:
            continue
        fields = left.split()
        if len(fields) < 6:
            continue
        mount_point = _decode_mountinfo_path(fields[4])
        try:
            if os.path.commonpath((normalized_path, mount_point)) != mount_point:
                continue
        except ValueError:
            continue
        if len(mount_point) > best_length:
            best_length = len(mount_point)
            best_read_only = "ro" in fields[5].split(",")
    return best_read_only


def _decode_mountinfo_path(value: str) -> str:
    for escaped, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(escaped, decoded)
    return value


def load_runtime_secret(
    environ: Mapping[str, str],
    *,
    value_variable: str,
    file_variable: str,
) -> str | None:
    direct = environ.get(value_variable)
    file_path = environ.get(file_variable)
    if direct and file_path:
        raise RuntimeSecretError(
            f"{value_variable} and {file_variable} are mutually exclusive."
        )
    if file_path:
        return read_runtime_secret_file(file_path, variable_name=file_variable)
    return direct or None


def load_runtime_secret_from_os(
    *,
    value_variable: str,
    file_variable: str,
) -> str | None:
    return load_runtime_secret(
        os.environ,
        value_variable=value_variable,
        file_variable=file_variable,
    )
