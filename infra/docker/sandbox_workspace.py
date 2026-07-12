from __future__ import annotations

import hashlib
import os
import pathlib
import stat

MAX_WORKSPACE_FILES = 50_000
MAX_WORKSPACE_BYTES = 512 * 1024 * 1024
MAX_WORKSPACE_PATHS = 75_000
MAX_PATH_BYTES = 4_096
MAX_TOTAL_PATH_BYTES = 64 * 1024 * 1024


def workspace_fingerprint(
    root: pathlib.Path,
    *,
    max_files: int = MAX_WORKSPACE_FILES,
    max_bytes: int = MAX_WORKSPACE_BYTES,
    max_paths: int = MAX_WORKSPACE_PATHS,
    max_path_bytes: int = MAX_PATH_BYTES,
    max_total_path_bytes: int = MAX_TOTAL_PATH_BYTES,
) -> str:
    """Hash the exact bounded snapshot that sandbox commands will execute.

    The byte format intentionally matches ``SandboxRunner._workspace_fingerprint``:
    sorted relative directory/file records, file sizes, and full file contents.
    POSIX mode bits are normalized because Docker Desktop bind mounts do not
    preserve Windows host modes. Links and special files fail closed.
    """

    root = root.absolute()
    root_metadata = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("workspace root must be a real directory")
    root = root.resolve(strict=True)
    if (
        max_files <= 0
        or max_bytes < 0
        or max_paths <= 0
        or max_path_bytes <= 0
        or max_total_path_bytes <= 0
    ):
        raise ValueError("workspace fingerprint limits must be positive")

    digest = hashlib.sha256()
    directories = [root]
    file_count = 0
    total_bytes = 0
    path_count = 0
    total_path_bytes = 0
    while directories:
        directory = directories.pop()
        entries = _directory_entries_no_follow(root, directory, max_paths=max_paths)
        for name, metadata in sorted(entries, key=lambda item: item[0]):
            entry = directory / name
            relative = entry.relative_to(root).as_posix()
            relative_bytes = len(relative.encode("utf-8"))
            path_count += 1
            total_path_bytes += relative_bytes
            if relative_bytes > max_path_bytes:
                raise ValueError("workspace path limit exceeded")
            if path_count > max_paths:
                raise ValueError("workspace path count limit exceeded")
            if total_path_bytes > max_total_path_bytes:
                raise ValueError("workspace total path byte limit exceeded")
            if (
                stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & 0x400
            ):
                raise ValueError("workspace links are forbidden")
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(entry)
                digest.update(b"D\0" + relative.encode("utf-8") + b"\0")
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("workspace special files are forbidden")
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > max_files:
                raise ValueError("workspace file limit exceeded")
            if total_bytes > max_bytes:
                raise ValueError("workspace byte limit exceeded")
            digest.update(b"F\0" + relative.encode("utf-8") + b"\0")
            digest.update(str(metadata.st_size).encode("ascii") + b"\0")
            _update_digest_from_unchanged_regular_file(
                digest,
                root,
                entry,
                metadata,
            )
            digest.update(b"\0")
    return digest.hexdigest()


def regular_file_sha256(
    root: pathlib.Path,
    path: pathlib.Path,
    expected: os.stat_result,
) -> str:
    digest = hashlib.sha256()
    _update_digest_from_unchanged_regular_file(digest, root, path, expected)
    return digest.hexdigest()


def _update_digest_from_unchanged_regular_file(
    digest: object,
    root: pathlib.Path,
    path: pathlib.Path,
    expected: os.stat_result,
) -> None:
    relative = path.absolute().relative_to(root.absolute())
    if _supports_secure_directory_fds():
        parent_descriptor = _open_directory_no_follow(root, relative.parent)
        try:
            descriptor = os.open(
                relative.name,
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_descriptor,
            )
        finally:
            os.close(parent_descriptor)
    else:
        before_path = path.lstat()
        if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
            raise ValueError("workspace file must remain a regular non-link file")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        after_path = path.lstat()
        if not _same_file_identity(before_path, opened) or not _same_file_identity(
            opened,
            after_path,
        ):
            os.close(descriptor)
            raise ValueError("workspace file changed during open")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_file_identity(expected, before)
            or before.st_size != expected.st_size
        ):
            raise ValueError("workspace file changed before fingerprinting")
        remaining = expected.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise ValueError("workspace file changed while fingerprinting")
            update = getattr(digest, "update")
            update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("workspace file grew while fingerprinting")
        after = os.fstat(descriptor)
        if not _same_descriptor_snapshot(before, after):
            raise ValueError("workspace file changed while fingerprinting")
    finally:
        os.close(descriptor)


def _supports_secure_directory_fds() -> bool:
    return (
        hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.scandir in os.supports_fd
    )


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    if (
        stat.S_IFMT(first.st_mode) != stat.S_IFMT(second.st_mode)
        or stat.S_IMODE(first.st_mode) != stat.S_IMODE(second.st_mode)
        or first.st_size != second.st_size
    ):
        return False
    first_inode = (getattr(first, "st_dev", 0), getattr(first, "st_ino", 0))
    second_inode = (getattr(second, "st_dev", 0), getattr(second, "st_ino", 0))
    if first_inode != (0, 0) and second_inode != (0, 0):
        return first_inode == second_inode
    return first.st_mtime_ns == second.st_mtime_ns


def _same_descriptor_snapshot(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
        and stat.S_IMODE(first.st_mode) == stat.S_IMODE(second.st_mode)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


def _open_directory_no_follow(root: pathlib.Path, relative: pathlib.Path) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(root, flags)
    try:
        for part in relative.parts:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directory_entries_no_follow(
    root: pathlib.Path,
    directory: pathlib.Path,
    *,
    max_paths: int,
) -> list[tuple[str, os.stat_result]]:
    relative = directory.absolute().relative_to(root.absolute())
    result: list[tuple[str, os.stat_result]] = []
    if _supports_secure_directory_fds():
        descriptor = _open_directory_no_follow(root, relative)
        try:
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if len(result) >= max_paths:
                        raise ValueError("workspace path count limit exceeded")
                    result.append((entry.name, entry.stat(follow_symlinks=False)))
            return result
        finally:
            os.close(descriptor)

    before = directory.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ValueError("workspace directory must remain a real directory")
    with os.scandir(directory) as entries:
        for entry in entries:
            if len(result) >= max_paths:
                raise ValueError("workspace path count limit exceeded")
            result.append((entry.name, entry.stat(follow_symlinks=False)))
    after = directory.lstat()
    if not _same_file_identity(before, after):
        raise ValueError("workspace directory changed during traversal")
    return result
