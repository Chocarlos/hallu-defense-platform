from __future__ import annotations

import hashlib
import os
import pathlib
import stat

MAX_WORKSPACE_FILES = 50_000
MAX_WORKSPACE_BYTES = 512 * 1024 * 1024


def workspace_fingerprint(
    root: pathlib.Path,
    *,
    max_files: int = MAX_WORKSPACE_FILES,
    max_bytes: int = MAX_WORKSPACE_BYTES,
) -> str:
    """Hash the exact bounded snapshot that sandbox commands will execute.

    The byte format intentionally matches ``SandboxRunner._workspace_fingerprint``:
    sorted relative directory/file records, file sizes, and full file contents.
    Links and special files fail closed.
    """

    root = root.resolve(strict=True)
    root_metadata = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("workspace root must be a real directory")
    if max_files <= 0 or max_bytes <= 0:
        raise ValueError("workspace fingerprint limits must be positive")

    digest = hashlib.sha256()
    directories = [root]
    file_count = 0
    total_bytes = 0
    while directories:
        directory = directories.pop()
        entries = sorted(directory.iterdir(), key=lambda entry: entry.name)
        for entry in entries:
            metadata = entry.lstat()
            relative = entry.relative_to(root).as_posix()
            if entry.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
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
            _update_digest_from_unchanged_regular_file(digest, entry, metadata)
            digest.update(b"\0")
    return digest.hexdigest()


def regular_file_sha256(path: pathlib.Path, expected: os.stat_result) -> str:
    digest = hashlib.sha256()
    _update_digest_from_unchanged_regular_file(digest, path, expected)
    return digest.hexdigest()


def _update_digest_from_unchanged_regular_file(
    digest: object,
    path: pathlib.Path,
    expected: os.stat_result,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != expected.st_dev
            or before.st_ino != expected.st_ino
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
        if (
            after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise ValueError("workspace file changed while fingerprinting")
    finally:
        os.close(descriptor)
