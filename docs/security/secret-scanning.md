# Secret Scanning and Synthetic Fixtures

The repository uses two fail-closed scanners. `scripts/ci/secret_scan.py` inspects the
current tracked/non-ignored source snapshot for high-signal assignments and private-key
material. `scripts/ci/run_gitleaks.py` runs pinned Gitleaks 8.30.1 both against that
source snapshot and against the complete Git history (`git --all`). Security checkout
uses `fetch-depth: 0`; a shallow repository cannot claim full-history coverage.

`.gitleaks.toml` contains detector rules but deliberately contains no path or regex
allowlist. Tests, examples, documentation, live-smoke scripts, and broad categories are
not trusted merely because of their location or name.

The only accepted exceptions live in
`requirements/gitleaks-synthetic-fixtures.json`. Each entry binds exactly:

- one normalized repository-relative file path;
- one exact detector rule ID;
- the SHA-256 of the exact matched value; and
- a documented synthetic purpose.

Changing any byte, moving the fixture, changing its detector, adding an unexpected
manifest field, duplicating a fingerprint, using traversal/absolute paths, or presenting
an unlisted finding fails. The scanners never print the matched secret value. New
fixtures require review of the concrete value and a new exact fingerprint; never add a
directory, filename glob, generic `test`/`example` exemption, or detector-class waiver.

The Gitleaks runner prefers the externally installed pinned binary and verifies the
reported version. Its Docker fallback is digest-pinned, runs without network and with a
non-root host UID/GID on POSIX, and rejects linked-worktree history scans it cannot
faithfully mount. Tool absence, malformed/non-UTF-8 tracked content, symlinks, timeouts,
invalid JSON reports, shallow history, or Git/Docker errors are scan failures rather
than skipped files.

Run the gates with:

```text
python scripts/ci/check_gitleaks_config.py
python scripts/ci/run_gitleaks.py
python scripts/ci/secret_scan.py
```

Record the actual engine/version and both directory/history results. A fixture-filtered
result means only exact committed synthetic fingerprints were suppressed; it does not
authorize equivalent-looking credentials elsewhere.
