# Changelog

This file records notable user-visible, security-relevant, and compatibility changes to Hallu Defense Platform.

The project has not published a stable release yet. Entries remain under `Unreleased` until a signed, accepted release is created from an exact commit.

## Unreleased

### Added

- Apache License 2.0 as the repository license.
- Licensing and attribution policy identifying Xocarlos as the copyright holder.
- Contribution provenance and licensing requirements.

### Changed

- The public-repository stabilization work is being developed on a dedicated branch and draft pull request; `master` remains unchanged until review and validation are complete.

### Security

- No runtime, authentication, authorization, sandbox, provider, persistence, network, secret-handling, or deployment behavior is changed by the licensing work.

## Release entry requirements

A versioned entry must identify:

- the exact signed tag and source commit;
- compatibility or migration impact;
- security-relevant changes and remaining limitations;
- validation evidence for that exact commit;
- released artifacts and their checksums, SBOMs, and attestations where applicable.

Do not move an item from `Unreleased` into a versioned section until the corresponding release process has completed successfully.
