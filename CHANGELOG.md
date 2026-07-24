# Changelog

This file records notable user-visible, security-relevant, and compatibility changes to Hallu Defense Platform.

The project has not published a stable release yet. Entries remain under `Unreleased` until a signed, accepted release is created from an exact commit.

## Unreleased

### Added

- Apache License 2.0 as the repository license.
- Licensing and attribution policy identifying Chocarlos as the copyright holder.
- Contribution provenance and licensing requirements.
- Community governance files, issue forms, pull-request review guidance, code ownership, and conservative Dependabot configuration.
- Public-release contract and external repository-control runbook for `v0.1.0`.
- Failure-only CI artifacts for Python test and Node audit diagnostics; the underlying gates remain fail-closed.

### Changed

- The public-repository stabilization work is being developed on a dedicated branch and draft pull request; `master` remains unchanged until review and validation are complete.
- The public README is shorter and identifies the project as a technical alpha while preserving exact-commit acceptance limits and operational gates.

### Security

- Updated the Next-scoped PostCSS override and generated lock from `8.5.10` to patched `8.5.12` for `CVE-2026-45623` / `GHSA-6g55-p6wh-862q`; no audit exception or vulnerability ignore was added.
- Licensing and governance documentation does not change authentication, authorization, sandbox, provider, persistence, network, secret-handling, or deployment behavior.
- Private vulnerability reporting is documented as a required external setting and is not represented as enabled until independently verified in GitHub settings.

## Release entry requirements

A versioned entry must identify:

- the exact signed tag and source commit;
- compatibility or migration impact;
- security-relevant changes and remaining limitations;
- validation evidence for that exact commit;
- released artifacts and their checksums, SBOMs, and attestations where applicable.

Do not move an item from `Unreleased` into a versioned section until the corresponding release process has completed successfully.
