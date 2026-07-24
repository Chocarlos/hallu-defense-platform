# GitHub repository control plane

Repository files can define workflows and ownership, but they cannot prove that GitHub-hosted settings are enabled. This runbook records the external controls required before the first public release or broad contribution intake.

## Honest status rule

A control remains `pending` until an administrator verifies it in GitHub settings and records dated evidence. A workflow, documentation file, successful local command, or maintainer statement must not be treated as proof of an external setting.

## Required controls

| Control | Required state | Current repository evidence | Status |
| --- | --- | --- | --- |
| Default branch | `master` remains the canonical default branch | Repository metadata and workflows target `master`/`main` | `observed` |
| Branch ruleset | Pull request required; force push and deletion blocked; conversations resolved; required checks selected from a successful run | `CODEOWNERS` and CI workflows exist, but settings are external | `pending` |
| Required approvals | Use one independent approval when a second trusted reviewer exists; do not configure an impossible self-review requirement for a sole maintainer | No independent reviewer is recorded | `pending` |
| Code-owner review | Enable when an eligible reviewer other than the PR author can satisfy it | `.github/CODEOWNERS` identifies `@Chocarlos` | `pending` |
| Tag ruleset | Protect `v*` tags against ordinary creation, update, and deletion | Release workflow requires an existing signed semantic-version tag | `pending` |
| Release environment | Restrict to the protected default branch; require an independent reviewer; prevent self-review; store only the public signing trust bundle required by the workflow | `.github/workflows/release.yml` is fail-closed around protected refs and the `release` environment | `pending` |
| Private vulnerability reporting | Enable GitHub private vulnerability reporting and verify the **Report a vulnerability** button from an unauthenticated account | `SECURITY.md` contains a safe fallback and does not claim enablement | `pending` |
| Security notifications | Repository administrators subscribe to security alerts and verify the notification path | Not represented in repository files | `pending` |

## Branch ruleset procedure

1. Open repository **Settings** and create a branch ruleset targeting the default branch.
2. Require changes through a pull request.
3. Block force pushes and branch deletion.
4. Require conversation resolution.
5. Select required status checks only from an exact, recent successful run. Do not guess check names or require a check that cannot report on pull requests.
6. Require the branch to be up to date only after the selected checks are proven to support that flow.
7. Review bypass actors explicitly. Avoid broad administrator bypasses.
8. If `@Chocarlos` is the only eligible reviewer, keep the required approval count at zero until an independent trusted reviewer exists. CI and PR requirements should still remain active.
9. Record the ruleset name, target, enforcement state, reviewer policy, required checks, verifier, and date in the release evidence.

## Tag ruleset procedure

1. Create a tag ruleset targeting `v*`.
2. Restrict tag creation, update, and deletion to the release authority.
3. Require annotated, signed `vMAJOR.MINOR.PATCH` tags through the documented release process.
4. Verify the rule with a disposable non-release tag pattern before relying on it for production releases.

## Release environment procedure

1. Create the GitHub Environment named `release`.
2. Allow deployments only from the protected default branch.
3. Add an independent reviewer and prevent self-review before enabling publication.
4. Store `RELEASE_SIGNING_PUBLIC_KEYS_B64` as the externally governed public-key trust bundle described in `docs/security/release-process.md`.
5. Do not store private signing keys, provider credentials, deployment credentials, or tenant data in this environment for the current build-and-attest workflow.
6. Execute a dry run using a disposable signed prerelease tag and retain the workflow IDs and artifact evidence.

## Private vulnerability reporting procedure

1. Open **Settings → Security → Advanced Security**.
2. Enable **Private vulnerability reporting**.
3. From an unauthenticated or non-admin account, verify that **Security → Advisories → Report a vulnerability** is available.
4. Subscribe repository administrators to security-alert notifications.
5. Record the verification date without creating a synthetic vulnerability containing sensitive information.

## Release gate

The first public release remains blocked while any of the following are `pending`:

- protected default branch;
- protected `v*` tags;
- independently reviewed `release` environment;
- private vulnerability reporting;
- successful CI, eval, security, and required live evidence for the exact release commit.
