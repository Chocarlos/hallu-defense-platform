from __future__ import annotations

import json

from scripts.dev import live_prod_profile_e2e as smoke


def test_live_prod_profile_e2e_skips_by_default() -> None:
    result = smoke.run_from_env({})

    assert result["status"] == "skipped"
    assert "eval" in result["planned_checks"]
    assert "unresolved_dependencies" not in result


def test_live_prod_profile_e2e_enabled_requires_bearer_token() -> None:
    exit_code = smoke.main(env={smoke.ENABLED_ENV: "true"})

    assert exit_code == 1


def test_live_prod_profile_e2e_enabled_requires_explicit_sandbox_repo_ref() -> None:
    exit_code = smoke.main(
        env={
            smoke.ENABLED_ENV: "true",
            smoke.BEARER_TOKEN_ENV: "synthetic-token",
        }
    )

    assert exit_code == 1


def test_live_prod_profile_e2e_skip_output_does_not_leak_tokens(
    capsys,
) -> None:
    exit_code = smoke.main(env={smoke.BEARER_TOKEN_ENV: "secret-token"})

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "skipped"
    assert "secret-token" not in json.dumps(payload)
