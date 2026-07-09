from __future__ import annotations

import json

from scripts.dev import live_kind_helm_smoke as smoke


def test_live_kind_helm_smoke_skips_by_default() -> None:
    result = smoke.run_from_env({})

    assert result["status"] == "skipped"
    assert result["required_tools"] == ["kind", "kubectl", "helm"]


def test_live_kind_helm_smoke_skip_prints_json(capsys) -> None:
    exit_code = smoke.main(env={})

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "skipped"
