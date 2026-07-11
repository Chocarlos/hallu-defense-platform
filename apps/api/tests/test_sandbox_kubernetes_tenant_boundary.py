from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi import HTTPException

from hallu_defense.api import dependencies, routes
from hallu_defense.api.dependencies import RequestContext
from hallu_defense.domain.models import RepoChecksRunRequest
from hallu_defense.services.auth import Principal


def test_kubernetes_sandbox_rejects_cross_tenant_workspace_access() -> None:
    runtime_settings = replace(
        dependencies.settings,
        sandbox_backend="kubernetes",
        sandbox_kubernetes_tenant_id="tenant-a",
    )
    context = RequestContext(
        tenant_id="tenant-b",
        trace_id="tr_cross_tenant_sandbox",
        principal=Principal(
            subject_id="sandbox-user",
            roles=frozenset({"sandbox_runner"}),
        ),
    )

    with pytest.raises(HTTPException) as raised:
        routes.run_repo_checks(
            RepoChecksRunRequest(
                repo_ref="repo",
                commands=["python probe.py"],
                network_policy="deny",
            ),
            context,
            runtime_settings,
        )

    assert raised.value.status_code == 403
    assert raised.value.detail == "Kubernetes sandbox workspace is bound to a different tenant"
