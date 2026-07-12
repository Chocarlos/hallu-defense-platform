from __future__ import annotations

from typing import Any

from httpx import Response

from evals.runners.smoke import EVAL_TENANT_ID, _post_verification_scenario


class _RecordingClient:
    def __init__(self) -> None:
        self.path: str | None = None
        self.request_kwargs: dict[str, Any] = {}

    def post(
        self,
        path: str,
        *,
        json: Any,
        headers: dict[str, str],
    ) -> Response:
        self.path = path
        self.request_kwargs = {"json": json, "headers": headers}
        return Response(200)


def test_smoke_verification_request_binds_body_and_header_to_eval_tenant() -> None:
    client = _RecordingClient()
    scenario = {
        "message_text": "The policy is supported.",
        "task_type": "document_qa",
        "documents": [],
    }

    _post_verification_scenario(client, scenario)

    assert client.path == "/verification/run"
    assert client.request_kwargs["json"]["tenant_id"] == EVAL_TENANT_ID
    assert client.request_kwargs["headers"] == {"x-tenant-id": EVAL_TENANT_ID}
