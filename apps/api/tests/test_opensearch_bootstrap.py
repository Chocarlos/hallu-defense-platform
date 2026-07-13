from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

import scripts.dev.bootstrap_opensearch_template as bootstrap_module
from hallu_defense.config import RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP, Settings
from hallu_defense.services.rag_index import RagIndexConfigurationError, RagIndexTransportError
from scripts.dev.bootstrap_opensearch_template import (
    bootstrap_opensearch_template,
    load_template,
)


def test_bootstrap_opensearch_template_dry_run_validates_without_transport(
    tmp_path: Path,
) -> None:
    template_path = _write_template(tmp_path)

    result = bootstrap_opensearch_template(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        template_name="hallu_evidence_template",
        template_path=template_path,
        timeout_seconds=3,
        dry_run=True,
    )

    assert result.dry_run is True
    assert result.installed is False
    assert result.acknowledged is False
    assert result.to_jsonable()["template_path"] == str(template_path)


def test_bootstrap_opensearch_template_installs_with_acknowledgement(
    tmp_path: Path,
) -> None:
    template_path = _write_template(tmp_path)
    transport = RecordingOpenSearchTransport(response={"acknowledged": True})

    result = bootstrap_opensearch_template(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        template_name="hallu_evidence_template",
        template_path=template_path,
        timeout_seconds=3,
        transport=transport,
    )

    assert result.installed is True
    assert result.acknowledged is True
    assert result.schema_version == "rag-opensearch-template.v3"
    assert result.index_state == "absent"
    assert result.schema_ready is True
    method, path, body, headers, timeout = transport.calls[0]
    assert method == "PUT"
    assert path == "/_index_template/hallu_evidence_template"
    assert headers is None
    assert timeout == 3
    assert isinstance(body, dict)
    assert body["index_patterns"] == ["hallu_evidence*"]
    assert [call[1] for call in transport.calls] == [
        "/_index_template/hallu_evidence_template",
        "/_index_template/hallu_evidence_template",
        "/hallu_evidence/_mapping?ignore_unavailable=true&expand_wildcards=all",
    ]


def test_bootstrap_opensearch_template_fails_when_not_acknowledged(
    tmp_path: Path,
) -> None:
    template_path = _write_template(tmp_path)
    transport = RecordingOpenSearchTransport(response={"acknowledged": False})

    with pytest.raises(RagIndexTransportError, match="did not acknowledge"):
        bootstrap_opensearch_template(
            endpoint="http://opensearch:9200",
            index_name="hallu_evidence",
            template_name="hallu_evidence_template",
            template_path=template_path,
            timeout_seconds=3,
            transport=transport,
        )


def test_load_template_requires_json_object(tmp_path: Path) -> None:
    template_path = tmp_path / "bad-template.json"
    template_path.write_text("[]", encoding="utf-8")

    with pytest.raises(RagIndexConfigurationError, match="JSON object"):
        load_template(template_path)


def test_bootstrap_cli_loads_only_dedicated_runtime_role(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    template_path = _write_template(tmp_path)
    settings = Settings(
        runtime_role=RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP,
        environment="local",
        policy_version="bootstrap-test",
        auth_required=False,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        rag_index_backend="opensearch",
        opensearch_endpoint="http://opensearch:9200",
        opensearch_index_name="hallu_evidence",
    )
    observed: list[str | None] = []

    def fake_load_settings(*, expected_runtime_role: str | None = None) -> Settings:
        observed.append(expected_runtime_role)
        return settings

    monkeypatch.setattr(bootstrap_module, "load_settings", fake_load_settings)

    bootstrap_module.main(["--dry-run", "--template-path", str(template_path)])

    assert observed == [RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP]
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "rag-opensearch-template.v3"
    assert payload["index_state"] == "not_checked"


def test_bootstrap_rejects_existing_pre_v3_index_and_requires_reindex(
    tmp_path: Path,
) -> None:
    template_path = _write_template(tmp_path)
    transport = RecordingOpenSearchTransport(
        response={"acknowledged": True},
        mapping_response={
            "hallu_evidence": {
                "mappings": {
                    "properties": {
                        "tenant_id": {"type": "keyword"},
                        "evidence_id": {"type": "keyword"},
                        "source_ref": {"type": "keyword"},
                    }
                }
            }
        },
    )

    with pytest.raises(RagIndexTransportError, match="create and reindex.*schema v3"):
        bootstrap_opensearch_template(
            endpoint="http://opensearch:9200",
            index_name="hallu_evidence",
            template_name="hallu_evidence_template",
            template_path=template_path,
            timeout_seconds=3,
            transport=transport,
        )


def test_bootstrap_fails_when_template_readback_is_not_schema_v3(
    tmp_path: Path,
) -> None:
    template_path = _write_template(tmp_path)
    transport = RecordingOpenSearchTransport(
        response={"acknowledged": True},
        readback_response={"index_templates": []},
    )

    with pytest.raises(RagIndexTransportError, match="readback"):
        bootstrap_opensearch_template(
            endpoint="http://opensearch:9200",
            index_name="hallu_evidence",
            template_name="hallu_evidence_template",
            template_path=template_path,
            timeout_seconds=3,
            transport=transport,
        )


def test_bootstrap_rejects_template_that_does_not_target_configured_index(
    tmp_path: Path,
) -> None:
    template = _template_payload()
    template["index_patterns"] = ["other_index*"]
    template_path = tmp_path / "wrong-pattern.json"
    template_path.write_text(json.dumps(template), encoding="utf-8")

    with pytest.raises(RagIndexConfigurationError, match="does not target"):
        bootstrap_opensearch_template(
            endpoint="http://opensearch:9200",
            index_name="hallu_evidence",
            template_name="hallu_evidence_template",
            template_path=template_path,
            timeout_seconds=3,
            transport=RecordingOpenSearchTransport(
                response={"acknowledged": True}
            ),
        )


@pytest.mark.parametrize("dynamic_value", [False, "false"])
def test_bootstrap_reports_compatible_only_when_existing_v3_mapping_and_replicas_are_present(
    tmp_path: Path,
    dynamic_value: bool | str,
) -> None:
    template_path = _write_template(tmp_path)
    template = _template_payload()
    template_body = template["template"]
    assert isinstance(template_body, Mapping)
    raw_mappings = template_body["mappings"]
    assert isinstance(raw_mappings, Mapping)
    mappings = dict(raw_mappings)
    mappings["dynamic"] = dynamic_value
    transport = RecordingOpenSearchTransport(
        response={"acknowledged": True},
        mapping_response={"hallu_evidence": {"mappings": mappings}},
        settings_response={
            "hallu_evidence": {
                "settings": {"index": {"number_of_replicas": "1"}}
            }
        },
    )

    result = bootstrap_opensearch_template(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        template_name="hallu_evidence_template",
        template_path=template_path,
        timeout_seconds=3,
        transport=transport,
    )

    assert result.index_state == "compatible"
    assert result.schema_ready is True


def test_bootstrap_rejects_existing_v3_index_without_replica() -> None:
    template = _template_payload()
    body = template["template"]
    assert isinstance(body, Mapping)
    mappings = body["mappings"]
    assert isinstance(mappings, Mapping)
    transport = RecordingOpenSearchTransport(
        response={"acknowledged": True},
        mapping_response={"hallu_evidence": {"mappings": mappings}},
        settings_response={
            "hallu_evidence": {
                "settings": {"index": {"number_of_replicas": "0"}}
            }
        },
    )
    backend = bootstrap_module.OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=transport,
    )

    with pytest.raises(RagIndexTransportError, match="at least one replica"):
        backend.provision_index_schema(
            template_name="hallu_evidence_template",
            template=template,
        )


class RecordingOpenSearchTransport:
    def __init__(
        self,
        response: Mapping[str, object],
        *,
        mapping_response: Mapping[str, object] | None = None,
        readback_response: Mapping[str, object] | None = None,
        settings_response: Mapping[str, object] | None = None,
    ) -> None:
        self.calls: list[
            tuple[
                str,
                str,
                Mapping[str, object] | Sequence[object] | str,
                Mapping[str, str] | None,
                float,
            ]
        ] = []
        self._response = response
        self._mapping_response = mapping_response or {}
        self._readback_response = readback_response
        self._settings_response = settings_response or {}
        self._installed_template: Mapping[str, object] | None = None

    def request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | Sequence[object] | str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append((method, path, body, headers, timeout_seconds))
        if method == "PUT" and path.startswith("/_index_template/"):
            assert isinstance(body, Mapping)
            self._installed_template = body
            return self._response
        if method == "GET" and path.startswith("/_index_template/"):
            if self._readback_response is not None:
                return self._readback_response
            assert self._installed_template is not None
            return {
                "index_templates": [
                    {
                        "name": path.rsplit("/", maxsplit=1)[-1],
                        "index_template": self._installed_template,
                    }
                ]
            }
        if method == "GET" and "_mapping" in path:
            return self._mapping_response
        if method == "GET" and "_settings" in path:
            return self._settings_response
        return self._response


def _write_template(tmp_path: Path) -> Path:
    template_path = tmp_path / "evidence-index-template.json"
    template_path.write_text(
        json.dumps(_template_payload()),
        encoding="utf-8",
    )
    return template_path


def _template_payload() -> dict[str, object]:
    return {
        "index_patterns": ["hallu_evidence*"],
        "template": {
            "settings": {"number_of_replicas": 1},
            "mappings": {
                "_meta": {"schema_version": "rag-opensearch-template.v3"},
                "dynamic": False,
                "properties": {
                    "tenant_id": {"type": "keyword"},
                    "evidence_id": {"type": "keyword"},
                    "source_ref": {"type": "keyword"},
                    "corpus_id": {"type": "keyword"},
                    "document_revision": {"type": "keyword"},
                    "content": {"type": "text"},
                    "metadata": {
                        "type": "object",
                        "enabled": False,
                    },
                    "metadata_filter_tokens": {"type": "keyword"},
                },
            },
        },
        "_meta": {
            "schema_version": "rag-opensearch-template.v3",
            "required_query_filter": "tenant_id",
        },
    }
