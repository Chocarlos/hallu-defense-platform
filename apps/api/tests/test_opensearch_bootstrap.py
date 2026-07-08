from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

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
    method, path, body, headers, timeout = transport.calls[0]
    assert method == "PUT"
    assert path == "/_index_template/hallu_evidence_template"
    assert headers is None
    assert timeout == 3
    assert isinstance(body, dict)
    assert body["index_patterns"] == ["hallu_evidence*"]


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


class RecordingOpenSearchTransport:
    def __init__(self, response: Mapping[str, object]) -> None:
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
        return self._response


def _write_template(tmp_path: Path) -> Path:
    template_path = tmp_path / "evidence-index-template.json"
    template_path.write_text(
        json.dumps(
            {
                "index_patterns": ["hallu_evidence*"],
                "template": {
                    "mappings": {
                        "dynamic": False,
                        "properties": {
                            "tenant_id": {"type": "keyword"},
                            "content": {"type": "text"},
                        },
                    },
                },
                "_meta": {"required_query_filter": "tenant_id"},
            }
        ),
        encoding="utf-8",
    )
    return template_path
