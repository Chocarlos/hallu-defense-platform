from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

import pytest

from scripts.dev import live_opensearch_rag_smoke as smoke


def test_live_opensearch_rag_smoke_skips_by_default() -> None:
    result = smoke.run_from_env({})

    assert result["status"] == "skipped"
    assert result["indexed_count"] == 0
    assert result["tenant_isolation"] is False


@pytest.mark.parametrize(
    "index_name",
    [
        "hallu_evidence",
        "other_smoke",
        "hallu_evidence_*_smoke",
        "hallu-evidence-smoke",
        "HALLU_EVIDENCE_SMOKE",
    ],
)
def test_live_opensearch_rag_smoke_rejects_unsafe_index_names(index_name: str) -> None:
    with pytest.raises(ValueError):
        smoke.validate_smoke_index_name(index_name)


def test_live_opensearch_rag_smoke_runs_with_recording_transport() -> None:
    transport = RecordingOpenSearchTransport()

    result = smoke.run_from_env(
        {
            smoke.ENABLED_ENV: "true",
            smoke.ENDPOINT_ENV: "http://opensearch:9200",
            smoke.SMOKE_INDEX_ENV: "hallu_evidence_live_smoke",
            smoke.TIMEOUT_ENV: "5",
        },
        transport=transport,
        run_id="unit",
    )

    assert result == {
        "status": "passed",
        "endpoint": "http://opensearch:9200",
        "index_name": "hallu_evidence_live_smoke",
        "backend": "opensearch",
        "indexed_count": 2,
        "tenant_isolation": True,
    }
    paths = [call[1] for call in transport.calls]
    assert "/_index_template/hallu_evidence_template" in paths
    assert paths.count("/hallu_evidence_live_smoke?ignore_unavailable=true") == 2
    assert "/hallu_evidence_live_smoke/_refresh" in paths


def test_live_opensearch_rag_smoke_main_returns_failure_for_bad_timeout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = smoke.main(env={smoke.ENABLED_ENV: "true", smoke.TIMEOUT_ENV: "0"})

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert "TIMEOUT" in payload["error"]


class RecordingOpenSearchTransport:
    def __init__(self) -> None:
        self.calls: list[
            tuple[
                str,
                str,
                Mapping[str, object] | Sequence[object] | str,
                Mapping[str, str] | None,
                float,
            ]
        ] = []
        self._documents: list[dict[str, object]] = []

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
        if path.startswith("/_index_template/"):
            return {"acknowledged": True}
        if method == "DELETE" and path == "/hallu_evidence_live_smoke?ignore_unavailable=true":
            self._documents.clear()
            return {"acknowledged": True}
        if method == "PUT" and path == "/hallu_evidence_live_smoke":
            return {"acknowledged": True}
        if method == "POST" and path == "/_bulk":
            assert isinstance(body, Sequence)
            for item in body:
                if isinstance(item, Mapping) and "tenant_id" in item:
                    self._documents.append(dict(item))
            return {"errors": False}
        if method == "POST" and path == "/hallu_evidence_live_smoke/_refresh":
            return {"_shards": {"successful": 1}}
        if method == "POST" and path == "/hallu_evidence_live_smoke/_search":
            assert isinstance(body, Mapping)
            tenant_id = _tenant_filter(body)
            query_text = _query_text(body)
            hits = [
                {"_score": 1.0, "_source": document}
                for document in self._documents
                if document.get("tenant_id") == tenant_id and _matches_query(query_text, document)
            ]
            return {"hits": {"hits": hits}}
        raise AssertionError(f"Unexpected OpenSearch request: {method} {path}")


def _tenant_filter(body: Mapping[str, object]) -> str:
    query = body["query"]
    assert isinstance(query, Mapping)
    bool_query = query["bool"]
    assert isinstance(bool_query, Mapping)
    filters = bool_query["filter"]
    assert isinstance(filters, Sequence)
    for item in filters:
        if not isinstance(item, Mapping):
            continue
        term = item.get("term")
        if isinstance(term, Mapping) and isinstance(term.get("tenant_id"), str):
            return term["tenant_id"]
    raise AssertionError("tenant_id filter missing")


def _query_text(body: Mapping[str, object]) -> str:
    query = body["query"]
    assert isinstance(query, Mapping)
    bool_query = query["bool"]
    assert isinstance(bool_query, Mapping)
    must = bool_query["must"]
    assert isinstance(must, Sequence)
    multi_match = must[0]
    assert isinstance(multi_match, Mapping)
    clause = multi_match["multi_match"]
    assert isinstance(clause, Mapping)
    value = clause["query"]
    assert isinstance(value, str)
    return value


def _matches_query(query_text: str, document: Mapping[str, object]) -> bool:
    content = document.get("content")
    if not isinstance(content, str):
        return False
    query_terms = {term.lower() for term in query_text.split()}
    content_terms = {term.strip(".,").lower() for term in content.split()}
    return bool(query_terms.intersection(content_terms))
