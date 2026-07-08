from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from hallu_defense.config import load_settings
from hallu_defense.services.rag_index import (
    OpenSearchRagIndexBackend,
    OpenSearchTransport,
    RagIndexConfigurationError,
    RagIndexTransportError,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TEMPLATE_PATH = ROOT / "infra" / "rag" / "opensearch" / "evidence-index-template.json"
DEFAULT_TEMPLATE_NAME = "hallu_evidence_template"


@dataclass(frozen=True)
class OpenSearchTemplateBootstrapResult:
    template_name: str
    endpoint: str
    index_name: str
    template_path: Path
    dry_run: bool
    installed: bool
    acknowledged: bool

    def to_jsonable(self) -> dict[str, object]:
        return {
            "template_name": self.template_name,
            "endpoint": self.endpoint,
            "index_name": self.index_name,
            "template_path": str(self.template_path),
            "dry_run": self.dry_run,
            "installed": self.installed,
            "acknowledged": self.acknowledged,
        }


def load_template(template_path: Path) -> dict[str, object]:
    payload = json.loads(template_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RagIndexConfigurationError("OpenSearch index template must be a JSON object")
    return payload


def bootstrap_opensearch_template(
    *,
    endpoint: str,
    index_name: str,
    template_name: str,
    template_path: Path,
    timeout_seconds: float,
    dry_run: bool = False,
    transport: OpenSearchTransport | None = None,
) -> OpenSearchTemplateBootstrapResult:
    template = load_template(template_path)
    backend = OpenSearchRagIndexBackend(
        endpoint=endpoint,
        index_name=index_name,
        timeout_seconds=timeout_seconds,
        transport=_ValidationOnlyOpenSearchTransport() if dry_run else transport,
    )
    if dry_run:
        backend.install_index_template(
            template_name=template_name,
            template=template,
        )
        return OpenSearchTemplateBootstrapResult(
            template_name=template_name,
            endpoint=endpoint,
            index_name=index_name,
            template_path=template_path,
            dry_run=True,
            installed=False,
            acknowledged=False,
        )

    result = backend.install_index_template(
        template_name=template_name,
        template=template,
    )
    if not result.acknowledged:
        raise RagIndexTransportError(
            f"OpenSearch did not acknowledge index template installation at {result.path}"
        )
    return OpenSearchTemplateBootstrapResult(
        template_name=template_name,
        endpoint=endpoint,
        index_name=index_name,
        template_path=template_path,
        dry_run=False,
        installed=True,
        acknowledged=True,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Install the RAG OpenSearch index template.")
    parser.add_argument("--endpoint", default=settings.opensearch_endpoint)
    parser.add_argument("--index-name", default=settings.opensearch_index_name)
    parser.add_argument("--template-name", default=DEFAULT_TEMPLATE_NAME)
    parser.add_argument("--template-path", type=Path, default=DEFAULT_TEMPLATE_PATH)
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=float(settings.rag_index_timeout_seconds),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate local inputs without sending a request to OpenSearch.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    result = bootstrap_opensearch_template(
        endpoint=args.endpoint,
        index_name=args.index_name,
        template_name=args.template_name,
        template_path=args.template_path,
        timeout_seconds=args.timeout_seconds,
        dry_run=args.dry_run,
    )
    print(json.dumps(result.to_jsonable(), sort_keys=True))


class _ValidationOnlyOpenSearchTransport:
    def request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | Sequence[object] | str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        return {"acknowledged": method == "PUT" and path.startswith("/_index_template/")}


if __name__ == "__main__":
    main()
