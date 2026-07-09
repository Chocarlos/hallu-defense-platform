from __future__ import annotations

import copy
import importlib
import sys
from pathlib import Path

import pytest


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "Makefile").exists() and (parent / ".github").exists():
            return parent
    raise AssertionError("Repository root not found from Helm chart test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_helm_chart = importlib.import_module("scripts.ci.check_helm_chart")
CHART_PATH = check_helm_chart.CHART_PATH
CI_WORKFLOW_PATH = check_helm_chart.CI_WORKFLOW_PATH
DEPLOYMENT_DOC_PATH = check_helm_chart.DEPLOYMENT_DOC_PATH
HelmChartConfigError = check_helm_chart.HelmChartConfigError
LIVE_WORKFLOW_PATH = check_helm_chart.LIVE_WORKFLOW_PATH
MAKEFILE_PATH = check_helm_chart.MAKEFILE_PATH
SECURITY_WORKFLOW_PATH = check_helm_chart.SECURITY_WORKFLOW_PATH
VALUES_PATH = check_helm_chart.VALUES_PATH
load_template_texts = check_helm_chart.load_template_texts
load_yaml_file = check_helm_chart.load_yaml_file
run_helm_template_if_available = check_helm_chart.run_helm_template_if_available
validate_helm_chart = check_helm_chart.validate_helm_chart


def _current_inputs() -> dict[str, object]:
    return {
        "chart": load_yaml_file(CHART_PATH),
        "values": load_yaml_file(VALUES_PATH),
        "templates": load_template_texts(),
        "deployment_doc_text": DEPLOYMENT_DOC_PATH.read_text(encoding="utf-8"),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "security_workflow_text": SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "live_workflow_text": LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
    }


def test_helm_chart_validates_current_repository() -> None:
    validate_helm_chart(**_current_inputs())


def test_helm_chart_rejects_missing_worker_template() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates.pop("worker-deployment.yaml")
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="worker-deployment"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_missing_non_root_security_context() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    helpers = templates["_helpers.tpl"]
    templates["_helpers.tpl"] = helpers.replace("runAsNonRoot: true", "runAsNonRoot: false")
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="runAsNonRoot"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_plaintext_secret_defaults() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    secrets = values["secrets"]
    assert isinstance(secrets, dict)
    secrets["postgresPassword"] = "change-me"
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="default secret marker"):
        validate_helm_chart(**inputs)


def test_helm_chart_template_skips_when_helm_missing() -> None:
    result = run_helm_template_if_available(helm_binary="definitely-missing-helm")

    assert result["status"] == "skipped"
    assert "helm template" in result["command"]
