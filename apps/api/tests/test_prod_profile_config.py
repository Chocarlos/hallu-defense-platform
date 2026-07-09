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
    raise AssertionError("Repository root not found from production profile test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_prod_profile_config = importlib.import_module("scripts.ci.check_prod_profile_config")
BASE_COMPOSE_PATH = check_prod_profile_config.BASE_COMPOSE_PATH
CI_WORKFLOW_PATH = check_prod_profile_config.CI_WORKFLOW_PATH
LIVE_WORKFLOW_PATH = check_prod_profile_config.LIVE_WORKFLOW_PATH
MAKEFILE_PATH = check_prod_profile_config.MAKEFILE_PATH
PROD_COMPOSE_PATH = check_prod_profile_config.PROD_COMPOSE_PATH
PROD_DOC_PATH = check_prod_profile_config.PROD_DOC_PATH
PROMETHEUS_PROD_PATH = check_prod_profile_config.PROMETHEUS_PROD_PATH
ProdProfileConfigError = check_prod_profile_config.ProdProfileConfigError
SECURITY_WORKFLOW_PATH = check_prod_profile_config.SECURITY_WORKFLOW_PATH
load_yaml_file = check_prod_profile_config.load_yaml_file
run_compose_config_if_available = check_prod_profile_config.run_compose_config_if_available
validate_prod_profile_config = check_prod_profile_config.validate_prod_profile_config


def _current_inputs() -> dict[str, object]:
    return {
        "base_compose": load_yaml_file(BASE_COMPOSE_PATH),
        "prod_compose": load_yaml_file(PROD_COMPOSE_PATH),
        "prometheus_prod": load_yaml_file(PROMETHEUS_PROD_PATH),
        "prod_doc_text": PROD_DOC_PATH.read_text(encoding="utf-8"),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "security_workflow_text": SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "live_workflow_text": LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
    }


def _api_env(prod_compose: dict[str, object]) -> dict[str, object]:
    services = prod_compose["services"]
    assert isinstance(services, dict)
    api = services["api"]
    assert isinstance(api, dict)
    env = api["environment"]
    assert isinstance(env, dict)
    return env


def test_prod_profile_config_accepts_current_repository() -> None:
    validate_prod_profile_config(**_current_inputs())


def test_prod_profile_config_rejects_memory_backends() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_AUDIT_LEDGER_BACKEND"] = "memory"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="memory/local backend"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_unsigned_headers() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_AUTH_CLAIMS_MODE"] = "unsigned_headers"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="oidc_jwt"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_host_sandbox_backend() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_SANDBOX_BACKEND"] = "host"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="host sandbox"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_default_credentials() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_POSTGRES_DSN"] = (
        "postgresql://hallu:hallu@postgres:5432/hallu_defense"
    )
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="default credential"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_inline_prometheus_credentials() -> None:
    inputs = _current_inputs()
    prometheus_prod = copy.deepcopy(inputs["prometheus_prod"])
    assert isinstance(prometheus_prod, dict)
    scrape_configs = prometheus_prod["scrape_configs"]
    assert isinstance(scrape_configs, list)
    scrape = scrape_configs[0]
    assert isinstance(scrape, dict)
    authorization = scrape["authorization"]
    assert isinstance(authorization, dict)
    authorization["credentials"] = "inline-token-value"
    inputs["prometheus_prod"] = prometheus_prod

    with pytest.raises(ProdProfileConfigError, match="inline credentials"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_compose_config_skips_without_docker() -> None:
    result = run_compose_config_if_available(runner=("definitely-missing-docker", "compose"))

    assert result["status"] == "skipped"
    assert "docker-compose.prod.yml" in result["command"]
