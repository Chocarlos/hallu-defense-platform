from __future__ import annotations

import copy
from pathlib import Path

import pytest

from scripts.ci.check_encryption_config import (
    POLICY_PATH,
    PolicyValidationError,
    load_policy,
    validate_policy,
)

ROOT = Path(__file__).resolve().parents[3]


def test_encryption_policy_validates_enterprise_defaults() -> None:
    policy = load_policy(POLICY_PATH)

    validate_policy(policy)

    defaults = policy["defaults"]
    assert isinstance(defaults, dict)
    assert defaults["in_transit"]["minimum_tls_version"] == "1.3"
    assert defaults["in_transit"]["external_plaintext_allowed"] is False
    assert defaults["at_rest"]["plaintext_persistent_volumes_allowed"] is False
    components = policy["components"]
    assert isinstance(components, dict)
    assert {"api", "postgres", "minio", "opensearch"}.issubset(components)


def test_encryption_policy_rejects_plaintext_external_interfaces() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    assert isinstance(policy, dict)
    components = policy["components"]
    assert isinstance(components, dict)
    api = components["api"]
    assert isinstance(api, dict)
    in_transit = api["in_transit"]
    assert isinstance(in_transit, dict)
    in_transit["external_plaintext_allowed"] = True

    with pytest.raises(PolicyValidationError, match="external_plaintext_allowed"):
        validate_policy(policy)


def test_encryption_policy_rejects_weak_tls() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    assert isinstance(policy, dict)
    components = policy["components"]
    assert isinstance(components, dict)
    postgres = components["postgres"]
    assert isinstance(postgres, dict)
    in_transit = postgres["in_transit"]
    assert isinstance(in_transit, dict)
    in_transit["minimum_tls_version"] = "1.2"

    with pytest.raises(PolicyValidationError, match="minimum_tls_version"):
        validate_policy(policy)


def test_encryption_policy_rejects_plaintext_key_management() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    assert isinstance(policy, dict)
    components = policy["components"]
    assert isinstance(components, dict)
    minio = components["minio"]
    assert isinstance(minio, dict)
    at_rest = minio["at_rest"]
    assert isinstance(at_rest, dict)
    at_rest["key_management"] = "none"

    with pytest.raises(PolicyValidationError, match="key_management"):
        validate_policy(policy)
