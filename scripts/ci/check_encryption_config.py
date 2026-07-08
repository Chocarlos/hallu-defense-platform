from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "infra" / "security" / "encryption-policy.json"

REQUIRED_COMPONENTS = {
    "api",
    "console",
    "grafana",
    "minio",
    "opensearch",
    "otel-collector",
    "postgres",
    "prometheus",
    "redis",
}
ALLOWED_PROFILES = {"active", "future-required"}
ALLOWED_LOCAL_EXEMPTIONS = {
    "container_private_network_plaintext",
    "localhost_http_only",
    "local_unencrypted_volume_allowed",
}
MINIMUM_TLS_VERSION = "1.3"
FORBIDDEN_KEY_MANAGEMENT = {"", "none", "plaintext", "local-file", "local_file", "env"}


class PolicyValidationError(ValueError):
    pass


def load_policy(path: Path = POLICY_PATH) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise PolicyValidationError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return payload


def validate_policy(policy: Mapping[str, object]) -> None:
    errors: list[str] = []

    if policy.get("schema_version") != "encryption-policy.v1":
        errors.append("schema_version must be encryption-policy.v1")

    defaults = _mapping(policy.get("defaults"), "defaults", errors)
    default_in_transit = _mapping(defaults.get("in_transit"), "defaults.in_transit", errors)
    default_at_rest = _mapping(defaults.get("at_rest"), "defaults.at_rest", errors)
    _validate_in_transit(default_in_transit, "defaults.in_transit", errors)
    _validate_at_rest(default_at_rest, "defaults.at_rest", errors)
    if default_in_transit.get("minimum_tls_version") != MINIMUM_TLS_VERSION:
        errors.append("defaults.in_transit.minimum_tls_version must be 1.3")
    if default_at_rest.get("plaintext_persistent_volumes_allowed") is not False:
        errors.append("defaults.at_rest.plaintext_persistent_volumes_allowed must be false")

    components = _mapping(policy.get("components"), "components", errors)
    missing_components = REQUIRED_COMPONENTS - set(components)
    if missing_components:
        errors.append(f"components missing required entries: {', '.join(sorted(missing_components))}")

    for component_name in sorted(components):
        component = _mapping(components.get(component_name), f"components.{component_name}", errors)
        _validate_component(component_name, component, errors)

    if errors:
        raise PolicyValidationError("\n".join(errors))


def _validate_component(
    component_name: str,
    component: Mapping[str, object],
    errors: list[str],
) -> None:
    profile = component.get("profile")
    if profile not in ALLOWED_PROFILES:
        errors.append(f"components.{component_name}.profile must be one of {sorted(ALLOWED_PROFILES)}")

    data_classes = component.get("data_classes")
    if not isinstance(data_classes, list) or not data_classes:
        errors.append(f"components.{component_name}.data_classes must be a non-empty list")
    elif not all(isinstance(item, str) and item.strip() for item in data_classes):
        errors.append(f"components.{component_name}.data_classes must contain non-empty strings")

    in_transit = _mapping(
        component.get("in_transit"),
        f"components.{component_name}.in_transit",
        errors,
    )
    at_rest = _mapping(component.get("at_rest"), f"components.{component_name}.at_rest", errors)
    _validate_in_transit(in_transit, f"components.{component_name}.in_transit", errors)
    _validate_at_rest(at_rest, f"components.{component_name}.at_rest", errors)

    exemptions = component.get("local_dev_exemptions", [])
    if not isinstance(exemptions, list):
        errors.append(f"components.{component_name}.local_dev_exemptions must be a list")
    else:
        invalid = sorted(str(item) for item in exemptions if item not in ALLOWED_LOCAL_EXEMPTIONS)
        if invalid:
            errors.append(
                f"components.{component_name}.local_dev_exemptions has unsupported values: "
                f"{', '.join(invalid)}"
            )


def _validate_in_transit(
    section: Mapping[str, object],
    path: str,
    errors: list[str],
) -> None:
    if section.get("required") is not True:
        errors.append(f"{path}.required must be true")
    if section.get("external_plaintext_allowed") is not False:
        errors.append(f"{path}.external_plaintext_allowed must be false")

    tls_version = section.get("minimum_tls_version")
    if not isinstance(tls_version, str) or _tls_tuple(tls_version) < _tls_tuple(MINIMUM_TLS_VERSION):
        errors.append(f"{path}.minimum_tls_version must be at least {MINIMUM_TLS_VERSION}")

    mode = section.get("mode")
    if mode is not None and not _nonempty_string(mode):
        errors.append(f"{path}.mode must be a non-empty string when present")


def _validate_at_rest(
    section: Mapping[str, object],
    path: str,
    errors: list[str],
) -> None:
    if section.get("required") is not True:
        errors.append(f"{path}.required must be true")

    algorithm = section.get("algorithm")
    if not _nonempty_string(algorithm) or "AES-256" not in str(algorithm):
        errors.append(f"{path}.algorithm must specify AES-256 encryption")

    key_management = section.get("key_management")
    if not _nonempty_string(key_management):
        errors.append(f"{path}.key_management must be a non-empty string")
    elif str(key_management).strip().lower() in FORBIDDEN_KEY_MANAGEMENT:
        errors.append(f"{path}.key_management must not be plaintext/local-only")

    scope = section.get("scope")
    if scope is not None and not _nonempty_string(scope):
        errors.append(f"{path}.scope must be a non-empty string when present")


def _mapping(value: object, path: str, errors: list[str]) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{path} must be an object")
    return {}


def _tls_tuple(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return (0,)


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _component_count(policy: Mapping[str, object]) -> int:
    components = policy.get("components")
    if isinstance(components, Mapping):
        return len(components)
    if isinstance(components, Sequence) and not isinstance(components, str):
        return len(components)
    return 0


def main() -> None:
    policy = load_policy()
    validate_policy(policy)
    print(f"Validated encryption policy with {_component_count(policy)} component(s).")


if __name__ == "__main__":
    main()
