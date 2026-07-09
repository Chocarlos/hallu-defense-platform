"""Export public Keycloak JWKS for the production-profile mounted JWKS path."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from urllib import error, request

DEFAULT_DISCOVERY_URL = "http://localhost:8081/realms/hallu-defense/.well-known/openid-configuration"
DEFAULT_OUTPUT_PATH = Path("var/keycloak/jwks.json")
MAX_JSON_BYTES = 256 * 1024


class KeycloakJwksExportError(RuntimeError):
    pass


def export_keycloak_jwks(
    *,
    discovery_url: str,
    output_path: Path,
    http_get_json: Callable[[str], Mapping[str, object]] | None = None,
) -> dict[str, object]:
    getter = http_get_json or _get_json
    discovery = getter(discovery_url)
    jwks_uri = discovery.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise KeycloakJwksExportError("OIDC discovery response must include jwks_uri.")
    jwks = getter(jwks_uri)
    _validate_jwks(jwks)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(jwks, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    keys = jwks["keys"]
    assert isinstance(keys, list)
    return {
        "status": "exported",
        "discovery_url": discovery_url,
        "jwks_uri": jwks_uri,
        "output_path": str(output_path),
        "key_count": len(keys),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovery-url", default=DEFAULT_DISCOVERY_URL)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    args = parser.parse_args(argv)
    try:
        result = export_keycloak_jwks(
            discovery_url=args.discovery_url,
            output_path=args.output,
        )
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def _get_json(url: str) -> Mapping[str, object]:
    try:
        with request.urlopen(url, timeout=10) as response:
            raw = response.read(MAX_JSON_BYTES + 1)
    except error.URLError as exc:
        raise KeycloakJwksExportError("Keycloak JWKS export request failed.") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise KeycloakJwksExportError("Keycloak JWKS export response is too large.")
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, Mapping):
        raise KeycloakJwksExportError("Keycloak JWKS export response must be a JSON object.")
    return parsed


def _validate_jwks(jwks: object) -> None:
    if not isinstance(jwks, Mapping):
        raise KeycloakJwksExportError("JWKS must be a JSON object.")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise KeycloakJwksExportError("JWKS must contain at least one key.")
    for key in keys:
        if not isinstance(key, Mapping):
            raise KeycloakJwksExportError("JWKS keys must be objects.")
        if key.get("kty") != "RSA":
            raise KeycloakJwksExportError("JWKS keys must be RSA keys.")
        if key.get("use") not in {None, "sig"}:
            raise KeycloakJwksExportError("JWKS keys must be signing keys.")
        if (
            not isinstance(key.get("kid"), str)
            or not isinstance(key.get("n"), str)
            or not isinstance(key.get("e"), str)
        ):
            raise KeycloakJwksExportError("JWKS RSA keys must include kid, n, and e.")


if __name__ == "__main__":
    sys.exit(main())
