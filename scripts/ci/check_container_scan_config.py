from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
DOCKERFILES = {
    "api": ROOT / "infra" / "docker" / "api.Dockerfile",
    "console": ROOT / "infra" / "docker" / "console.Dockerfile",
}
IMAGE_REFS = {
    "api": "hallu-defense-api:ci",
    "console": "hallu-defense-console:ci",
}
FORBIDDEN_ACTION_REFS = {"master", "main", "HEAD"}


class ContainerScanConfigError(ValueError):
    pass


def validate_container_scan_config(
    *,
    workflow_text: str,
    dockerfile_texts: Mapping[str, str],
) -> None:
    errors: list[str] = []
    _validate_workflow(workflow_text, errors)
    for name, image_ref in IMAGE_REFS.items():
        dockerfile_text = dockerfile_texts.get(name)
        if dockerfile_text is None:
            errors.append(f"missing Dockerfile text for {name}")
            continue
        _validate_dockerfile(name, image_ref, dockerfile_text, workflow_text, errors)

    if errors:
        raise ContainerScanConfigError("\n".join(errors))


def _validate_workflow(workflow_text: str, errors: list[str]) -> None:
    if "continue-on-error: true" in workflow_text:
        errors.append("container scanning must not use continue-on-error")

    action_refs = re.findall(r"aquasecurity/trivy-action@([A-Za-z0-9_.-]+)", workflow_text)
    if len(action_refs) < len(IMAGE_REFS):
        errors.append("security workflow must scan each required image with aquasecurity/trivy-action")
    for action_ref in action_refs:
        if action_ref in FORBIDDEN_ACTION_REFS:
            errors.append("trivy action must be pinned to a released version, not a branch")

    required_snippets = {
        'exit-code: "1"',
        "ignore-unfixed: true",
        "vuln-type: os,library",
        "severity: CRITICAL,HIGH",
    }
    for snippet in required_snippets:
        if workflow_text.count(snippet) < len(IMAGE_REFS):
            errors.append(f"security workflow must configure `{snippet}` for every image scan")


def _validate_dockerfile(
    name: str,
    image_ref: str,
    dockerfile_text: str,
    workflow_text: str,
    errors: list[str],
) -> None:
    dockerfile_path = f"infra/docker/{name}.Dockerfile"
    if f"docker build -f {dockerfile_path} -t {image_ref} ." not in workflow_text:
        errors.append(f"security workflow must build {image_ref} from {dockerfile_path}")
    if f"image-ref: {image_ref}" not in workflow_text:
        errors.append(f"security workflow must scan image-ref {image_ref}")

    from_lines = [line for line in dockerfile_text.splitlines() if line.strip().startswith("FROM ")]
    if not from_lines:
        errors.append(f"{dockerfile_path} must declare a base image")
    for line in from_lines:
        if ":latest" in line:
            errors.append(f"{dockerfile_path} must not use latest base images")

    if re.search(r"(?m)^USER\s+(root|0)\s*$", dockerfile_text):
        errors.append(f"{dockerfile_path} must not end with root user")
    elif not re.search(r"(?m)^USER\s+\S+", dockerfile_text):
        errors.append(f"{dockerfile_path} must set a non-root USER")

    if re.search(r"(?im)^ADD\s+https?://", dockerfile_text):
        errors.append(f"{dockerfile_path} must not ADD remote URLs")

    if name == "api" and "pip install --no-cache-dir" not in dockerfile_text:
        errors.append(f"{dockerfile_path} must install Python dependencies without pip cache")
    if name == "console" and "npm ci" not in dockerfile_text:
        errors.append(f"{dockerfile_path} must use npm ci for reproducible installs")


def load_current_config() -> tuple[str, dict[str, str]]:
    workflow_text = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    dockerfile_texts = {
        name: path.read_text(encoding="utf-8")
        for name, path in DOCKERFILES.items()
    }
    return workflow_text, dockerfile_texts


def main() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    validate_container_scan_config(
        workflow_text=workflow_text,
        dockerfile_texts=dockerfile_texts,
    )
    print(f"Validated container scan config for {len(IMAGE_REFS)} image(s).")


if __name__ == "__main__":
    main()
