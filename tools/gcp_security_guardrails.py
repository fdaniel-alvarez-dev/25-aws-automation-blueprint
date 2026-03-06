#!/usr/bin/env python3
import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Finding:
    severity: str  # ERROR | WARN | INFO
    rule_id: str
    message: str
    path: str | None = None


def repo_read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def add(findings: list[Finding], severity: str, rule_id: str, message: str, path: Path | None = None) -> None:
    findings.append(
        Finding(
            severity=severity,
            rule_id=rule_id,
            message=message,
            path=str(path.relative_to(REPO_ROOT)) if path else None,
        )
    )


def check_required_docs(findings: list[Finding]) -> None:
    required = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "docs" / "ops" / "slo.md",
        REPO_ROOT / "docs" / "security" / "threat-model.md",
        REPO_ROOT / "docs" / "runbooks" / "backup-and-restore.md",
    ]
    for p in required:
        if not p.exists():
            add(findings, "ERROR", "docs.required", "Required documentation file is missing.", p)


def check_readme_sections(findings: list[Finding]) -> None:
    readme = REPO_ROOT / "README.md"
    if not readme.exists():
        return
    text = repo_read(readme)
    if "GCP" not in text and "Google Cloud" not in text:
        add(findings, "WARN", "docs.gcp", "README should describe how the patterns map to GCP (e.g., GKE, IAM, KMS).", readme)
    if "TEST_MODE" not in text:
        add(findings, "WARN", "docs.test_mode", "README should document TEST_MODE=demo|production.", readme)
    if "Cost" in text:
        add(findings, "INFO", "docs.cost_note", "If cost is mentioned, ensure it is backed by real guardrails or tooling.", readme)


def check_gitignore_job_files(findings: list[Finding]) -> None:
    ignore = REPO_ROOT / ".gitignore"
    if not ignore.exists():
        add(findings, "WARN", "gitignore.missing", ".gitignore is missing; add rules for artifacts and private inputs.")
        return
    text = repo_read(ignore)
    if ".[0-9][0-9]_*.txt" not in text:
        add(findings, "WARN", "gitignore.job_descriptions", "Add a .gitignore rule to prevent committing job description .txt files.", ignore)


def check_docker_compose_image_pinning(findings: list[Finding]) -> None:
    compose = REPO_ROOT / "docker-compose.yml"
    if not compose.exists():
        return
    text = repo_read(compose)
    images = re.findall(r"(?m)^\\s*image:\\s*([^\\s#]+)\\s*$", text)
    for image in images:
        if ":" not in image:
            add(findings, "WARN", "compose.image_tag", f"Image has no tag pinned: {image}", compose)
            continue
        tag = image.split(":", 1)[1]
        if tag == "latest":
            add(findings, "ERROR", "compose.image_latest", f"Image uses a floating tag: {image}", compose)


def check_terraform_examples(findings: list[Finding]) -> None:
    tf_files = sorted((REPO_ROOT / "infra").rglob("*.tf"))
    if not tf_files:
        add(findings, "INFO", "tf.none", "No Terraform files found under infra/; skipping Terraform guardrails.")
        return

    combined = "\n".join(repo_read(p) for p in tf_files)
    if "required_version" not in combined:
        add(findings, "WARN", "tf.required_version", "Terraform should define required_version to avoid drift.")
    if "required_providers" not in combined:
        add(findings, "WARN", "tf.required_providers", "Terraform should define required_providers with pinned versions.")
    if not re.search(r'variable\\s+\"owner\"\\s*\\{', combined):
        add(findings, "WARN", "tf.owner_variable", "Terraform examples should include an `owner` (or equivalent) variable for attribution.")

    if re.search(r'\\bprovider\\s+\"google\"\\b', combined) and not re.search(r'version\\s*=\\s*\"~>', combined):
        add(findings, "WARN", "tf.google_provider_pin", "If using the Google provider, pin its version under required_providers.")


def check_k8s_manifests_present(findings: list[Finding]) -> None:
    manifests = REPO_ROOT / "k8s" / "manifests"
    if not manifests.exists():
        add(findings, "WARN", "k8s.missing", "Consider adding minimal Kubernetes manifests demonstrating secure defaults (NetworkPolicy, PDB, quotas).")
        return
    if not list(manifests.glob("*.json")):
        add(findings, "WARN", "k8s.empty", "k8s/manifests exists but has no JSON manifests.", manifests)


def summarize(findings: list[Finding]) -> dict:
    errors = sum(1 for f in findings if f.severity == "ERROR")
    warns = sum(1 for f in findings if f.severity == "WARN")
    infos = sum(1 for f in findings if f.severity == "INFO")
    return {"errors": errors, "warnings": warns, "info": infos}


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline, deterministic GCP + security guardrails for this repo.")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--out", default="", help="Write output to a file (optional).")
    args = parser.parse_args()

    findings: list[Finding] = []
    check_required_docs(findings)
    check_readme_sections(findings)
    check_gitignore_job_files(findings)
    check_docker_compose_image_pinning(findings)
    check_terraform_examples(findings)
    check_k8s_manifests_present(findings)

    report = {"summary": summarize(findings), "findings": [asdict(f) for f in findings]}

    if args.format == "json":
        output = json.dumps(report, indent=2, sort_keys=True)
    else:
        lines = []
        for f in findings:
            where = f" ({f.path})" if f.path else ""
            lines.append(f"{f.severity} {f.rule_id}{where}: {f.message}")
        lines.append("")
        lines.append(f"Summary: {report['summary']}")
        output = "\n".join(lines)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    return 1 if report["summary"]["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

