#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = REPO_ROOT / "artifacts"


def run(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd or REPO_ROOT),
        env=os.environ.copy(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def fail(message: str, *, output: str | None = None, code: int = 1) -> None:
    print(f"FAIL: {message}")
    if output:
        print(output.rstrip())
    raise SystemExit(code)


def require_file(path: Path, description: str) -> None:
    if not path.exists():
        fail(f"Missing {description}: {path}")


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON: {path}", output=str(exc))
    return {}


def demo_mode() -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    gcp_report = ARTIFACTS_DIR / "gcp_security_guardrails.json"
    guardrails = run([sys.executable, "tools/gcp_security_guardrails.py", "--format", "json", "--out", str(gcp_report)])
    if guardrails.returncode != 0:
        fail("GCP security guardrails failed (demo mode must be offline and deterministic).", output=guardrails.stdout)

    report = load_json(gcp_report)
    if report.get("summary", {}).get("errors", 0) != 0:
        fail("Guardrails reported errors.", output=json.dumps(report.get("findings", []), indent=2))

    k8s_report = ARTIFACTS_DIR / "k8s_policy_findings.json"
    k8s_check = run([sys.executable, "tools/k8s_policy_check.py", "--out", str(k8s_report)])
    if k8s_check.returncode != 0:
        fail("Kubernetes policy checks failed.", output=k8s_check.stdout)

    require_file(REPO_ROOT / "NOTICE.md", "NOTICE.md")
    require_file(REPO_ROOT / "COMMERCIAL_LICENSE.md", "COMMERCIAL_LICENSE.md")
    require_file(REPO_ROOT / "GOVERNANCE.md", "GOVERNANCE.md")

    license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8", errors="replace")
    if "it.freddy.alvarez@gmail.com" not in license_text:
        fail("LICENSE must include the commercial licensing contact email.")

    print("OK: demo-mode tests passed (offline).")


def production_mode() -> None:
    if os.environ.get("PRODUCTION_TESTS_CONFIRM") != "1":
        fail(
            "Production-mode tests require an explicit opt-in.",
            output=(
                "Set `PRODUCTION_TESTS_CONFIRM=1` and rerun:\n"
                "  TEST_MODE=production PRODUCTION_TESTS_CONFIRM=1 python3 tests/run_tests.py\n"
            ),
            code=2,
        )

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    ran_external_integration = False
    docker_usable = False
    if shutil.which("docker") is not None:
        info = run(["docker", "info"])
        if info.returncode == 0:
            docker_usable = True
        else:
            print("SKIP: Docker is installed but not usable (daemon/socket not accessible).")
            print(info.stdout.rstrip())

    try:
        if docker_usable:
            ran_external_integration = True

            up = run(["docker", "compose", "up", "-d", "--build"])
            if up.returncode != 0:
                fail(
                    "docker compose up failed.",
                    output=(
                        "If this is a permissions issue, ensure your user can access the Docker daemon.\n\n"
                        + up.stdout
                    ),
                    code=2,
                )

            seed = run(["bash", "scripts/seed_demo_data.sh"])
            if seed.returncode != 0:
                fail("Seeding demo data failed.", output=seed.stdout)

            check = run(["bash", "scripts/check_replication.sh"])
            if check.returncode != 0:
                fail("Replication check failed.", output=check.stdout)

            backup = run(["bash", "scripts/backup.sh"])
            if backup.returncode != 0:
                fail("Backup script failed.", output=backup.stdout)

            backups = sorted((REPO_ROOT / "artifacts" / "backups").glob("*.sql"))
            if not backups:
                fail("No backup files created under artifacts/backups/.")
            latest_backup = backups[-1]

            verify = run(["bash", "scripts/backup_verify.sh", str(latest_backup)])
            if verify.returncode != 0:
                fail("Backup verification failed.", output=verify.stdout)

            restore = run(["bash", "scripts/restore.sh"])
            if restore.returncode != 0:
                fail("Restore drill failed.", output=restore.stdout)
        else:
            print("SKIP: Docker integration drills not executed.")

        if os.environ.get("K8S_VALIDATE") == "1":
            if shutil.which("kubectl") is None:
                fail(
                    "K8S_VALIDATE=1 requires kubectl.",
                    output="Install `kubectl` and rerun production mode, or unset K8S_VALIDATE.",
                    code=2,
                )
            dry = run(["kubectl", "apply", "--dry-run=client", "-f", "k8s/manifests"])
            if dry.returncode != 0:
                fail("kubectl dry-run failed for k8s manifests.", output=dry.stdout)

        if os.environ.get("GCP_VALIDATE") == "1":
            if not os.environ.get("GCP_PROJECT_ID"):
                fail(
                    "GCP_VALIDATE=1 requires GCP_PROJECT_ID.",
                    output="Set `GCP_PROJECT_ID` and rerun production mode.",
                    code=2,
                )
            if shutil.which("gcloud") is None:
                fail(
                    "GCP_VALIDATE=1 requires gcloud.",
                    output="Install the Google Cloud CLI (`gcloud`) and rerun production mode.",
                    code=2,
                )

            ran_external_integration = True
            describe = run(["gcloud", "projects", "describe", os.environ["GCP_PROJECT_ID"], "--format=json"])
            if describe.returncode != 0:
                fail(
                    "gcloud integration check failed.",
                    output=(
                        "Ensure you are authenticated (`gcloud auth login`) and have access to the project.\n\n"
                        + describe.stdout
                    ),
                )

        if not ran_external_integration:
            fail(
                "No external integration checks were executed in production mode.",
                output=(
                    "Enable at least one real integration:\n"
                    "- Install Docker (runs the local Postgres lab drills automatically), or\n"
                    "- Set `GCP_VALIDATE=1` and `GCP_PROJECT_ID=...` (runs a gcloud API check).\n\n"
                    "Then rerun:\n"
                    "  TEST_MODE=production PRODUCTION_TESTS_CONFIRM=1 python3 tests/run_tests.py\n"
                ),
                code=2,
            )

        print("OK: production-mode tests passed (real local integrations).")
    finally:
        if docker_usable:
            down = run(["docker", "compose", "down", "-v"])
            if down.returncode != 0:
                print("WARN: docker compose down failed (manual cleanup may be required).")
                print(down.stdout.rstrip())


def main() -> None:
    mode = os.environ.get("TEST_MODE", "demo").strip().lower()
    if mode not in {"demo", "production"}:
        fail("Invalid TEST_MODE. Expected 'demo' or 'production'.", code=2)

    if mode == "demo":
        demo_mode()
        return

    production_mode()


if __name__ == "__main__":
    main()
