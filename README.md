# 25-aws-reliability-security-gcp

A portfolio-grade, runnable reliability + security toolkit that demonstrates **database operations patterns** and how they map to cloud environments like **Google Cloud** (GKE, IAM, KMS).

This repository is intentionally generic (no employer branding). It focuses on working automation, not claims.

## The 3 core problems this repo solves
1) **Repeatable DBaaS-style operations:** runbooks + drills for backup/restore and replica health.
2) **Security-minded defaults:** guardrails and lightweight policy checks that are deterministic and reviewable.
3) **Production-safe validation:** explicit test modes that separate offline checks from integration tests.

## Quickstart (local lab)
Prereqs: Docker + Docker Compose.

```bash
make demo
```

You get:
- Postgres primary + replica
- PgBouncer for connection pooling
- scripts to seed data, verify replication, and run backup/restore drills

## Tests (two explicit modes)

This repo supports exactly two test modes via `TEST_MODE`:

- `TEST_MODE=demo` (default): **offline-only**, deterministic checks (no Docker, no cloud, no credentials)
- `TEST_MODE=production`: **real integrations**, guarded by an explicit opt-in

Run demo mode:

```bash
make test-demo
```

Run production mode (local integrations):

```bash
make test-production
```

Optional production checks:
- Set `K8S_VALIDATE=1` to run `kubectl apply --dry-run=client` against `k8s/manifests/`
- Set `GCP_VALIDATE=1` and `GCP_PROJECT_ID=...` to enable a `gcloud projects describe` check (requires `gcloud` + auth)

## Guardrails and policy checks

Offline, deterministic checks:
- `tools/gcp_security_guardrails.py` scans repo conventions (docs, Terraform example hygiene, image pinning).
- `tools/k8s_policy_check.py` validates the included Kubernetes JSON manifests for secure-default primitives.

Generate artifacts:

```bash
python3 tools/gcp_security_guardrails.py --format json --out artifacts/gcp_security_guardrails.json
python3 tools/k8s_policy_check.py --out artifacts/k8s_policy_findings.json
```

## Sponsorship and contact

Sponsored by:
CloudForgeLabs  
https://cloudforgelabs.ainextstudios.com/  
support@ainextstudios.com

Built by:
Freddy D. Alvarez  
https://www.linkedin.com/in/freddy-daniel-alvarez/

For job opportunities, contact:
it.freddy.alvarez@gmail.com

## License

Personal, educational, and non-commercial use is free. Commercial use requires paid permission.
See `LICENSE` and `COMMERCIAL_LICENSE.md`.
