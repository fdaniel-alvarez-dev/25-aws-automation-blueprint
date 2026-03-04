# Threat model (lightweight)

Goal: identify likely risks early and make secure defaults cheap.

## Assets
- source code and CI workflows
- infrastructure definitions (IaC)
- operational artifacts (runbooks, dashboards)

## Threats (examples)
- leaked secrets via git history
- over-privileged CI tokens
- misconfigured infrastructure (public exposure)

## Mitigations implemented in this repo
- secret scanning in CI
- `.gitignore` for sensitive/local artifacts
- minimal, runnable examples that do not require real credentials
