# Infra

This folder contains small, production-minded Terraform examples used to demonstrate:
- formatting and validation gates in CI
- conventions (tags/ownership)
- reproducible workflows

Quickstart:
```bash
cd infra/examples/dev
terraform init -backend=false
terraform validate
terraform apply -auto-approve
```
