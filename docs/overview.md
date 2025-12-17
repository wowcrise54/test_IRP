# MITRE ATT&CK TTP Lab Framework

This repository provides a controlled lab framework for emulating MITRE ATT&CK techniques with Bash, PowerShell, and Ansible orchestrations. It is intended for defenders, red teams, and detection engineers who need repeatable patterns, safety guardrails, and clear cleanup steps.

## Goals
- Offer technique-aligned scripts with consistent logging, parameters, and cleanup.
- Support cross-platform execution via Ansible playbooks.
- Keep safety first: dry-run defaults, explicit target definition, and environment gating.

## Guardrails
- **Lab only.** Scripts are designed for non-production environments. Avoid running on unmanaged hosts.
- **Dry run by default.** Scripts should honor a `DRY_RUN=true` flag and emit the actions they _would_ take.
- **Target scoping.** Use inventories and variables to select hosts; avoid hardcoded addresses.
- **Cleanup-first mindset.** Each technique includes rollback guidance.

## Components
- `ansible/`: Playbooks and roles to orchestrate technique runs and collection.
- `scripts/`: Bash, PowerShell, and shared helpers tagged by technique IDs.
- `configs/`: Safety settings and artifact collection paths.
- `docs/`: Catalog of techniques and usage guidance.
- `tests/`: Linting and smoke checks to ensure scripts remain safe to run.

## Usage
1. Review `docs/ttp-catalog.md` to pick techniques and confirm prerequisites.
2. Populate `ansible/inventory/hosts` with lab targets and credentials.
3. Run `make run-linux` or `make run-windows` to execute the curated bundles in dry-run mode.
4. Review artifacts and logs, then switch off `DRY_RUN` when ready in a safe environment.
5. Use `make cleanup` to revert changes.

## Next steps
- Expand the catalog with more techniques.
- Add automated checks to enforce dry-run defaults and required variables.
- Flesh out artifact collection and detection engineering examples.
