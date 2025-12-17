# MITRE ATT&CK TTP Lab Framework

Starter scaffold for emulating MITRE ATT&CK techniques across Linux and Windows using Bash, PowerShell, and Ansible. The repository prioritizes safety (dry-run defaults, explicit inventories) and repeatability.

## Layout
- `docs/` — overview and technique catalog.
- `ansible/` — inventories, group vars, roles, and playbooks to orchestrate techniques.
- `scripts/` — technique-aligned scripts for Linux and Windows, plus shared helpers.
- `configs/` — safety and artifact configuration.
- `tests/` — smoke/lint hooks.
- `.github/workflows/` — CI for linting and Ansible syntax validation.

## Quickstart
1. Review `docs/overview.md` and `docs/ttp-catalog.md`.
2. Update `ansible/inventory/hosts` with your lab hosts.
3. Run a dry-run bundle:
   - Linux: `make run-linux`
   - Windows: `make run-windows`
4. Collect logs in `artifacts/` and adjust detection content accordingly.
5. Run `make cleanup` to remove artifacts and perform manual rollback as noted in each script.

## Safety notes
- Designed for **lab use only**; avoid production targets.
- `DRY_RUN` defaults to `true` in scripts and Ansible vars.
- Scripts log actions and expected cleanup steps. Disable `DRY_RUN` only in isolated environments.
