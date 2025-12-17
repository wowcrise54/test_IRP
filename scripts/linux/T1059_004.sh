#!/usr/bin/env bash
set -euo pipefail
TECHNIQUE_ID=T1059_004
source "$(dirname "$0")/../shared/logging.sh"

SCRIPT_LOG=${SCRIPT_LOG:-$(ensure_log_dir "$TECHNIQUE_ID")}
exec > >(tee -a "$SCRIPT_LOG") 2>&1

log_action "Starting Linux shell execution demo (T1059.004)."
log_action "DRY_RUN=${DRY_RUN:-true}"

if require_dry_run_opt_out; then
  log_action "Executing sample commands in lab mode."
  whoami
  uname -a
  echo "Sample command execution completed." 
else
  log_action "Dry-run mode: commands not executed."
fi
