#!/usr/bin/env bash
set -euo pipefail
TECHNIQUE_ID=T1053_003
source "$(dirname "$0")/../shared/logging.sh"

SCRIPT_LOG=${SCRIPT_LOG:-$(ensure_log_dir "$TECHNIQUE_ID")}
exec > >(tee -a "$SCRIPT_LOG") 2>&1

log_action "Starting cron persistence demo (T1053.003)."
log_action "DRY_RUN=${DRY_RUN:-true}"

CRON_LINE="*/5 * * * * /usr/bin/printf '%s' 'cron demo' >> /tmp/ttp-shell-cron.log"

if require_dry_run_opt_out; then
  log_action "Installing cron entry: $CRON_LINE"
  (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
  log_action "Cron entry installed. Remove with: crontab -l | grep -v 'ttp-shell-cron' | crontab -"
else
  log_action "Dry-run mode: cron entry not installed."
fi
