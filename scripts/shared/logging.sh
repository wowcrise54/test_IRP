#!/usr/bin/env bash
set -euo pipefail

default_artifacts_root() {
  printf '%s' "${ARTIFACT_ROOT:-$(pwd)/artifacts}"
}

ensure_log_dir() {
  local technique="$1"
  local root
  root="$(default_artifacts_root)"
  mkdir -p "$root/logs/$technique"
  printf '%s/logs/%s/%s.log' "$root" "$technique" "$(date +%s)"
}

log_action() {
  local message="$1"
  echo "[${TECHNIQUE_ID:-unknown}] $(date --iso-8601=seconds) $message"
}

require_dry_run_opt_out() {
  if [[ "${DRY_RUN:-true}" != "false" ]]; then
    log_action "DRY_RUN enabled; performing no-op demonstration. Override with DRY_RUN=false in lab only."
    return 1
  fi
  return 0
}
