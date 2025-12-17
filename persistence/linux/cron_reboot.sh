#!/usr/bin/env bash
set -euo pipefail

# Adds a cron entry for the current user (default: @reboot) without duplicating existing entries.

usage() {
  cat <<'USAGE'
Usage: cron_reboot.sh --command "<command>" [--schedule <cron_spec>]

Required:
  --command "<command>"   Full command to execute.

Options:
  --schedule <cron_spec>   Cron timing expression (default: @reboot).
  -h, --help               Show this message.

Cleanup:
  crontab -l | grep -v "<command>" | crontab -
USAGE
}

COMMAND=""
SCHEDULE="@reboot"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --command)
      COMMAND="$2"; shift 2 ;;
    --schedule)
      SCHEDULE="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1 ;;
  esac
done

if [[ -z "$COMMAND" ]]; then
  echo "Error: --command is required." >&2
  usage
  exit 1
fi

TMP_CRON=$(mktemp)
crontab -l > "$TMP_CRON" 2>/dev/null || true

if grep -Fq "$SCHEDULE $COMMAND" "$TMP_CRON"; then
  echo "Cron entry already present. No changes made."
  rm -f "$TMP_CRON"
  exit 0
fi

{
  cat "$TMP_CRON"
  echo "$SCHEDULE $COMMAND"
} | sed '/^\s*$/d' | crontab -

rm -f "$TMP_CRON"

echo "Cron entry added for schedule '$SCHEDULE'."
echo "Verify with: crontab -l"
