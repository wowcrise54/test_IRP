#!/usr/bin/env bash
set -euo pipefail

# Creates an XDG autostart desktop entry for graphical sessions.

usage() {
  cat <<'USAGE'
Usage: xdg_autostart.sh --name <app_name> --exec <command> [options]

Required:
  --name <app_name>     Logical application name (used as filename and display name).
  --exec <command>      Command executed on session start (quote if it contains spaces).

Options:
  --comment <text>      Description/comment for the desktop entry.
  --only-show-in <list> Limit to desktops (comma separated, e.g., GNOME,KDE).
  -h, --help            Show this help message.

Cleanup:
  rm ~/.config/autostart/<app_name>.desktop
USAGE
}

APP_NAME=""
EXEC_CMD=""
COMMENT=""
ONLY_SHOW_IN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      APP_NAME="$2"; shift 2 ;;
    --exec)
      EXEC_CMD="$2"; shift 2 ;;
    --comment)
      COMMENT="$2"; shift 2 ;;
    --only-show-in)
      ONLY_SHOW_IN="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1 ;;
  esac
done

if [[ -z "$APP_NAME" || -z "$EXEC_CMD" ]]; then
  echo "Error: --name and --exec are required." >&2
  usage
  exit 1
fi

AUTOSTART_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"
mkdir -p "$AUTOSTART_DIR"

DESKTOP_FILE="$AUTOSTART_DIR/${APP_NAME}.desktop"

{
  echo "[Desktop Entry]"
  echo "Type=Application"
  echo "Name=$APP_NAME"
  echo "Exec=$EXEC_CMD"
  [[ -n "$COMMENT" ]] && echo "Comment=$COMMENT"
  echo "X-GNOME-Autostart-enabled=true"
  [[ -n "$ONLY_SHOW_IN" ]] && echo "OnlyShowIn=${ONLY_SHOW_IN}"
} > "$DESKTOP_FILE"

echo "Created autostart entry at $DESKTOP_FILE"
echo "Remove it by deleting the file if you no longer need it."
