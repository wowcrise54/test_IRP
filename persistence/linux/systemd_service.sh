#!/usr/bin/env bash
set -euo pipefail

# Creates and enables a systemd service for a given executable.
# Examples:
#   ./systemd_service.sh --name demo --exec /usr/local/bin/demo --user
#   sudo ./systemd_service.sh --name demo --exec /opt/demo/start.sh --system

usage() {
  cat <<'USAGE'
Usage: systemd_service.sh --name <service_name> --exec <path> [options]

Required:
  --name <service_name>   Unique name for the service unit (no spaces).
  --exec <path>           Absolute or relative path to the executable/script.

Options:
  --user                  Create a per-user unit (default).
  --system                Create a system-wide unit (requires root privileges).
  --workdir <path>        Working directory for the service.
  --description <text>    Description for the unit (default: Custom persistence service).
  --wanted-by <target>    Install target (default: default.target for user, multi-user.target for system).
  -h, --help              Show this help message.

Cleanup:
  systemctl [--user] disable --now <service_name>.service
  rm <unit_file>
  systemctl [--user] daemon-reload
USAGE
}

SERVICE_SCOPE="user"
SERVICE_NAME=""
EXEC_PATH=""
WORKDIR=""
DESCRIPTION="Custom persistence service"
WANTED_BY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      SERVICE_NAME="$2"; shift 2 ;;
    --exec)
      EXEC_PATH="$2"; shift 2 ;;
    --user)
      SERVICE_SCOPE="user"; shift ;;
    --system)
      SERVICE_SCOPE="system"; shift ;;
    --workdir)
      WORKDIR="$2"; shift 2 ;;
    --description)
      DESCRIPTION="$2"; shift 2 ;;
    --wanted-by)
      WANTED_BY="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1 ;;
  esac
done

if [[ -z "$SERVICE_NAME" || -z "$EXEC_PATH" ]]; then
  echo "Error: --name and --exec are required." >&2
  usage
  exit 1
fi

if command -v realpath >/dev/null 2>&1; then
  EXEC_PATH=$(realpath "$EXEC_PATH")
fi

if [[ ! -e "$EXEC_PATH" ]]; then
  echo "Error: executable path '$EXEC_PATH' does not exist." >&2
  exit 1
fi

if [[ "$SERVICE_SCOPE" == "user" ]]; then
  UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  SYSTEMCTL_OPTS=("--user")
  : "${WANTED_BY:=default.target}"
else
  UNIT_DIR="/etc/systemd/system"
  SYSTEMCTL_OPTS=()
  : "${WANTED_BY:=multi-user.target}"
fi

UNIT_FILE="$UNIT_DIR/${SERVICE_NAME}.service"
mkdir -p "$UNIT_DIR"

{
  echo "[Unit]"
  echo "Description=$DESCRIPTION"
  echo "After=network.target"
  echo
  echo "[Service]"
  echo "Type=simple"
  echo "ExecStart=$EXEC_PATH"
  echo "Restart=on-failure"
  [[ -n "$WORKDIR" ]] && echo "WorkingDirectory=$WORKDIR"
  echo
  echo "[Install]"
  echo "WantedBy=$WANTED_BY"
} > "$UNIT_FILE"

echo "Created unit file at $UNIT_FILE"

systemctl "${SYSTEMCTL_OPTS[@]}" daemon-reload
systemctl "${SYSTEMCTL_OPTS[@]}" enable "${SERVICE_NAME}.service"
systemctl "${SYSTEMCTL_OPTS[@]}" start "${SERVICE_NAME}.service"

echo "Service '${SERVICE_NAME}' is enabled and started."
echo "Check status with: systemctl ${SYSTEMCTL_OPTS[*]} status ${SERVICE_NAME}.service"
