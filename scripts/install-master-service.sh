#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/install-master-service.sh --database-url 'postgres://user:pass@host:5432/opengfw?sslmode=disable' [options]

Options:
  --database-url URL   PostgreSQL DSN, required
  --binary PATH        prebuilt binary path, default: ./dist/opengfw-master
  --listen ADDR        master listen address, default: :9527
  --service-name NAME  systemd service name, default: opengfw-master
  --user NAME          service user, default: opengfw
  --group NAME         service group, default: opengfw
  --state-dir PATH     working dir, default: /var/lib/opengfw-master
  --help               show this help
EOF
}

escape_env_value() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//\$/\\$}
  value=${value//\`/\\\`}
  printf '"%s"' "$value"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
  fi
}

DATABASE_URL=""
BINARY_PATH="$ROOT_DIR/dist/opengfw-master"
LISTEN_ADDR=":9527"
SERVICE_NAME="opengfw-master"
SERVICE_USER="opengfw"
SERVICE_GROUP="opengfw"
STATE_DIR="/var/lib/opengfw-master"
INSTALL_DIR="/usr/local/bin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database-url)
      DATABASE_URL="${2:-}"
      shift 2
      ;;
    --binary)
      BINARY_PATH="${2:-}"
      shift 2
      ;;
    --listen)
      LISTEN_ADDR="${2:-}"
      shift 2
      ;;
    --service-name)
      SERVICE_NAME="${2:-}"
      shift 2
      ;;
    --user)
      SERVICE_USER="${2:-}"
      shift 2
      ;;
    --group)
      SERVICE_GROUP="${2:-}"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

require_root

if [[ -z "$DATABASE_URL" ]]; then
  echo "--database-url is required" >&2
  usage
  exit 1
fi

if [[ ! -f "$BINARY_PATH" ]]; then
  echo "binary not found: $BINARY_PATH" >&2
  echo "build it first with ./scripts/build-master.sh" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required" >&2
  exit 1
fi

NOLOGIN_BIN="$(command -v nologin || true)"
if [[ -z "$NOLOGIN_BIN" ]]; then
  NOLOGIN_BIN="/usr/sbin/nologin"
fi

if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
  groupadd --system "$SERVICE_GROUP"
fi

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd \
    --system \
    --gid "$SERVICE_GROUP" \
    --home-dir "$STATE_DIR" \
    --create-home \
    --shell "$NOLOGIN_BIN" \
    "$SERVICE_USER"
fi

ENV_DIR="/etc/opengfw"
ENV_FILE="$ENV_DIR/${SERVICE_NAME}.env"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALLED_BINARY="$INSTALL_DIR/opengfw-master"

install -d -m 0755 "$ENV_DIR" "$STATE_DIR"
install -m 0755 "$BINARY_PATH" "$INSTALLED_BINARY"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$STATE_DIR"

{
  printf 'OPENGFW_DATABASE_URL=%s\n' "$(escape_env_value "$DATABASE_URL")"
  printf 'OPENGFW_MASTER_LISTEN=%s\n' "$(escape_env_value "$LISTEN_ADDR")"
} >"$ENV_FILE"
chmod 0600 "$ENV_FILE"

cat >"$UNIT_FILE" <<EOF
[Unit]
Description=OpenGFW Master
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$STATE_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALLED_BINARY -listen \${OPENGFW_MASTER_LISTEN} -database-url \${OPENGFW_DATABASE_URL}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

echo
echo "installed:"
echo "  binary : $INSTALLED_BINARY"
echo "  env    : $ENV_FILE"
echo "  unit   : $UNIT_FILE"
echo
systemctl --no-pager --full status "$SERVICE_NAME" || true
