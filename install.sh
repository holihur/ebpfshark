#!/usr/bin/env bash
# ebpfshark one-click installer / service setup.
set -euo pipefail

SERVICE="ebpfshark"
PREFIX="${PREFIX:-}"
PORT="9999"
BINARY=""
REBUILD=0
AUTO_UPDATE="true"
UPDATE_INTERVAL="10m"
UPDATE_URL=""
NO_SYSTEMD=0
FORCE_ENV=0
UNINSTALL=0
PURGE=0
AUTH_USER="admin"
AUTH_PASS=""
MCP_TOKEN=""

usage() {
  cat <<'USAGE'
Usage: sudo ./install.sh [options]

Options:
  --port PORT             HTTP/Web port (default 9999)
  --binary PATH           Install a prebuilt binary instead of ./bin/ebpfshark
  --rebuild               Force `make web && make go-build` before installing
  --auth-user USER        Login user for a fresh env file (default admin)
  --auth-pass PASS        Login password (default: generate)
  --mcp-token TOKEN       MCP bearer token (default: generate)
  --update-url URL        Auto-update manifest URL
  --update-interval DUR   Check interval (default 10m)
  --no-auto-update        Disable auto-update
  --force-env             Rewrite /etc/ebpfshark/ebpfshark.env
  --no-systemd            Install files only, do not enable the service
  --prefix DIR            Install under DIR (testing; implies --no-systemd)
  --uninstall             Stop and remove the service and binary
  --purge                 With --uninstall, also remove the env file
  -h, --help              Show this help

Auto-update requires a manifest URL. Without one it stays enabled but idle.
USAGE
}

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --rebuild) REBUILD=1; shift ;;
    --auth-user) AUTH_USER="$2"; shift 2 ;;
    --auth-pass) AUTH_PASS="$2"; shift 2 ;;
    --mcp-token) MCP_TOKEN="$2"; shift 2 ;;
    --update-url) UPDATE_URL="$2"; shift 2 ;;
    --update-interval) UPDATE_INTERVAL="$2"; shift 2 ;;
    --no-auto-update) AUTO_UPDATE="false"; shift ;;
    --force-env) FORCE_ENV=1; shift ;;
    --no-systemd) NO_SYSTEMD=1; shift ;;
    --prefix) PREFIX="$2"; NO_SYSTEMD=1; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (use --help)" ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root (sudo ./install.sh)"

ROOT="${PREFIX%/}"
BIN_PATH="${ROOT}/usr/local/bin/ebpfshark"
ENV_DIR="${ROOT}/etc/ebpfshark"
ENV_FILE="${ENV_DIR}/ebpfshark.env"
UNIT_FILE="${ROOT}/etc/systemd/system/${SERVICE}.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

gen_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 32
  else
    head -c 128 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32
  fi
}

if [[ "$UNINSTALL" -eq 1 ]]; then
  if [[ "$NO_SYSTEMD" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop "$SERVICE" 2>/dev/null || true
    systemctl disable "$SERVICE" 2>/dev/null || true
  fi
  rm -f "$UNIT_FILE" "$BIN_PATH"
  if [[ "$NO_SYSTEMD" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
  fi
  if [[ "$PURGE" -eq 1 ]]; then
    rm -rf "$ENV_DIR"
  fi
  info "ebpfshark uninstalled"
  exit 0
fi

if [[ "$REBUILD" -eq 1 ]]; then
  command -v go >/dev/null 2>&1 || die "go is required for --rebuild"
  command -v pnpm >/dev/null 2>&1 || die "pnpm is required for --rebuild"
  info "building ebpfshark"
  (cd "$SCRIPT_DIR" && make web && make go-build)
fi

if [[ -z "$BINARY" ]]; then
  if [[ -x "$SCRIPT_DIR/bin/ebpfshark" ]]; then
    BINARY="$SCRIPT_DIR/bin/ebpfshark"
  else
    command -v go >/dev/null 2>&1 || die "no binary found; build first or pass --binary"
    command -v pnpm >/dev/null 2>&1 || die "pnpm is required to build the web UI"
    info "no prebuilt binary, building"
    (cd "$SCRIPT_DIR" && make web && make go-build)
    BINARY="$SCRIPT_DIR/bin/ebpfshark"
  fi
fi
[[ -x "$BINARY" ]] || die "binary not executable: $BINARY"

info "installing binary to $BIN_PATH"
install -D -m 0755 "$BINARY" "$BIN_PATH"
mkdir -p "$ENV_DIR"
chmod 700 "$ENV_DIR"

if [[ ! -f "$ENV_FILE" || "$FORCE_ENV" -eq 1 ]]; then
  [[ -n "$AUTH_PASS" ]] || AUTH_PASS="$(gen_secret)"
  [[ -n "$MCP_TOKEN" ]] || MCP_TOKEN="$(gen_secret)"
  cat > "$ENV_FILE" <<ENVEOF
EBPFSHARK_ADDR=":${PORT}"
EBPFSHARK_AUTH_USER="${AUTH_USER}"
EBPFSHARK_AUTH_PASS="${AUTH_PASS}"
EBPFSHARK_MCP_TOKEN="${MCP_TOKEN}"
EBPFSHARK_AUTO_UPDATE="${AUTO_UPDATE}"
EBPFSHARK_UPDATE_INTERVAL="${UPDATE_INTERVAL}"
EBPFSHARK_UPDATE_URL="${UPDATE_URL}"
EBPFSHARK_STREAM_BUDGET="64"
ENVEOF
  chmod 600 "$ENV_FILE"
else
  info "keeping existing $ENV_FILE (use --force-env to rewrite)"
fi

get_kv() {
  grep -E "^$1=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//'
}

mkdir -p "$(dirname "$UNIT_FILE")"
cat > "$UNIT_FILE" <<UNITEOF
[Unit]
Description=ebpfshark eBPF packet analyzer
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH}
Restart=always
RestartSec=3
LimitMEMLOCK=infinity
PrivateTmp=true
ProtectHome=true
UMask=0077

[Install]
WantedBy=multi-user.target
UNITEOF

if [[ "$NO_SYSTEMD" -eq 0 ]]; then
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found; use --no-systemd"
  systemctl daemon-reload
  systemctl enable "$SERVICE"
  systemctl restart "$SERVICE"
  info "service started: systemctl status $SERVICE"
else
  info "systemd skipped; run manually:"
  echo "    set -a; . $ENV_FILE; set +a; $BIN_PATH"
fi

echo
echo "ebpfshark installed"
echo "  URL:        http://<host>:$(get_kv EBPFSHARK_ADDR | sed 's/^://')"
echo "  env file:   $ENV_FILE"
echo "  username:   $(get_kv EBPFSHARK_AUTH_USER)"
echo "  password:   $(get_kv EBPFSHARK_AUTH_PASS)"
echo "  MCP token:  $(get_kv EBPFSHARK_MCP_TOKEN)"
echo "  auto-update: $(get_kv EBPFSHARK_AUTO_UPDATE) ($(get_kv EBPFSHARK_UPDATE_INTERVAL))"
if [[ -n "$(get_kv EBPFSHARK_UPDATE_URL)" ]]; then
  echo "  update URL: $(get_kv EBPFSHARK_UPDATE_URL)"
else
  echo "  update URL: (not configured; auto-update stays idle)"
fi
echo
echo "Keep the env file private. To change credentials, edit it and restart $SERVICE."
