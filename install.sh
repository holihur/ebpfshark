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
MITM_SYSTEM=1
MITM_ADDR="127.0.0.1:18080"
MITM_ADDR_SET=0
MITM_CA_DIR="/etc/ebpfshark/mitm"
UPDATE_URL=""
REPO="holihur/ebpfshark"
VARIANT="full"
RELEASE_VERSION="latest"
ARCH=""
DOWNLOAD_TMP=""
INSTALLED_FROM_RELEASE=0
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
  --repo OWNER/REPO       GitHub repository for release downloads (default: holihur/ebpfshark)
  --variant core|full     Release/build variant (default: full)
  --release-version VER   Release tag or "latest" (default: latest)
  --update-url URL        Auto-update manifest URL (default: GitHub release manifest)
  --update-interval DUR   Check interval (default 10m)
  --no-auto-update        Disable auto-update
  --mitm-addr ADDR        Local MITM proxy address (default 127.0.0.1:18080)
  --no-mitm-system        Do not install the MITM CA or system proxy profile
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
    --repo) REPO="$2"; shift 2 ;;
    --variant) VARIANT="$2"; shift 2 ;;
    --release-version) RELEASE_VERSION="$2"; shift 2 ;;
    --update-url) UPDATE_URL="$2"; shift 2 ;;
    --update-interval) UPDATE_INTERVAL="$2"; shift 2 ;;
    --no-auto-update) AUTO_UPDATE="false"; shift ;;
    --mitm-addr) MITM_ADDR="$2"; MITM_ADDR_SET=1; shift 2 ;;
    --no-mitm-system) MITM_SYSTEM=0; shift ;;
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
[[ "$VARIANT" == "core" || "$VARIANT" == "full" ]] || die "--variant must be core or full"
if [[ "$MITM_ADDR_SET" -eq 0 && "$MITM_ADDR" == "127.0.0.1:18080" ]] && command -v ss >/dev/null 2>&1; then
  port=18080
  while ss -ltn 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; do
    port=$((port + 1))
    [[ "$port" -le 18099 ]] || die "no free loopback port for MITM proxy"
  done
  MITM_ADDR="127.0.0.1:${port}"
fi

ROOT="${PREFIX%/}"
BIN_PATH="${ROOT}/usr/local/bin/ebpfshark"
ENV_DIR="${ROOT}/etc/ebpfshark"
ENV_FILE="${ENV_DIR}/ebpfshark.env"
UNIT_FILE="${ROOT}/etc/systemd/system/${SERVICE}.service"
SCRIPT_SOURCE="${BASH_SOURCE[0]:-}"
if [[ -n "$SCRIPT_SOURCE" && "$SCRIPT_SOURCE" != "/dev/stdin" && -f "$SCRIPT_SOURCE" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
else
  SCRIPT_DIR=""
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "unsupported CPU architecture: $ARCH (release installs support amd64/arm64)" ;;
esac

fetch_stdout() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$1"
  else
    return 1
  fi
}

fetch_to() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    return 1
  fi
}

download_release() {
  local base asset manifest_tmp archive_tmp version url sha actual
  base="https://github.com/${REPO}/releases"
  if [[ "$RELEASE_VERSION" == "latest" ]]; then
    base="${base}/latest/download"
  else
    base="${base}/download/${RELEASE_VERSION}"
  fi
  asset="ebpfshark-${VARIANT}-linux-${ARCH}"
  manifest_tmp="$(mktemp)"
  archive_tmp="$(mktemp)"
  if ! fetch_to "${base}/manifest-${VARIANT}-linux-${ARCH}.json" "$manifest_tmp"; then
    rm -f "$manifest_tmp" "$archive_tmp"
    return 1
  fi
  version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest_tmp" | head -n1)"
  url="$(sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest_tmp" | head -n1)"
  sha="$(sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest_tmp" | head -n1)"
  if [[ -z "$version" || -z "$url" || -z "$sha" ]]; then
    rm -f "$manifest_tmp" "$archive_tmp"
    return 1
  fi
  info "downloading ebpfshark ${version} (${VARIANT}, linux/${ARCH})"
  if ! fetch_to "$url" "$archive_tmp"; then
    rm -f "$manifest_tmp" "$archive_tmp"
    return 1
  fi
  actual="$(sha256sum "$archive_tmp" | awk '{print $1}')"
  if [[ "$actual" != "$sha" ]]; then
    rm -f "$manifest_tmp" "$archive_tmp"
    die "downloaded binary checksum mismatch (expected $sha, got $actual)"
  fi
  chmod 0755 "$archive_tmp"
  BINARY="$archive_tmp"
  DOWNLOAD_TMP="$archive_tmp"
  INSTALLED_FROM_RELEASE=1
  rm -f "$manifest_tmp"
  return 0
}

build_from_source() {
  require_build_deps
  info "building ebpfshark from source (${VARIANT})"
  local target="go-build"
  [[ "$VARIANT" == "full" ]] && target="go-build-full"
  (cd "$SCRIPT_DIR" && make web && make "$target")
  BINARY="$SCRIPT_DIR/bin/ebpfshark"
}

require_build_deps() {
  local missing=0
  for tool in make go pnpm clang llvm-strip bpftool; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "  missing: $tool" >&2
      missing=1
    fi
  done
  if [[ ! -f /usr/include/bpf/bpf_helpers.h ]]; then
    echo "  missing: libbpf headers (/usr/include/bpf/bpf_helpers.h)" >&2
    missing=1
  fi
  if [[ "$missing" -ne 0 ]]; then
    die "build dependencies required; on Debian/Ubuntu: apt-get install -y clang llvm libbpf-dev bpftool (plus Go and pnpm)"
  fi
}

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
  rm -f "${ROOT}/usr/local/share/ca-certificates/ebpfshark-mitm.crt"
  rm -f "${ROOT}/etc/pki/ca-trust/source/anchors/ebpfshark-mitm.crt"
  rm -f "${ROOT}/etc/profile.d/ebpfshark-mitm.sh"
  if command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates >/dev/null 2>&1 || true
  fi
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
  [[ -n "$SCRIPT_DIR" ]] || die "--rebuild requires a local checkout of the repository"
  build_from_source
fi

if [[ -z "$BINARY" ]]; then
  if [[ -n "$SCRIPT_DIR" && -x "$SCRIPT_DIR/bin/ebpfshark" ]]; then
    BINARY="$SCRIPT_DIR/bin/ebpfshark"
  elif ! download_release; then
    if [[ -n "$SCRIPT_DIR" ]]; then
      build_from_source
    else
      die "could not download a release; check --repo/--release-version or run install.sh from the repository"
    fi
  fi
fi
[[ -x "$BINARY" ]] || die "binary not executable: $BINARY"

if [[ -z "$UPDATE_URL" && "$AUTO_UPDATE" == "true" ]]; then
  if [[ "$RELEASE_VERSION" == "latest" ]]; then
    UPDATE_URL="https://github.com/${REPO}/releases/latest/download/manifest-${VARIANT}-linux-${ARCH}.json"
  else
    UPDATE_URL="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/manifest-${VARIANT}-linux-${ARCH}.json"
  fi
fi

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

ensure_env() {
  local key="$1" value="$2"
  if ! grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    printf '%s="%s"\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

setup_system_mitm() {
  local ca_path ca_cert
  if [[ -n "$ROOT" ]]; then
    info "prefix install: skipping system-wide CA/profile changes"
    return
  fi
  mkdir -p "$MITM_CA_DIR"
  chmod 700 "$MITM_CA_DIR"
  ca_path="$("$BIN_PATH" -mitm-ca-init "$MITM_CA_DIR")" || die "could not generate MITM CA"
  ca_cert="${ca_path:-$MITM_CA_DIR/ca.crt}"
  ensure_env EBPFSHARK_MITM "$MITM_ADDR"
  ensure_env EBPFSHARK_MITM_CA_DIR "$MITM_CA_DIR"

  if [[ -d /usr/local/share/ca-certificates ]] && command -v update-ca-certificates >/dev/null 2>&1; then
    install -m 0644 "$ca_cert" /usr/local/share/ca-certificates/ebpfshark-mitm.crt
    update-ca-certificates >/dev/null 2>&1 || true
  elif [[ -d /etc/pki/ca-trust/source/anchors ]] && command -v update-ca-trust >/dev/null 2>&1; then
    install -m 0644 "$ca_cert" /etc/pki/ca-trust/source/anchors/ebpfshark-mitm.crt
    update-ca-trust >/dev/null 2>&1 || true
  else
    info "system CA store not detected; trust $ca_cert manually"
  fi

  cat > /etc/profile.d/ebpfshark-mitm.sh <<PROFILEEOF
# Added by ebpfshark: route HTTPS through the local MITM proxy.
export HTTPS_PROXY="\${HTTPS_PROXY:-http://${MITM_ADDR}}"
export NO_PROXY="\${NO_PROXY:-localhost,127.0.0.1,::1}"
export NODE_EXTRA_CA_CERTS="\${NODE_EXTRA_CA_CERTS:-${ca_cert}}"
PROFILEEOF
  chmod 0644 /etc/profile.d/ebpfshark-mitm.sh
  info "system MITM enabled (CA: $ca_cert, proxy: http://$MITM_ADDR)"
}

get_kv() {
  grep -E "^$1=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//'
}

if [[ "$MITM_SYSTEM" -eq 1 ]]; then
  setup_system_mitm
fi

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
if [[ "$MITM_SYSTEM" -eq 1 ]]; then
  echo "  HTTPS MITM:  http://${MITM_ADDR} (system CA/profile installed; re-login or restart apps)"
fi
if [[ -n "$(get_kv EBPFSHARK_UPDATE_URL)" ]]; then
  echo "  update URL: $(get_kv EBPFSHARK_UPDATE_URL)"
else
  echo "  update URL: (not configured; auto-update stays idle)"
fi
if [[ -n "$DOWNLOAD_TMP" && -f "$DOWNLOAD_TMP" ]]; then rm -f "$DOWNLOAD_TMP"; fi
echo
echo "  variant:    ${VARIANT} / linux-${ARCH}"
echo "Keep the env file private. To change credentials, edit it and restart $SERVICE."
