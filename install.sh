#!/usr/bin/env bash

set -euo pipefail

readonly REPO="Hamster-Prime/DNS_automatic_traffic_splitting"
readonly INSTALL_DIR="/usr/local/bin"
readonly CONFIG_DIR="/etc/doh-autoproxy"
readonly SERVICE_NAME="doh-autoproxy"
readonly BINARY_NAME="doh-autoproxy"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly RELEASE_BASE_URL="https://github.com/${REPO}/releases/latest/download"
readonly PROGRAM_NAME="${0##*/}"

if [ -t 1 ]; then
  readonly COLOR_RED=$'\033[0;31m'
  readonly COLOR_GREEN=$'\033[0;32m'
  readonly COLOR_YELLOW=$'\033[0;33m'
  readonly COLOR_RESET=$'\033[0m'
else
  readonly COLOR_RED=""
  readonly COLOR_GREEN=""
  readonly COLOR_YELLOW=""
  readonly COLOR_RESET=""
fi

OS=""
ARCH=""
ASSET_NAME=""
DOWNLOAD_TOOL=""
SYSTEMD_READY=0
SERVICE_FILE_WRITTEN=0

info() {
  printf "%s[INFO]%s %s\n" "$COLOR_GREEN" "$COLOR_RESET" "$*"
}

warn() {
  printf "%s[WARN]%s %s\n" "$COLOR_YELLOW" "$COLOR_RESET" "$*"
}

error() {
  printf "%s[ERROR]%s %s\n" "$COLOR_RED" "$COLOR_RESET" "$*" >&2
}

die() {
  error "$@"
  exit 1
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "Please run this script as root. Example: sudo bash ${PROGRAM_NAME} install"
  fi
}

ensure_download_tool() {
  if command_exists curl; then
    DOWNLOAD_TOOL="curl"
  elif command_exists wget; then
    DOWNLOAD_TOOL="wget"
  else
    die "curl or wget is required."
  fi
}

download_file() {
  local url="$1"
  local dest="$2"

  case "$DOWNLOAD_TOOL" in
    curl)
      curl -fsSL --retry 3 --retry-delay 1 --connect-timeout 10 -o "$dest" "$url"
      ;;
    wget)
      wget -q -O "$dest" "$url"
      ;;
    *)
      die "No download tool is available."
      ;;
  esac
}

detect_platform() {
  local os_name
  local arch_name

  os_name="$(uname -s 2>/dev/null || true)"
  arch_name="$(uname -m 2>/dev/null || true)"

  case "$os_name" in
    Linux)
      OS="linux"
      ;;
    *)
      die "This installer only supports Linux. Detected OS: ${os_name:-unknown}"
      ;;
  esac

  case "$arch_name" in
    x86_64|amd64)
      ARCH="amd64"
      ;;
    aarch64|arm64)
      ARCH="arm64"
      ;;
    i386|i686)
      ARCH="386"
      ;;
    *)
      die "Unsupported architecture: ${arch_name:-unknown}"
      ;;
  esac

  ASSET_NAME="${BINARY_NAME}-${OS}-${ARCH}"
  info "Detected platform: ${OS}/${ARCH}"
}

install_binary() {
  local tmp_file
  local target_path="${INSTALL_DIR}/${BINARY_NAME}"

  mkdir -p "$INSTALL_DIR"
  tmp_file="$(mktemp "${TMPDIR:-/tmp}/${BINARY_NAME}.XXXXXX")"

  info "Downloading ${ASSET_NAME} from GitHub Releases..."
  download_file "${RELEASE_BASE_URL}/${ASSET_NAME}" "$tmp_file"

  install -m 0755 "$tmp_file" "$target_path"
  rm -f "$tmp_file"

  info "Binary installed to ${target_path}"
}

write_example_config() {
  local example_path="${CONFIG_DIR}/config.yaml.example"

  cat > "$example_path" <<'EOF'
# Example configuration for doh-autoproxy.

listen:
  dns_udp: "53"
  dns_tcp: "53"
  doh: "443"
  doh_path: "/dns-query"
  dot: "853"
  doq: "853"

auto_cert:
  enabled: false
  email: "your-email@example.com"
  domains:
    - "dns.example.com"
  cert_dir: "certs"

tls_certificates:
  # - cert_file: "certs/example.com.crt"
  #   key_file: "certs/example.com.key"

bootstrap_dns:
  - "223.5.5.5:53"
  - "tcp://8.8.8.8:53" # optional: omit tcp:// to use UDP by default

upstreams:
  cn:
    - address: "223.5.5.5"
      protocol: "udp"
      ecs_ip: "114.114.114.114"
    - address: "223.6.6.6"
      protocol: "dot"
      ecs_ip: "114.114.114.114"
      pipeline: true
      insecure_skip_verify: false
  overseas:
    - address: "1.1.1.1"
      protocol: "doh"
      ecs_ip: "8.8.8.8"
      http3: true
      insecure_skip_verify: false
    - address: "8.8.8.8"
      protocol: "dot"
      ecs_ip: "8.8.8.8"
      pipeline: true
    - address: "dns.nextdns.io"
      protocol: "doq"
      ecs_ip: "8.8.8.8"

geo_data:
  geoip_dat: "GeoIP.dat"
  geosite_dat: "GeoSite.dat"
  geoip_download_url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite_download_url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  auto_update: "04:00"

web_ui:
  enabled: true
  address: ":8080"
  username: ""
  password: ""
  guest_mode: false
  # cert_file: ""
  # key_file: ""

query_log:
  enabled: true
  max_history: 5000
  save_to_file: false
  file: "query.log"
  max_size_mb: 1
EOF
}

write_hosts_template() {
  local hosts_path="${CONFIG_DIR}/hosts.txt"

  if [ -f "$hosts_path" ]; then
    return
  fi

  cat > "$hosts_path" <<'EOF'
# Format:
# 127.0.0.1 example.com
# 0.0.0.0 ads.example.com
EOF
}

write_rules_template() {
  local rules_path="${CONFIG_DIR}/rule.txt"

  if [ -f "$rules_path" ]; then
    return
  fi

  cat > "$rules_path" <<'EOF'
# Format:
# google.com overseas
# baidu.com cn
# regexp:.*\.example\.com overseas
EOF
}

install_config() {
  local config_path="${CONFIG_DIR}/config.yaml"
  local example_path="${CONFIG_DIR}/config.yaml.example"

  mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/certs"

  write_example_config

  if [ ! -f "$config_path" ]; then
    cp "$example_path" "$config_path"
    info "Created ${config_path}"
  else
    warn "Keeping existing config: ${config_path}"
  fi

  write_hosts_template
  write_rules_template

  info "Configuration directory is ready: ${CONFIG_DIR}"
}

write_service_file() {
  local service_dir

  service_dir="$(dirname "$SERVICE_FILE")"
  SERVICE_FILE_WRITTEN=0

  if ! command_exists systemctl && [ ! -d "$service_dir" ]; then
    warn "systemd was not detected. Skipping service file generation."
    return
  fi

  mkdir -p "$service_dir"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=DNS Automatic Traffic Splitting Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${CONFIG_DIR}
Environment=DOH_AUTOPROXY_CONFIG=${CONFIG_DIR}/config.yaml
ExecStart=${INSTALL_DIR}/${BINARY_NAME}
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  SERVICE_FILE_WRITTEN=1
  info "Systemd service file written to ${SERVICE_FILE}"
}

reload_and_enable_service() {
  SYSTEMD_READY=0

  if [ "$SERVICE_FILE_WRITTEN" -ne 1 ]; then
    warn "Service file was not created. Service management was skipped."
    return
  fi

  if ! command_exists systemctl; then
    warn "systemctl was not found. The binary is installed, but service management was skipped."
    return
  fi

  if systemctl daemon-reload && systemctl enable "$SERVICE_NAME" >/dev/null 2>&1; then
    SYSTEMD_READY=1
    info "Systemd service has been reloaded and enabled."
  else
    warn "systemd is installed but not usable in this environment. Service management was skipped."
  fi
}

restart_service_if_needed() {
  local was_active="$1"

  if [ "$SYSTEMD_READY" -ne 1 ]; then
    warn "Start the service manually after editing ${CONFIG_DIR}/config.yaml."
    warn "You can also run the binary directly: ${INSTALL_DIR}/${BINARY_NAME}"
    return
  fi

  if [ "$was_active" -eq 1 ]; then
    systemctl restart "$SERVICE_NAME"
    info "Service was already running and has been restarted."
  else
    info "Service is installed but not started yet."
    info "Edit ${CONFIG_DIR}/config.yaml, then run: systemctl start ${SERVICE_NAME}"
  fi
}

do_install() {
  local was_active=0

  require_root
  ensure_download_tool
  detect_platform

  if command_exists systemctl && systemctl is-active --quiet "$SERVICE_NAME"; then
    was_active=1
  fi

  install_binary
  install_config
  write_service_file
  reload_and_enable_service
  restart_service_if_needed "$was_active"

  info "Install/update completed."
}

do_uninstall() {
  require_root

  if command_exists systemctl; then
    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi

  rm -f "$SERVICE_FILE"

  if command_exists systemctl; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  rm -f "${INSTALL_DIR}/${BINARY_NAME}"

  warn "Binary and service files were removed."
  warn "Configuration was kept at ${CONFIG_DIR}"
}

require_systemctl() {
  require_root

  if ! command_exists systemctl; then
    die "systemctl was not found on this machine."
  fi
}

service_action() {
  local action="$1"
  require_systemctl
  systemctl "$action" "$SERVICE_NAME"
}

show_logs() {
  require_root

  if ! command_exists journalctl; then
    die "journalctl was not found on this machine."
  fi

  journalctl -u "$SERVICE_NAME" -f
}

usage() {
  cat <<EOF
Usage: ${PROGRAM_NAME} [command]

Commands:
  install, update   Install or update ${BINARY_NAME}
  uninstall         Remove the binary and service file
  start             Start the systemd service
  stop              Stop the systemd service
  restart           Restart the systemd service
  status            Show the systemd service status
  log, logs         Follow service logs
  help              Show this help message

If no command is provided, "install" is used by default.
EOF
}

main() {
  local action="${1:-install}"

  case "$action" in
    install|update)
      do_install
      ;;
    uninstall)
      do_uninstall
      ;;
    start|stop|restart|status)
      service_action "$action"
      ;;
    log|logs)
      show_logs
      ;;
    help|-h|--help)
      usage
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
