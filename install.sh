#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
readonly REPO="Hamster-Prime/DNS_automatic_traffic_splitting"
readonly INSTALL_DIR="/usr/local/bin"
readonly CONFIG_DIR="/etc/doh-autoproxy"
readonly BINARY_NAME="doh-autoproxy"
readonly SERVICE_NAME="doh-autoproxy"

# --- Colors ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly PLAIN='\033[0m'

# --- Helper Functions ---
msg_info() {
    echo -e "${GREEN}[INFO]${PLAIN} $1"
}
msg_warn() {
    echo -e "${YELLOW}[WARN]${PLAIN} $1"
}
msg_err() {
    echo -e "${RED}[ERROR]${PLAIN} $1"
    exit 1
}

# --- Pre-flight Checks ---
check_root() {
    if [ "$EUID" -ne 0 ]; then
        msg_err "请使用 root 权限运行此脚本 (e.g., sudo $0 install)"
    fi
}

check_deps() {
    if ! command -v curl &> /dev/null; then
        msg_err "'curl' 未安装，请先安装它 (e.g., sudo apt update && sudo apt install curl)"
    fi
    if ! command -v jq &> /dev/null; {
        msg_warn "'jq' 未安装，将尝试自动安装..."
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y jq
        elif command -v yum &> /dev/null; then
            yum install -y jq
        elif command -v dnf &> /dev/null; then
            dnf install -y jq
        else
            msg_err "无法自动安装 'jq'。请手动安装后再运行此脚本。"
        fi
    }
}

check_sys() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) msg_err "不支持的架构: $ARCH" ;;
    esac
    OS="linux"
    msg_info "检测到系统: $OS/$ARCH"
}

# --- Core Functions ---
get_latest_version() {
    msg_info "正在获取最新版本信息..."
    LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | jq -r '.tag_name')
    if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" == "null" ]; then
        msg_err "获取最新版本失败，请检查网络或 GitHub API 速率限制。"
    fi
    msg_info "最新版本: $LATEST_TAG"
}

install_binary() {
    get_latest_version
    local download_url="https://github.com/$REPO/releases/download/$LATEST_TAG/doh-autoproxy-$OS-$ARCH"
    
    msg_info "正在下载: $download_url"
    curl -L -o "$INSTALL_DIR/$BINARY_NAME" "$download_url"
    if [ $? -ne 0 ]; then
        msg_err "下载失败！"
    fi
    
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    msg_info "主程序已安装/更新至 $INSTALL_DIR/$BINARY_NAME"
}

install_service_file() {
    msg_info "正在配置 Systemd 服务..."
    cat <<EOF > /etc/systemd/system/$SERVICE_NAME.service
[Unit]
Description=DNS Automatic Traffic Splitting Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$CONFIG_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
Environment="DOH_AUTOPROXY_CONFIG=$CONFIG_DIR/config.yaml"

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    msg_info "Systemd 服务文件已创建/更新。"
}

install_config() {
    msg_info "正在配置文件夹..."
    mkdir -p "$CONFIG_DIR"
    
    local example_config_path="$CONFIG_DIR/config.yaml.example"
    local config_path="$CONFIG_DIR/config.yaml"
    
    msg_info "正在下载最新配置文件模板..."
    curl -L -o "$example_config_path" "https://raw.githubusercontent.com/$REPO/main/config.yaml.example"
    
    if [ ! -f "$config_path" ]; then
        cp "$example_config_path" "$config_path"
        msg_info "已创建默认配置文件: $config_path"
    else
        msg_warn "检测到已存在配置文件 $config_path，未进行覆盖。"
        msg_warn "你可以参考 ${example_config_path} 手动更新配置。"
    fi
    
    touch "$CONFIG_DIR/hosts.txt"
    touch "$CONFIG_DIR/rule.txt"
    msg_info "配置文件夹初始化完成: $CONFIG_DIR"
}

# --- Action Functions ---
do_install() {
    msg_info "开始安装/更新..."
    check_root
    check_deps
    check_sys
    
    install_binary
    install_service_file
    install_config
    
    systemctl enable "$SERVICE_NAME"
    msg_info "服务已设为开机自启。"
    msg_info "请编辑 $CONFIG_DIR/config.yaml 文件，然后使用 'sudo $0 start' 启动服务。"
    msg_info "安装/更新完成！"
}

do_uninstall() {
    check_root
    msg_info "开始卸载..."
    
    systemctl stop "$SERVICE_NAME" || true
    systemctl disable "$SERVICE_NAME" || true
    
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    rm -f "$INSTALL_DIR/$BINARY_NAME"
    
    msg_warn "主程序和服务已卸载。配置文件保留在 $CONFIG_DIR"
    msg_info "卸载完成。"
}

# --- Main Logic ---
usage() {
    echo "用法: $0 [命令]"
    echo
    echo "命令:"
    echo "  install, update   安装或更新程序"
    echo "  uninstall         卸载程序"
    echo "  start             启动服务"
    echo "  stop              停止服务"
    echo "  restart           重启服务"
    echo "  status            查看服务状态"
    echo "  log               实时查看日志"
    echo
}

main() {
    case "$1" in
        install|update)
            do_install
            ;;
        uninstall)
            do_uninstall
            ;;
        start|stop|restart|status)
            check_root
            systemctl "$1" "$SERVICE_NAME"
            ;;
        log)
            check_root
            journalctl -u "$SERVICE_NAME" -f
            ;;
        "")
            usage
            ;;
        *)
            msg_err "未知命令: $1"
            ;;
    esac
}

main "$@"
