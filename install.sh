#!/usr/bin/env bash
# ============================================================================
# CeylonProxy — Installer
# ============================================================================
set -euo pipefail

# Colors
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''
fi

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }
step()  { echo -e "${CYAN}[→]${NC} $*"; }

header() {
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}  CeylonProxy — Installer${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This installer requires root. Run: sudo bash install.sh"
    exit 1
fi

header

# ── Check Dependencies ──────────────────────────────────────────────────
step "Checking dependencies..."

DEPS=("wireguard-tools" "iproute2" "iptables")
CMDS=("wg" "ip" "iptables")
MISSING=()

for i in "${!CMDS[@]}"; do
    if command -v "${CMDS[$i]}" &>/dev/null; then
        info "${DEPS[$i]} ... found"
    else
        warn "${DEPS[$i]} ... MISSING"
        MISSING+=("${DEPS[$i]}")
    fi
done

# Check xxd (part of vim or xxd package)
if command -v xxd &>/dev/null; then
    info "xxd ... found"
else
    warn "xxd ... MISSING"
    MISSING+=("xxd")
fi

# Check curl
if command -v curl &>/dev/null; then
    info "curl ... found"
else
    warn "curl ... MISSING"
    MISSING+=("curl")
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo ""
    warn "Missing packages: ${MISSING[*]}"
    echo ""
    echo -n "  Install missing packages now? [Y/n] "
    read -r answer
    if [[ "${answer,,}" != "n" ]]; then
        if command -v apt &>/dev/null; then
            apt update -qq && apt install -y -qq "${MISSING[@]}"
        elif command -v dnf &>/dev/null; then
            dnf install -y "${MISSING[@]}"
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm "${MISSING[@]}"
        else
            error "Cannot auto-install. Please install manually: ${MISSING[*]}"
            exit 1
        fi
        info "Dependencies installed"
    else
        error "Cannot proceed without dependencies"
        exit 1
    fi
fi

echo ""

# ── Install Script ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/ceylonproxy"
SCRIPT_NAME="ceylonproxy"

step "Installing ${SCRIPT_NAME} to ${INSTALL_DIR}/..."
if [[ -f "${SCRIPT_DIR}/ceylonproxy.sh" ]]; then
    cp "${SCRIPT_DIR}/ceylonproxy.sh" "${INSTALL_DIR}/${SCRIPT_NAME}"
    chmod +x "${INSTALL_DIR}/${SCRIPT_NAME}"
    info "Script installed to ${INSTALL_DIR}/${SCRIPT_NAME}"
else
    error "ceylonproxy.sh not found in ${SCRIPT_DIR}"
    exit 1
fi

# ── Install Config ──────────────────────────────────────────────────────
step "Installing configuration..."
mkdir -p "${CONFIG_DIR}"

if [[ -f "${SCRIPT_DIR}/conf.txt" ]]; then
    cp "${SCRIPT_DIR}/conf.txt" "${CONFIG_DIR}/conf.txt"
    chmod 600 "${CONFIG_DIR}/conf.txt"
    info "Config installed to ${CONFIG_DIR}/conf.txt"
else
    warn "conf.txt not found — you'll need to provide it manually"
fi

# ── Create Log File ─────────────────────────────────────────────────────
touch /var/log/ceylonproxy.log
chmod 644 /var/log/ceylonproxy.log
info "Log file created at /var/log/ceylonproxy.log"

# ── Systemd Service (Optional) ─────────────────────────────────────────
echo ""
echo -n "  Install systemd service for auto-start? [y/N] "
read -r answer
if [[ "${answer,,}" == "y" ]]; then
    cat > /etc/systemd/system/ceylonproxy.service << EOF
[Unit]
Description=CeylonProxy WireGuard VPN
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${INSTALL_DIR}/${SCRIPT_NAME} connect
ExecStop=${INSTALL_DIR}/${SCRIPT_NAME} disconnect

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    info "Systemd service created"
    echo ""
    echo "    Enable:  sudo systemctl enable ceylonproxy"
    echo "    Start:   sudo systemctl start ceylonproxy"
    echo "    Status:  sudo systemctl status ceylonproxy"
fi

# ── Done ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}  Installation Complete!${NC}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Quick start:"
echo "    sudo ${SCRIPT_NAME} connect      # Connect to VPN"
echo "    ${SCRIPT_NAME} status            # Check connection"
echo "    sudo ${SCRIPT_NAME} disconnect   # Disconnect"
echo "    ${SCRIPT_NAME} help              # All commands"
echo ""
