#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# CeylonProxy — One-Command Server Setup
# Usage: sudo bash setup.sh
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════╗"
    echo "║        🛡️  CeylonProxy Setup  🛡️        ║"
    echo "║    Secure VPN Management System v1.0     ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[→]${NC} $1"; }

# ─── Root Check ──────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo bash setup.sh)"
    exit 1
fi

banner

# ─── Variables ───────────────────────────────────────────────
PANEL_DIR="/opt/ceylonproxy-panel"
PANEL_PORT="${PANEL_PORT:-8443}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── 1. System Update & Dependencies ────────────────────────
info "Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>/dev/null
apt-get install -y -qq \
    wireguard-tools \
    python3 python3-pip python3-venv \
    curl wget unzip jq \
    iptables iproute2 \
    sqlite3 \
    socat cron \
    net-tools xxd 2>/dev/null || true
log "Dependencies installed"

# ─── 2. Network Optimizations ───────────────────────────────
info "Applying network optimizations..."

cat > /etc/sysctl.d/99-ceylonproxy.conf << 'SYSCTL'
# ═══ CeylonProxy Network Optimizations ═══

# TCP BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Fast Open
net.ipv4.tcp_fastopen = 3

# Larger TCP buffers (better VPN throughput)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000

# Connection tracking
net.netfilter.nf_conntrack_max = 131072

# TCP optimizations
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

# Security
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# IP forwarding
net.ipv4.ip_forward = 1
SYSCTL

sysctl -p /etc/sysctl.d/99-ceylonproxy.conf >/dev/null 2>&1 || true
log "Network optimizations applied (BBR, TCP tuning, security)"

# ─── 3. Install Xray ────────────────────────────────────────
info "Installing Xray..."
if ! command -v xray &>/dev/null || [[ ! -f /usr/local/bin/xray ]]; then
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install 2>/dev/null
fi

# Overwrite Xray service to run as root (the installer creates User=nobody)
cat > /etc/systemd/system/xray.service << 'XRAYSVC'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
XRAYSVC

mkdir -p /var/log/xray
chmod 777 /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log
chmod 666 /var/log/xray/access.log /var/log/xray/error.log
mkdir -p /usr/local/etc/xray

log "Xray installed ($(xray version 2>/dev/null | head -1 || echo 'unknown version'))"

# ─── 4. Install acme.sh for SSL ─────────────────────────────
info "Installing acme.sh for SSL certificates..."

# Prompt for email for Let's Encrypt
read -p "Enter email for Let's Encrypt SSL registration (default: lkvpn@gmail.com): " ACME_EMAIL
ACME_EMAIL=${ACME_EMAIL:-lkvpn@gmail.com}

if [[ ! -f ~/.acme.sh/acme.sh ]]; then
    curl -sL https://get.acme.sh | sh -s email="${ACME_EMAIL}" 2>/dev/null || true
fi
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
log "acme.sh installed (Default CA: Let's Encrypt)"

# ─── 5. Decode conf.txt and Setup WireGuard ──────────────────
CONF_FILE="${SCRIPT_DIR}/conf.txt"

# Decode function matching ceylonproxy.sh algorithm
nibble_swap_hex() {
    local hex="$1"
    local result=""
    local i
    for (( i=0; i<${#hex}; i+=2 )); do
        result+="${hex:i+1:1}${hex:i:1}"
    done
    echo "$result"
}

decode_config() {
    local conf_file="$1"
    local hex_data
    hex_data="$(tr -d '[:space:]' < "$conf_file")"

    # Step 1: Nibble-swap
    local swapped
    swapped="$(nibble_swap_hex "$hex_data")"

    # Step 2: Hex → bytes
    local decoded
    decoded="$(echo "$swapped" | xxd -r -p)"

    # Step 3: Reverse (line-order + char-reverse), strip carriage returns
    echo "$decoded" | tac | rev | tr -d '\r'
}

if [[ -f "$CONF_FILE" ]]; then
    info "Setting up WireGuard VPN from conf.txt..."

    # Detect network
    SERVER_IP=$(hostname -I | awk '{print $1}')
    GATEWAY=$(ip route show default | awk '/default/ {print $3; exit}')
    IFACE=$(ip route show default | awk '/default/ {print $5; exit}')

    echo -e "  ${CYAN}Server IP:${NC}  $SERVER_IP"
    echo -e "  ${CYAN}Gateway:${NC}   $GATEWAY"
    echo -e "  ${CYAN}Interface:${NC} $IFACE"

    DECODED="$(decode_config "$CONF_FILE")"

    if [[ -n "$DECODED" ]]; then
        # Replace placeholders
        DECODED="${DECODED//GATEWAY/$GATEWAY}"
        DECODED="${DECODED//IFACE/$IFACE}"
        DECODED="${DECODED//IPADDR/$SERVER_IP}"

        # Strip any existing PostUp/PreDown from the decoded template
        DECODED="$(echo "$DECODED" | grep -v '^PostUp' | grep -v '^PreDown')"

        # Add MTU, DNS, PersistentKeepalive
        DECODED="$(echo "$DECODED" | sed "/^Address/a MTU = 1420")"
        DECODED="$(echo "$DECODED" | sed "/^MTU/a DNS = 162.252.172.57, 149.154.159.92")"
        DECODED="$(echo "$DECODED" | sed "/^AllowedIPs/a PersistentKeepalive = 25")"

        # Add PostUp/PreDown for response routing using CONNMARK
        DECODED="$(echo "$DECODED" | sed "/^DNS/a\\
PostUp = ip route add default via $GATEWAY dev $IFACE onlink table 123\\
PostUp = ip rule add fwmark 123 table 123\\
PostUp = iptables -t mangle -A PREROUTING -i $IFACE -m conntrack --ctstate NEW -j CONNMARK --set-mark 123\\
PostUp = iptables -t mangle -A OUTPUT -m connmark --mark 123 -j MARK --set-mark 123\\
PreDown = ip route del default via $GATEWAY dev $IFACE table 123 || true\\
PreDown = ip rule del fwmark 123 table 123 || true\\
PreDown = iptables -t mangle -D PREROUTING -i $IFACE -m conntrack --ctstate NEW -j CONNMARK --set-mark 123 || true\\
PreDown = iptables -t mangle -D OUTPUT -m connmark --mark 123 -j MARK --set-mark 123 || true")"

        mkdir -p /etc/wireguard
        echo "$DECODED" > /etc/wireguard/wg0.conf
        chmod 600 /etc/wireguard/wg0.conf
        log "WireGuard config generated"

        # Start WireGuard
        wg-quick down wg0 2>/dev/null || true
        wg-quick up wg0 2>/dev/null || true
        systemctl enable wg-quick@wg0 2>/dev/null || true
        log "WireGuard VPN started"
    else
        warn "Could not decode conf.txt — configure WireGuard manually"
    fi
else
    warn "No conf.txt found — skipping WireGuard setup"
    SERVER_IP=$(hostname -I | awk '{print $1}')
fi

# ─── 6. Install Panel ───────────────────────────────────────
info "Installing CeylonProxy..."

mkdir -p "$PANEL_DIR"
mkdir -p "$PANEL_DIR/templates"
mkdir -p "$PANEL_DIR/static"

# Copy panel files
if [[ -d "${SCRIPT_DIR}/panel" ]]; then
    cp -r "${SCRIPT_DIR}/panel/"* "$PANEL_DIR/"
else
    err "Panel files not found at ${SCRIPT_DIR}/panel/"
    err "Make sure panel/ directory exists alongside setup.sh"
    exit 1
fi

# Create Python venv and install Flask
python3 -m venv "$PANEL_DIR/venv"
"$PANEL_DIR/venv/bin/pip" install --quiet flask 2>/dev/null
log "Flask installed in virtual environment"

# Create default Xray config
cat > /usr/local/etc/xray/config.json << 'XRAYEOF'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "dns": {
    "servers": ["1.1.1.1", "8.8.8.8"]
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"]}
    ]
  },
  "inbounds": [],
  "outbounds": [
    {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIP"}},
    {"protocol": "blackhole", "tag": "blocked"}
  ]
}
XRAYEOF
log "Default Xray config created"

# ─── 7. Create Systemd Service ──────────────────────────────
info "Creating systemd service..."

cat > /etc/systemd/system/ceylonproxy-panel.service << SVCEOF
[Unit]
Description=CeylonProxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PANEL_DIR
ExecStart=$PANEL_DIR/venv/bin/python3 $PANEL_DIR/app.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SVCEOF

touch /var/log/ceylonproxy-panel.log

systemctl daemon-reload
systemctl enable ceylonproxy-panel
systemctl enable xray
systemctl restart xray
systemctl restart ceylonproxy-panel
log "Services created and started"

# ─── 8. Firewall ────────────────────────────────────────────
info "Configuring firewall..."
if command -v ufw &>/dev/null; then
    ufw allow 22/tcp >/dev/null 2>&1
    ufw allow 443/tcp >/dev/null 2>&1
    ufw allow ${PANEL_PORT}/tcp >/dev/null 2>&1
    ufw allow 80/tcp >/dev/null 2>&1
    echo "y" | ufw enable 2>/dev/null || true
    log "UFW firewall configured"
else
    warn "UFW not found — configure firewall manually"
fi

# ─── 9. Final Status ────────────────────────────────────────
sleep 3

PANEL_STATUS=$(systemctl is-active ceylonproxy-panel 2>/dev/null || echo "unknown")
XRAY_STATUS=$(systemctl is-active xray 2>/dev/null || echo "unknown")
WG_STATUS="DOWN"
if wg show wg0 &>/dev/null; then WG_STATUS="UP"; fi

echo ""
echo -e "${PURPLE}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ CeylonProxy Setup Complete!${NC}"
echo -e "${PURPLE}══════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Panel URL:${NC}    http://${SERVER_IP}:${PANEL_PORT}"
echo -e "  ${CYAN}Username:${NC}     admin"
echo -e "  ${CYAN}Password:${NC}     admin"
echo ""
echo -e "  ${CYAN}Panel:${NC}        ${PANEL_STATUS}"
echo -e "  ${CYAN}Xray:${NC}         ${XRAY_STATUS}"
echo -e "  ${CYAN}WireGuard:${NC}    ${WG_STATUS}"

if [[ "$WG_STATUS" == "UP" ]]; then
    PUB_IP=$(curl -s --max-time 5 http://api.ipify.org 2>/dev/null || echo "unknown")
    echo -e "  ${CYAN}Public IP:${NC}    ${PUB_IP} (through VPN)"
fi

echo ""
echo -e "  ${YELLOW}⚠ Change the admin password after first login!${NC}"
echo ""
echo -e "${PURPLE}══════════════════════════════════════════${NC}"
echo -e "  ${CYAN}Next steps:${NC}"
echo -e "  1. Open the panel URL in your browser"
echo -e "  2. Log in with admin/admin"
echo -e "  3. Go to SSL tab → enter domain → obtain cert"
echo -e "  4. Go to Inbounds → create VLESS or Trojan"
echo -e "  5. Add clients and share links"
echo -e "${PURPLE}══════════════════════════════════════════${NC}"
