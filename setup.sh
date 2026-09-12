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
    echo "║        🛡️  CeylonProxy Setup  🛡️          ║"
    echo "║    Secure VPN Management System v3.2     ║"
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
# Always run the installer — it upgrades in-place if already installed
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install 2>/dev/null

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

# Use ACME_EMAIL env var or default
ACME_EMAIL=${ACME_EMAIL:-lkvpn@gmail.com}

if [[ ! -f ~/.acme.sh/acme.sh ]]; then
    curl -sL https://get.acme.sh | sh -s email="${ACME_EMAIL}" 2>/dev/null || true
fi
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
log "acme.sh installed (Default CA: Let's Encrypt)"

SERVER_IP=$(hostname -I | awk '{print $1}')

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

# Create Python venv and install Flask + extensions
python3 -m venv "$PANEL_DIR/venv"
"$PANEL_DIR/venv/bin/pip" install --quiet \
    "flask>=3.0,<4" \
    "flask-compress>=1.14" \
    2>/dev/null
log "Flask 3.x and extensions installed in virtual environment"

# Create default Xray config
cat > /usr/local/etc/xray/config.json << 'XRAYEOF'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "dns": {
    "servers": [
      {"address": "https+local://1.1.1.1/dns-query"},
      {"address": "https+local://8.8.8.8/dns-query"}
    ],
    "queryStrategy": "UseIPv4"
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"]},
      {"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]}
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

# ─── 6.5 Install iSponsorBlockTV ────────────────────────────
info "Installing iSponsorBlockTV..."
mkdir -p /opt/isponsorblocktv
python3 -m venv /opt/isponsorblocktv/venv
/opt/isponsorblocktv/venv/bin/pip install --upgrade iSponsorBlockTV >/dev/null 2>&1
log "iSponsorBlockTV installed via PyPI"

cat > /etc/systemd/system/isponsorblockTV.service << 'ISBTVEOF'
[Unit]
Description=iSponsorBlockTV
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/isponsorblocktv/venv/bin/iSponsorBlockTV
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
ISBTVEOF

# Create default config to enable all categories
mkdir -p /root/.local/share/iSponsorBlockTV
cat > /root/.local/share/iSponsorBlockTV/config.json << 'ISBTVCFG'
{
    "skip_categories": [
        "sponsor",
        "selfpromo",
        "interaction",
        "intro",
        "outro",
        "preview",
        "filler",
        "music_offtopic"
    ],
    "mute_ads": false,
    "skip_ads": true,
    "devices": []
}
ISBTVCFG

systemctl daemon-reload
systemctl enable isponsorblockTV
log "iSponsorBlockTV service configured (will start after pairing)"

# ─── 6.6 Weekly auto-update timer for iSponsorBlockTV ───────
# Creates a systemd timer that checks for a new version every Sunday at 03:00
cat > /usr/local/bin/isbtv-update.sh << 'UPDATEEOF'
#!/bin/bash
# Weekly iSponsorBlockTV auto-updater
LOG=/var/log/isbtv-update.log
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Checking for iSponsorBlockTV update..." >> "$LOG"

BEFORE=$(/opt/isponsorblocktv/venv/bin/pip show iSponsorBlockTV 2>/dev/null | grep Version | awk '{print $2}')
/opt/isponsorblocktv/venv/bin/pip install --upgrade iSponsorBlockTV >> "$LOG" 2>&1
AFTER=$(/opt/isponsorblocktv/venv/bin/pip show iSponsorBlockTV 2>/dev/null | grep Version | awk '{print $2}')

if [ "$BEFORE" != "$AFTER" ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Upgraded $BEFORE → $AFTER — restarting service" >> "$LOG"
    systemctl restart isponsorblockTV
else
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Already up to date ($BEFORE)" >> "$LOG"
fi
UPDATEEOF
chmod +x /usr/local/bin/isbtv-update.sh

cat > /etc/systemd/system/isbtv-update.service << 'UPDATESVEOF'
[Unit]
Description=iSponsorBlockTV Weekly Auto-Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/isbtv-update.sh
UPDATESVEOF

cat > /etc/systemd/system/isbtv-update.timer << 'UPDATETIMEREOF'
[Unit]
Description=Run iSponsorBlockTV update weekly (Sundays 03:00 UTC)

[Timer]
OnCalendar=Sun 03:00 UTC
Persistent=true
RandomizedDelaySec=600

[Install]
WantedBy=timers.target
UPDATETIMEREOF

systemctl daemon-reload
systemctl enable --now isbtv-update.timer
log "iSponsorBlockTV weekly auto-update timer enabled (Sundays 03:00 UTC)"

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
echo -e "  ${CYAN}Xray:${NC}          ${XRAY_STATUS}"

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
