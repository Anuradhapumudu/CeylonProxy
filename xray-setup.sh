#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# CeylonProxy — One-Command Xray VLESS+Reality Installer
# Usage: bash <(curl -Ls https://raw.githubusercontent.com/Anuradhapumudu/CeylonProxy/main/xray-setup.sh)
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
step() { echo -e "${CYAN}[→]${NC} $1"; }

banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║     🛡️  CeylonProxy — Xray Quick Setup 🛡️    ║"
    echo "║      VLESS + Reality  |  SNI: zoom.us        ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ─── Root Check ───────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "Run as root: sudo bash <(curl -Ls ...)"
fi

banner

# ─── 1. Dependencies ──────────────────────────────────────────
step "Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get &>/dev/null; then
    apt-get update -qq 2>/dev/null
    apt-get install -y -qq curl openssl unzip 2>/dev/null
elif command -v yum &>/dev/null; then
    yum install -y -q curl openssl unzip 2>/dev/null
elif command -v dnf &>/dev/null; then
    dnf install -y -q curl openssl unzip 2>/dev/null
fi
log "Dependencies ready"

# ─── 2. Install Xray ──────────────────────────────────────────
step "Installing Xray core..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install 2>/dev/null
log "Xray installed: $(xray version 2>/dev/null | head -1)"

# ─── 3. Run as root (bypass port 443 permission issue) ────────
step "Configuring Xray service..."
mkdir -p /etc/systemd/system/xray.service.d
# Remove the nobody-user override drop-in
rm -f /etc/systemd/system/xray.service.d/10-donot_touch_single_conf.conf
rm -f /etc/systemd/system/xray.service.d/10-donot_touch_multi_conf.conf

cat > /etc/systemd/system/xray.service << 'EOF'
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
EOF
log "Service configured"

# ─── 4. Generate Keys & Config ────────────────────────────────
step "Generating keys..."
UUID=$(xray uuid)
KEYS=$(xray x25519)
PRIVATE_KEY=$(echo "$KEYS" | grep "^PrivateKey:" | awk '{print $2}')
PUBLIC_KEY=$(echo "$KEYS" | grep "^Password" | awk '{print $3}')
SHORT_ID=$(openssl rand -hex 8)

# Get server IP
SERVER_IP=$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null \
    || curl -s4 --max-time 5 api.ipify.org 2>/dev/null \
    || hostname -I | awk '{print $1}')

step "Writing VLESS+Reality config (SNI: zoom.us)..."
mkdir -p /usr/local/etc/xray
mkdir -p /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log

cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "flow": "xtls-rprx-vision",
            "email": "user@ceylonproxy"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "zoom.us:443",
          "xver": 0,
          "serverNames": ["zoom.us", "www.zoom.us"],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": { "domainStrategy": "UseIPv4" }
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"] }
    ]
  }
}
EOF
log "Config written"

# ─── 5. Start Xray ────────────────────────────────────────────
step "Starting Xray service..."
systemctl daemon-reload
systemctl enable xray 2>/dev/null
systemctl restart xray
sleep 3

STATUS=$(systemctl is-active xray 2>/dev/null || echo "unknown")
if [[ "$STATUS" != "active" ]]; then
    err "Xray failed to start! Check: journalctl -u xray -n 20"
fi
log "Xray is running on port 443"

# ─── 6. Build Share Link ──────────────────────────────────────
SHARE_LINK="vless://${UUID}@${SERVER_IP}:443?security=reality&sni=zoom.us&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome&type=tcp&flow=xtls-rprx-vision#CeylonProxy"

# ─── 7. Display Results ───────────────────────────────────────
echo ""
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║${NC}  ${GREEN}${BOLD}✓ CeylonProxy Setup Complete!${NC}                          ${PURPLE}║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Protocol:${NC}    VLESS + Reality"
echo -e "  ${CYAN}Server:${NC}      ${SERVER_IP}"
echo -e "  ${CYAN}Port:${NC}        443"
echo -e "  ${CYAN}UUID:${NC}        ${UUID}"
echo -e "  ${CYAN}Flow:${NC}        xtls-rprx-vision"
echo -e "  ${CYAN}SNI:${NC}         zoom.us"
echo -e "  ${CYAN}Public Key:${NC}  ${PUBLIC_KEY}"
echo -e "  ${CYAN}Short ID:${NC}    ${SHORT_ID}"
echo -e "  ${CYAN}Fingerprint:${NC} chrome"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  📋 Share Link (copy → import into Hiddify / v2rayNG):${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}${SHARE_LINK}${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${CYAN}Best clients:${NC}"
echo -e "  • Mac/iOS:  ${BOLD}Hiddify${NC} (App Store) ← recommended"
echo -e "  • Android:  ${BOLD}v2rayNG${NC} or ${BOLD}Hiddify${NC}"
echo -e "  • Windows:  ${BOLD}Hiddify${NC} or ${BOLD}Nekobox${NC}"
echo ""
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
