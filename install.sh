#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# CeylonProxy — One-Command Installer
# Usage: bash <(curl -Ls https://raw.githubusercontent.com/Anuradhapumudu/CeylonProxy/main/install.sh)
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
    echo "║        🛡️  CeylonProxy Installer  🛡️      ║"
    echo "║    Secure VPN Management System v3.1     ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ─── Root Check ──────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[✗] This installer must be run as root.${NC}"
    echo "Please switch to root (sudo -i) or run: sudo bash <(curl -Ls ...)"
    exit 1
fi

banner

# ─── Variables ───────────────────────────────────────────────
REPO_URL="https://github.com/Anuradhapumudu/CeylonProxy.git"
BRANCH="main"
INSTALL_DIR="/opt/ceylonproxy-repo"

echo -e "${CYAN}[→] Installing git and curl for downloading repository...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>/dev/null || true
apt-get install -y -qq git curl 2>/dev/null || true

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[!] Removing existing repository directory...${NC}"
    rm -rf "$INSTALL_DIR"
fi

echo -e "${CYAN}[→] Downloading CeylonProxy repository from GitHub...${NC}"
if ! git clone -b "$BRANCH" --quiet "$REPO_URL" "$INSTALL_DIR"; then
    echo -e "${RED}[✗] Failed to download repository.${NC}"
    echo -e "Make sure the repository at $REPO_URL is PUBLIC."
    exit 1
fi

cd "$INSTALL_DIR"

if [ ! -f "setup.sh" ]; then
    echo -e "${RED}[✗] setup.sh not found in the downloaded repository.${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Source downloaded successfully. Starting setup...${NC}"
sleep 2

# Execute the main setup script
chmod +x setup.sh
bash setup.sh
