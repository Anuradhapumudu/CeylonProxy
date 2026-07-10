# CeylonProxy

Optimized VPN tools for Sri Lanka, featuring an automatic Xray VLESS+Reality setup for SLT Zoom bypass, and a WireGuard management script for Surfshark endpoints.

## 🚀 Xray VLESS+Reality Quick Setup (SLT Zoom)

Easily deploy a fast, secure Xray server on any VPS (Ubuntu/Debian/CentOS) with VLESS, Reality protocol, and SNI spoofing for `zoom.us` (ideal for SLT Zoom data quota bypass).

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Anuradhapumudu/CeylonProxy/main/xray-setup.sh)
```

The script will automatically:
1. Install Xray-core.
2. Generate UUID, Short ID, and x25519 keys.
3. Configure VLESS + Reality (SNI: `zoom.us`).
4. Output a ready-to-use share link for clients like **Hiddify** (Mac/Windows/iOS) or **v2rayNG** (Android).

---

## Features

| Feature | Description |
|---|---|
| **Config Decode/Encode** | Decode obfuscated `conf.txt` or encode plain WireGuard configs |
| **Auto MTU** | Sets optimal 1420 MTU for WireGuard (accounts for 80-byte overhead) |
| **DNS Leak Prevention** | Automatically configures Surfshark secure DNS on connect |
| **Kill Switch** | iptables rules blocking all non-VPN traffic |
| **Health Monitor** | Background watchdog with auto-reconnect on failure |
| **Speed Optimizations** | TCP BBR, conntrack tuning, fwmark routing, txqueuelen |
| **Endpoint Selection** | Pings all endpoints and selects the fastest |
| **Status Dashboard** | Real-time connection stats, transfer data, handshake info |
| **Systemd Service** | Optional auto-start on boot |

## 🛡️ WireGuard VPN Management (Surfshark)

### Quick Start

```bash
# Install
sudo bash install.sh

# Connect
sudo ceylonproxy connect

# Check status
ceylonproxy status

# Disconnect
sudo ceylonproxy disconnect
```

## All Commands

```
ceylonproxy connect    [conf]      Connect to VPN
ceylonproxy disconnect             Disconnect from VPN
ceylonproxy status                 Show connection status & stats
ceylonproxy decode     [conf]      Decode conf.txt to WireGuard config
ceylonproxy encode     <file>      Encode WireGuard config to conf.txt
ceylonproxy speedtest              Test latency to all endpoints
ceylonproxy monitor                Start/stop health watchdog
ceylonproxy killswitch [on|off]    Toggle kill switch
ceylonproxy install    [conf]      Install system-wide + systemd
ceylonproxy help                   Show help
```

## Requirements

- **Linux** with kernel 5.6+ (or `wireguard-dkms`)
- `wireguard-tools` — `wg` and `wg-quick`
- `iproute2` — `ip` command
- `iptables` — for kill switch
- `xxd` — for config decoding
- `curl` — for IP checking

Install all on Debian/Ubuntu:
```bash
sudo apt install wireguard-tools iproute2 iptables xxd curl
```

## How It Works

1. **Config decoding** — `conf.txt` contains an obfuscated WireGuard config (hex → nibble-swap → reverse)
2. **Network detection** — Auto-detects gateway, interface, and IP address
3. **Endpoint selection** — Pings available endpoints, picks fastest
4. **Tunnel setup** — Generates optimized WireGuard config and starts `wg-quick`
5. **Optimizations** — Applies MTU, DNS, TCP BBR, fwmark routing, conntrack tuning

## Files

```
xray-setup.sh    — One-command Xray VLESS+Reality installer
ceylonproxy.sh   — Main VPN management script
install.sh       — Installer with dependency checks
conf.txt         — Obfuscated WireGuard configuration
README.md        — This file
```

## Systemd Service

After installing with `sudo bash install.sh`, enable auto-start:

```bash
sudo systemctl enable ceylonproxy
sudo systemctl start ceylonproxy
sudo systemctl status ceylonproxy
```

## License

MIT
