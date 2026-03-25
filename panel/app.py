#!/usr/bin/env python3
"""
CeylonProxy — Web Management Panel for Xray (VLESS/Trojan)
A lightweight 3X-UI alternative with WireGuard VPN integration.
"""

import os
import sys
import json
import uuid
import urllib.parse
import time
import sqlite3
import hashlib
import secrets
import subprocess
import logging
import threading
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, send_from_directory
)

# ─── Configuration ──────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = secrets.token_hex(32)

# Enable gzip compression
try:
    from flask_compress import Compress
    Compress(app)
except ImportError:
    pass  # flask-compress not installed, skip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'panel.db')
XRAY_CONFIG = '/usr/local/etc/xray/config.json'
XRAY_BIN = '/usr/local/bin/xray'
LOG_FILE = '/var/log/ceylonproxy-panel.log'

logging.basicConfig(
    filename=LOG_FILE if os.path.exists(os.path.dirname(LOG_FILE)) else None,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ─── Caching Layer ──────────────────────────────────────────────────────────
_cache = {}
_cache_ttl = {}

def cached(key, ttl_seconds=5):
    """Check if a cached value exists and is fresh."""
    if key in _cache and time.time() - _cache_ttl.get(key, 0) < ttl_seconds:
        return _cache[key]
    return None

def set_cache(key, value):
    """Store a value in cache with current timestamp."""
    _cache[key] = value
    _cache_ttl[key] = time.time()
    return value


# ─── Database ───────────────────────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA cache_size=2000")
    return db


def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS inbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remark TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'vless',
            enable INTEGER DEFAULT 1,
            tls_type TEXT DEFAULT 'tls',
            sni TEXT DEFAULT '',
            cert_path TEXT DEFAULT '',
            key_path TEXT DEFAULT '',
            settings_json TEXT DEFAULT '{}',
            stream_json TEXT DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inbound_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            client_id TEXT NOT NULL,
            password TEXT DEFAULT '',
            flow TEXT DEFAULT '',
            enable INTEGER DEFAULT 1,
            total_gb INTEGER DEFAULT 0,
            expiry_time INTEGER DEFAULT 0,
            upload INTEGER DEFAULT 0,
            download INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
        );
    ''')

    # Create default admin if not exists
    admin = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not admin:
        pw_hash = hash_password('admin')
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   ('admin', pw_hash))
        logger.info("Default admin user created (admin/admin)")

    # Default settings
    defaults = {
        'panel_port': '8443',
        'panel_domain': '',
        'panel_cert': '',
        'panel_key': '',
        'xray_dns': '1.1.1.1,8.8.8.8',
        'domain_strategy': 'IPIfNonMatch',
    }
    for k, v in defaults.items():
        existing = db.execute("SELECT key FROM settings WHERE key=?", (k,)).fetchone()
        if not existing:
            db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (k, v))

    db.commit()
    db.close()


def hash_password(password):
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"


def verify_password(stored, password):
    try:
        salt, h = stored.split(':')
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    except Exception:
        return False


def get_setting(key, default=''):
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    db.close()
    return row['value'] if row else default


def set_setting(key, value):
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    db.commit()
    db.close()


# ─── Auth ───────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'msg': 'Not authenticated'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ─── Xray Config Generation ────────────────────────────────────────────────
def generate_xray_config():
    """Generate Xray config from database inbounds/clients."""
    db = get_db()
    inbounds = db.execute("SELECT * FROM inbounds WHERE enable=1").fetchall()
    dns_servers = get_setting('xray_dns', '1.1.1.1,8.8.8.8').split(',')

    config = {
        "log": {
            "loglevel": "warning",
            "access": "/var/log/xray/access.log",
            "error": "/var/log/xray/error.log"
        },
        "dns": {
            "servers": [
                {"address": "https+local://1.1.1.1/dns-query", "skipFallback": False},
                {"address": "https+local://8.8.8.8/dns-query", "skipFallback": False},
            ] if dns_servers == ['1.1.1.1', '8.8.8.8'] else [s.strip() for s in dns_servers],
            "queryStrategy": "UseIPv4",
            "tag": "dns-out"
        },
        "routing": {
            "domainStrategy": get_setting('domain_strategy', 'IPIfNonMatch'),
            "rules": [
                # Block bittorrent
                {"type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"]},
                # Prevent routing loops — server's own IP must go direct
                {"type": "field", "outboundTag": "direct", "ip": [
                    "geoip:private",
                    "165.22.243.162",     # Server's own IP
                    "62.197.156.18",      # WireGuard endpoint
                    "62.197.156.19",      # WG exit IP
                ]},
                # Prevent routing loops — server's own domain must go direct
                {"type": "field", "outboundTag": "direct", "domain": [
                    "aidenandrew.duckdns.org",
                    "duckdns.org",
                ]},
            ]
        },
        "inbounds": [],
        "outbounds": []
    }

    # Build outbound — bind to WG interface if active (safe: WG doesn't change default route)
    wg_ip = None
    try:
        wg_check = subprocess.run(['ip', 'addr', 'show', 'wg0'], capture_output=True, text=True, timeout=3)
        if wg_check.returncode == 0:
            for line in wg_check.stdout.split('\n'):
                if 'inet ' in line:
                    wg_ip = line.strip().split()[1].split('/')[0]
                    break
    except Exception:
        pass

    direct_outbound = {
        "protocol": "freedom",
        "tag": "direct",
        "settings": {"domainStrategy": "UseIP"}
    }
    if wg_ip:
        direct_outbound["sendThrough"] = wg_ip

    config["outbounds"] = [
        direct_outbound,
        {"protocol": "blackhole", "tag": "blocked"}
    ]

    for ib in inbounds:
        clients_rows = db.execute(
            "SELECT * FROM clients WHERE inbound_id=? AND enable=1",
            (ib['id'],)
        ).fetchall()

        if ib['protocol'] == 'vless':
            clients = []
            for c in clients_rows:
                client = {"id": c['client_id'], "email": c['email']}
                if c['flow']:
                    client["flow"] = c['flow']
                clients.append(client)

            transport = dict(ib).get('transport', 'tcp')
            inbound_cfg = {
                "port": ib['port'],
                "protocol": "vless",
                "tag": f"inbound-{ib['id']}",
                "settings": {
                    "clients": clients,
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": transport,
                    "security": ib['tls_type'] or "tls",
                    "sockopt": {
                        "tcpFastOpen": True,
                        "tproxy": "off",
                        "tcpKeepAliveInterval": 30,
                        "tcpMptcp": True
                    }
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True
                }
            }

            # TLS settings logic
            cert = ib['cert_path'] or get_setting('panel_cert')
            key = ib['key_path'] or get_setting('panel_key')
            
            if ib['tls_type'] == 'tls' and cert and key:
                inbound_cfg["streamSettings"]["security"] = "tls"
                inbound_cfg["streamSettings"]["tlsSettings"] = {
                    "serverName": ib['sni'] or "",
                    "minVersion": "1.2",
                    "maxVersion": "1.3",
                    "rejectUnknownSni": False,
                    "certificates": [{
                        "certificateFile": cert,
                        "keyFile": key
                    }],
                    "alpn": ["h2", "http/1.1"],
                }
            else:
                inbound_cfg["streamSettings"]["security"] = "none"

            if transport == 'ws':
                inbound_cfg["streamSettings"]["wsSettings"] = {
                    "path": "/xray",
                    "headers": {
                        "Host": ib['sni'] or "teams.microsoft.com"
                    }
                }
            elif transport == 'tcp':
                inbound_cfg["streamSettings"]["tcpSettings"] = {
                    "acceptProxyProtocol": False,
                    "header": {"type": "none"}
                }

        elif ib['protocol'] == 'trojan':
            clients = []
            for c in clients_rows:
                clients.append({
                    "password": c['password'] or c['client_id'],
                    "email": c['email']
                })

            transport = dict(ib).get('transport', 'tcp')
            inbound_cfg = {
                "port": ib['port'],
                "protocol": "trojan",
                "tag": f"inbound-{ib['id']}",
                "settings": {"clients": clients},
                "streamSettings": {
                    "network": transport,
                    "security": "tls",
                    "sockopt": {"tcpFastOpen": True, "tproxy": "off"}
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"]
                }
            }

            cert = ib['cert_path'] or get_setting('panel_cert')
            key = ib['key_path'] or get_setting('panel_key')

            if cert and key:
                inbound_cfg["streamSettings"]["tlsSettings"] = {
                    "serverName": ib['sni'] or "",
                    "minVersion": "1.2",
                    "maxVersion": "1.3",
                    "rejectUnknownSni": False,
                    "certificates": [{
                        "certificateFile": cert,
                        "keyFile": key
                    }],
                    "alpn": ["h2", "http/1.1"],
                }
            else:
                inbound_cfg["streamSettings"]["security"] = "none"

            if transport == 'ws':
                inbound_cfg["streamSettings"]["wsSettings"] = {
                    "path": "/xray",
                    "headers": {
                        "Host": ib['sni'] or "teams.microsoft.com"
                    }
                }
            elif transport == 'tcp':
                inbound_cfg["streamSettings"]["tcpSettings"] = {
                    "acceptProxyProtocol": False,
                    "header": {"type": "none"}
                }
        else:
            continue

        config["inbounds"].append(inbound_cfg)

    db.close()
    return config


def apply_xray_config():
    """Write config, sync firewall, and restart Xray."""
    try:
        db = get_db()
        inbounds = db.execute("SELECT port FROM inbounds").fetchall()
        db.close()
        
        # Sync firewall ports dynamically
        for ib in inbounds:
            subprocess.run(['ufw', 'allow', f"{ib['port']}/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        config = generate_xray_config()
        os.makedirs(os.path.dirname(XRAY_CONFIG), exist_ok=True)
        with open(XRAY_CONFIG, 'w') as f:
            json.dump(config, f, indent=2)
        os.chmod(XRAY_CONFIG, 0o644)
        subprocess.run(['systemctl', 'restart', 'xray'], check=True, timeout=10)
        logger.info("Xray config applied and restarted")
        return True, "Xray restarted successfully"
    except Exception as e:
        logger.error(f"Failed to apply Xray config: {e}")
        return False, str(e)


def generate_share_link(inbound, client):
    """Generate VLESS or Trojan share link."""
    server_ip = get_setting('panel_domain') or get_server_ip()
    port = inbound['port']
    sni = inbound['sni'] or 'teams.microsoft.com'

    transport = inbound.get('transport', 'tcp')
    if transport == 'ws':
        type_str = f"&type=ws&path=%2Fxray&host={urllib.parse.quote(sni)}"
    else:
        type_str = "&type=tcp&headerType=none"

    if inbound['protocol'] == 'vless':
        flow_part = f"&flow={client.get('flow', '')}" if client.get('flow') else ""
        link = (
            f"vless://{client['client_id']}@{server_ip}:{port}"
            f"?allowInsecure=true"
            f"&alpn=h2%2Chttp%2F1.1"
            f"&fp=chrome"
            f"{type_str}"
            f"&security=tls"
            f"&sni={sni}"
            f"{flow_part}"
            f"#{client['email']}"
        )
    elif inbound['protocol'] == 'trojan':
        password = client.get('password') or client['client_id']
        link = (
            f"trojan://{password}@{server_ip}:{port}"
            f"?allowInsecure=true"
            f"&alpn=h2%2Chttp%2F1.1"
            f"&fp=chrome"
            f"{type_str}"
            f"&security=tls"
            f"&sni={sni}"
            f"#{client['email']}"
        )
    else:
        link = ""
    return link


_CACHED_SERVER_IP = None

def get_server_ip():
    global _CACHED_SERVER_IP
    if _CACHED_SERVER_IP: return _CACHED_SERVER_IP
    try:
        result = subprocess.run(
            ['hostname', '-I'], capture_output=True, text=True, timeout=2
        )
        ips = result.stdout.strip().split()
        for ip in ips:
            if not ip.startswith('10.') and not ip.startswith('172.') and ':' not in ip:
                _CACHED_SERVER_IP = ip
                return ip
        _CACHED_SERVER_IP = ips[0] if ips else '0.0.0.0'
        return _CACHED_SERVER_IP
    except Exception:
        return '0.0.0.0'


_CACHED_PUBLIC_IP = None

def get_system_stats():
    """Get server stats with caching (5s TTL)."""
    global _CACHED_PUBLIC_IP
    c = cached('system_stats', 5)
    if c:
        return c

    stats = {}
    try:
        with open('/proc/uptime') as f:
            uptime_s = float(f.read().split()[0])
            days = int(uptime_s // 86400)
            hours = int((uptime_s % 86400) // 3600)
            mins = int((uptime_s % 3600) // 60)
            stats['uptime'] = f"{days}d {hours}h {mins}m"

        with open('/proc/loadavg') as f:
            stats['load'] = f.read().split()[0]

        # CPU usage from /proc/stat
        try:
            with open('/proc/stat') as f:
                cpu = f.readline().split()[1:]
            idle = int(cpu[3])
            total = sum(int(x) for x in cpu)
            stats['cpu_pct'] = round((1 - idle / total) * 100, 1) if total > 0 else 0
        except Exception:
            stats['cpu_pct'] = 0

        # Active Xray connections
        try:
            conn_result = subprocess.run(
                ['ss', '-tnp', 'state', 'established'],
                capture_output=True, text=True, timeout=2
            )
            xray_conns = sum(1 for line in conn_result.stdout.split('\n') if 'xray' in line)
            stats['active_connections'] = xray_conns
        except Exception:
            stats['active_connections'] = 0

        # Memory from /proc/meminfo (no subprocess needed)
        try:
            with open('/proc/meminfo') as f:
                meminfo = {}
                for line in f:
                    parts = line.split()
                    meminfo[parts[0].rstrip(':')] = int(parts[1]) * 1024
            stats['mem_total'] = meminfo.get('MemTotal', 0)
            stats['mem_used'] = stats['mem_total'] - meminfo.get('MemAvailable', 0)
            stats['mem_pct'] = round(stats['mem_used'] / stats['mem_total'] * 100, 1) if stats['mem_total'] > 0 else 0
        except Exception:
            stats['mem_total'] = 0
            stats['mem_used'] = 0
            stats['mem_pct'] = 0

        # Network bytes (eth0)
        try:
            with open('/sys/class/net/eth0/statistics/rx_bytes') as f:
                stats['net_rx'] = int(f.read().strip())
            with open('/sys/class/net/eth0/statistics/tx_bytes') as f:
                stats['net_tx'] = int(f.read().strip())
        except Exception:
            stats['net_rx'] = 0
            stats['net_tx'] = 0

        # WireGuard status
        wg = subprocess.run(['wg', 'show', 'wg0'], capture_output=True, text=True, timeout=2)
        stats['wg_status'] = 'UP' if wg.returncode == 0 else 'DOWN'
        if wg.returncode == 0:
            for line in wg.stdout.split('\n'):
                if 'transfer' in line:
                    stats['wg_transfer'] = line.strip().replace('transfer: ', '')
                if 'latest handshake' in line:
                    stats['wg_handshake'] = line.strip().replace('latest handshake: ', '')

        # Xray status
        xray = subprocess.run(
            ['systemctl', 'is-active', 'xray'],
            capture_output=True, text=True, timeout=2
        )
        stats['xray_status'] = xray.stdout.strip().upper()

        if not _CACHED_PUBLIC_IP:
            try:
                ip_result = subprocess.run(
                    ['curl', '-s', '--max-time', '2', 'http://api.ipify.org'],
                    capture_output=True, text=True, timeout=3
                )
                _CACHED_PUBLIC_IP = ip_result.stdout.strip() or 'unknown'
            except Exception:
                _CACHED_PUBLIC_IP = 'unknown'

        stats['public_ip'] = _CACHED_PUBLIC_IP
        stats['server_ip'] = get_server_ip()

    except Exception as e:
        stats['error'] = str(e)

    return set_cache('system_stats', stats)


def obtain_ssl_cert(domain):
    """Obtain SSL cert via acme.sh."""
    try:
        cert_dir = f"/root/cert/{domain}"
        os.makedirs(cert_dir, exist_ok=True)

        # Stop WireGuard to stop VPN interference with Let's Encrypt API
        subprocess.run(['wg-quick', 'down', 'wg0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cmd = [
            os.path.expanduser('~/.acme.sh/acme.sh'),
            '--issue', '-d', domain,
            '--standalone', '--httpport', '80',
            '--server', 'letsencrypt',
            '--fullchain-file', f'{cert_dir}/fullchain.pem',
            '--key-file', f'{cert_dir}/privkey.pem',
            '--force'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        # Restart WireGuard
        subprocess.run(['wg-quick', 'up', 'wg0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if result.returncode == 0:
            os.chmod(f'{cert_dir}/fullchain.pem', 0o644)
            os.chmod(f'{cert_dir}/privkey.pem', 0o644)
            return True, cert_dir
        else:
            return False, result.stderr
    except Exception as e:
        return False, str(e)


# ─── Routes ─────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        db.close()
        if user and verify_password(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=24)
            logger.info(f"Login: {username}")
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


# ─── API Endpoints ──────────────────────────────────────────────────────────
@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_system_stats())


@app.route('/api/inbounds', methods=['GET'])
@login_required
def api_inbounds_list():
    db = get_db()
    inbounds = db.execute("SELECT * FROM inbounds ORDER BY id").fetchall()
    result = []
    for ib in inbounds:
        clients = db.execute(
            "SELECT * FROM clients WHERE inbound_id=?", (ib['id'],)
        ).fetchall()
        ib_dict = dict(ib)
        ib_dict['clients'] = [dict(c) for c in clients]
        ib_dict['client_count'] = len(clients)
        result.append(ib_dict)
    db.close()
    return jsonify({'success': True, 'inbounds': result})


@app.route('/api/inbounds', methods=['POST'])
@login_required
def api_inbound_create():
    data = request.json
    remark = data.get('remark', 'New Inbound')
    port = int(data.get('port', 443))
    protocol = data.get('protocol', 'vless')
    sni = data.get('sni', '').split('/')[0]
    cert_path = data.get('cert_path', '')
    key_path = data.get('key_path', '')
    transport = data.get('transport', 'tcp')

    db = get_db()
    existing = db.execute("SELECT id FROM inbounds WHERE port=?", (port,)).fetchone()
    if existing:
        db.close()
        return jsonify({'success': False, 'msg': f'Port {port} already in use'})

    db.execute(
        """INSERT INTO inbounds (remark, port, protocol, sni, cert_path, key_path, transport)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (remark, port, protocol, sni, cert_path, key_path, transport)
    )
    db.commit()
    db.close()
    apply_xray_config()
    return jsonify({'success': True, 'msg': 'Inbound created'})


@app.route('/api/inbounds/<int:inbound_id>', methods=['PUT'])
@login_required
def api_inbound_update(inbound_id):
    data = request.json
    db = get_db()
    db.execute(
        """UPDATE inbounds SET remark=?, port=?, protocol=?, sni=?,
           cert_path=?, key_path=?, enable=?, transport=?, updated_at=CURRENT_TIMESTAMP
           WHERE id=?""",
        (data.get('remark'), int(data.get('port')), data.get('protocol'),
         data.get('sni', '').split('/')[0], data.get('cert_path', ''), data.get('key_path', ''),
         int(data.get('enable', 1)), data.get('transport', 'tcp'), inbound_id)
    )
    db.commit()
    db.close()
    apply_xray_config()
    return jsonify({'success': True, 'msg': 'Inbound updated'})


@app.route('/api/inbounds/<int:inbound_id>', methods=['DELETE'])
@login_required
def api_inbound_delete(inbound_id):
    db = get_db()
    db.execute("DELETE FROM clients WHERE inbound_id=?", (inbound_id,))
    db.execute("DELETE FROM inbounds WHERE id=?", (inbound_id,))
    db.commit()
    db.close()
    apply_xray_config()
    return jsonify({'success': True, 'msg': 'Inbound deleted'})


@app.route('/api/clients', methods=['POST'])
@login_required
def api_client_create():
    data = request.json
    inbound_id = int(data.get('inbound_id'))
    email = data.get('email', f'user-{secrets.token_hex(4)}')
    client_id = data.get('client_id', str(uuid.uuid4()))
    password = data.get('password', secrets.token_urlsafe(16))
    # Flow left empty for maximum client compatibility (v2rayA, etc.)
    flow = ''
    total_gb = int(data.get('total_gb', 0))
    expiry_days = int(data.get('expiry_days', 0))
    expiry_time = int((datetime.now() + timedelta(days=expiry_days)).timestamp() * 1000) if expiry_days > 0 else 0

    db = get_db()
    db.execute(
        """INSERT INTO clients (inbound_id, email, client_id, password, flow,
           total_gb, expiry_time) VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (inbound_id, email, client_id, password, flow, total_gb, expiry_time)
    )
    db.commit()
    db.close()
    apply_xray_config()
    return jsonify({'success': True, 'msg': 'Client added', 'client_id': client_id})


@app.route('/api/quick-create', methods=['POST'])
@login_required
def api_quick_create():
    """One-step: create inbound + client, return share link."""
    data = request.json
    remark = data.get('remark', f'VPN-{secrets.token_hex(3)}')
    port = int(data.get('port', 443))
    protocol = data.get('protocol', 'vless')
    # Strip path from SNI just in case user adds one
    sni_input = data.get('sni', 'teams.microsoft.com') or 'teams.microsoft.com'
    sni = sni_input.split('/')[0]
    email = data.get('email', f'user-{secrets.token_hex(4)}')
    total_gb = int(data.get('total_gb', 0))
    expiry_days = int(data.get('expiry_days', 0))
    expiry_time = int((datetime.now() + timedelta(days=expiry_days)).timestamp() * 1000) if expiry_days > 0 else 0
    transport = data.get('transport', 'tcp')

    # Auto-fill cert from global settings
    cert_path = data.get('cert_path', '') or get_setting('panel_cert')
    key_path = data.get('key_path', '') or get_setting('panel_key')

    db = get_db()

    # Check if port is already in use
    existing = db.execute("SELECT id FROM inbounds WHERE port=?", (port,)).fetchone()
    if existing:
        db.close()
        return jsonify({'success': False, 'msg': f'Port {port} already in use'})

    # Create inbound
    cursor = db.execute(
        """INSERT INTO inbounds (remark, port, protocol, sni, cert_path, key_path, transport)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (remark, port, protocol, sni, cert_path, key_path, transport)
    )
    inbound_id = cursor.lastrowid

    # Create client
    client_id = str(uuid.uuid4())
    password = secrets.token_urlsafe(16)
    db.execute(
        """INSERT INTO clients (inbound_id, email, client_id, password, flow,
           total_gb, expiry_time) VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (inbound_id, email, client_id, password, '', total_gb, expiry_time)
    )
    db.commit()

    # Get the newly created records for link generation
    inbound = db.execute("SELECT * FROM inbounds WHERE id=?", (inbound_id,)).fetchone()
    client = db.execute("SELECT * FROM clients WHERE inbound_id=? AND client_id=?",
                        (inbound_id, client_id)).fetchone()
    db.close()

    # Apply config and generate link
    apply_xray_config()
    link = generate_share_link(dict(inbound), dict(client))

    return jsonify({
        'success': True,
        'msg': f'{protocol.upper()} created on port {port}',
        'link': link,
        'inbound_id': inbound_id,
        'client_id': client_id
    })


@app.route('/api/clients/<int:client_id>', methods=['DELETE'])
@login_required
def api_client_delete(client_id):
    db = get_db()
    db.execute("DELETE FROM clients WHERE id=?", (client_id,))
    db.commit()
    db.close()
    apply_xray_config()
    return jsonify({'success': True, 'msg': 'Client deleted'})


@app.route('/api/clients/<int:client_id>/toggle', methods=['POST'])
@login_required
def api_client_toggle(client_id):
    db = get_db()
    db.execute("UPDATE clients SET enable = CASE WHEN enable=1 THEN 0 ELSE 1 END WHERE id=?", (client_id,))
    db.commit()
    db.close()
    apply_xray_config()
    return jsonify({'success': True})


@app.route('/api/clients/<int:client_id>/link')
@login_required
def api_client_link(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    if not client:
        db.close()
        return jsonify({'success': False, 'msg': 'Client not found'})
    inbound = db.execute("SELECT * FROM inbounds WHERE id=?", (client['inbound_id'],)).fetchone()
    db.close()
    link = generate_share_link(dict(inbound), dict(client))
    return jsonify({'success': True, 'link': link})


@app.route('/api/ssl/obtain', methods=['POST'])
@login_required
def api_ssl_obtain():
    data = request.json
    domain = data.get('domain', '')
    if not domain:
        return jsonify({'success': False, 'msg': 'Domain required'})

    success, result = obtain_ssl_cert(domain)
    if success:
        cert_dir = result
        set_setting('panel_domain', domain)
        set_setting('panel_cert', f'{cert_dir}/fullchain.pem')
        set_setting('panel_key', f'{cert_dir}/privkey.pem')
        return jsonify({
            'success': True,
            'msg': f'Certificate obtained for {domain}',
            'cert_path': f'{cert_dir}/fullchain.pem',
            'key_path': f'{cert_dir}/privkey.pem'
        })
    return jsonify({'success': False, 'msg': f'Failed: {result}'})


@app.route('/api/settings', methods=['GET'])
@login_required
def api_settings_get():
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    db.close()
    return jsonify({'success': True, 'settings': {r['key']: r['value'] for r in rows}})


@app.route('/api/settings', methods=['POST'])
@login_required
def api_settings_save():
    data = request.json
    for key, value in data.items():
        set_setting(key, str(value))
    return jsonify({'success': True, 'msg': 'Settings saved'})


@app.route('/api/password', methods=['POST'])
@login_required
def api_password_change():
    data = request.json
    new_pw = data.get('password', '')
    if len(new_pw) < 4:
        return jsonify({'success': False, 'msg': 'Password too short'})
    db = get_db()
    db.execute("UPDATE users SET password_hash=? WHERE id=?",
               (hash_password(new_pw), session['user_id']))
    db.commit()
    db.close()
    return jsonify({'success': True, 'msg': 'Password changed'})


@app.route('/api/xray/restart', methods=['POST'])
@login_required
def api_xray_restart():
    success, msg = apply_xray_config()
    return jsonify({'success': success, 'msg': msg})


@app.route('/api/vpn/status')
@login_required
def api_vpn_status():
    """Get WireGuard VPN status with tunnel exit IP."""
    try:
        wg = subprocess.run(['wg', 'show', 'wg0'], capture_output=True, text=True, timeout=5)
        connected = wg.returncode == 0

        # Get tunnel exit IP (through wg0 interface) and server direct IP
        tunnel_ip = 'unknown'
        server_ip = 'unknown'

        if connected:
            # Check IP through WG tunnel
            try:
                r = subprocess.run(
                    ['curl', '-s', '--max-time', '4', '--interface', 'wg0', 'https://ifconfig.me'],
                    capture_output=True, text=True, timeout=6
                )
                ip = r.stdout.strip()
                if ip and '.' in ip and len(ip) < 50:
                    tunnel_ip = ip
            except Exception:
                pass

        # Server's direct IP (always through eth0)
        try:
            r = subprocess.run(
                ['curl', '-s', '--max-time', '3', 'https://ifconfig.me'],
                capture_output=True, text=True, timeout=5
            )
            ip = r.stdout.strip()
            if ip and '.' in ip and len(ip) < 50:
                server_ip = ip
        except Exception:
            pass

        result = {
            'success': True,
            'connected': connected,
            'current_ip': tunnel_ip if connected else server_ip,
            'server_ip': server_ip,
            'tunnel_ip': tunnel_ip,
        }

        if connected:
            for line in wg.stdout.split('\n'):
                if 'endpoint' in line and ':' in line:
                    result['endpoint'] = line.strip().split(':', 1)[1].strip() if ':' in line else ''
                if 'transfer' in line:
                    result['transfer'] = line.strip().replace('transfer: ', '')
                if 'latest handshake' in line:
                    result['handshake'] = line.strip().replace('latest handshake: ', '')

        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)})


@app.route('/api/vpn/toggle', methods=['POST'])
@login_required
def api_vpn_toggle():
    """Toggle WireGuard VPN on/off."""
    global _CACHED_PUBLIC_IP
    try:
        # Check current state
        wg = subprocess.run(['wg', 'show', 'wg0'], capture_output=True, text=True, timeout=5)
        is_up = wg.returncode == 0

        if is_up:
            # Turn OFF — brings down WireGuard, server uses direct internet
            result = subprocess.run(
                ['wg-quick', 'down', 'wg0'],
                capture_output=True, text=True, timeout=15
            )
            action = 'disconnected'
            new_state = False
        else:
            # Turn ON — brings up WireGuard, routes through WARP VPN
            result = subprocess.run(
                ['wg-quick', 'up', 'wg0'],
                capture_output=True, text=True, timeout=15
            )
            action = 'connected'
            new_state = True

        # Invalidate IP cache so dashboard refreshes
        _CACHED_PUBLIC_IP = None

        if result.returncode == 0:
            # Re-apply Xray config so outbound routing updates (sendThrough)
            import time
            time.sleep(1)  # Wait for WG interface to stabilize
            apply_xray_config()
            return jsonify({
                'success': True,
                'connected': new_state,
                'msg': f'WireGuard VPN {action} — Xray routing updated'
            })
        else:
            return jsonify({
                'success': False,
                'msg': f'Failed: {result.stderr}'
            })
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)})


@app.route('/api/xray/logs')
@login_required
def api_xray_logs():
    """Get last N lines of Xray logs — uses Python file seek instead of subprocess."""
    num_lines = int(request.args.get('lines', 100))
    log_type = request.args.get('type', 'access')
    log_path = f'/var/log/xray/{log_type}.log'
    try:
        if os.path.exists(log_path):
            # Efficient tail using file seek — no subprocess overhead
            with open(log_path, 'rb') as f:
                f.seek(0, 2)  # Seek to end
                size = f.tell()
                block_size = min(size, 8192)
                lines_found = []
                pos = size
                while len(lines_found) < num_lines + 1 and pos > 0:
                    read_size = min(block_size, pos)
                    pos -= read_size
                    f.seek(pos)
                    chunk = f.read(read_size).decode('utf-8', errors='replace')
                    lines_found = chunk.splitlines() + lines_found
                log_text = '\n'.join(lines_found[-num_lines:])
            return jsonify({
                'success': True,
                'logs': log_text,
                'log_type': log_type,
                'path': log_path
            })
        else:
            return jsonify({'success': True, 'logs': f'Log file not found: {log_path}', 'log_type': log_type})
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)})


@app.route('/api/ping')
@login_required
def api_ping():
    """Simple ping endpoint for client-side latency measurement."""
    return jsonify({'pong': True, 'ts': time.time()})


@app.route('/api/server/restart', methods=['POST'])
@login_required
def api_server_restart():
    """Restart the server (graceful reboot)."""
    try:
        # Schedule reboot in 3 seconds so we can send the response first
        subprocess.Popen(['shutdown', '-r', '+0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return jsonify({'success': True, 'msg': 'Server is rebooting... Please wait 30-60 seconds and refresh.'})
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)})


@app.route('/api/server/services')
@login_required
def api_server_services():
    """Get status of all key services."""
    services = ['ceylonproxy-panel', 'xray', 'wg-quick@wg0']
    result = {}
    for svc in services:
        try:
            r = subprocess.run(['systemctl', 'is-active', svc], capture_output=True, text=True, timeout=3)
            result[svc] = r.stdout.strip()
        except:
            result[svc] = 'unknown'
    return jsonify({'success': True, 'services': result})


@app.route('/api/system/info')
@login_required
def api_system_info():
    """Get detailed system information."""
    info = {}
    try:
        # OS info
        result = subprocess.run(['lsb_release', '-ds'], capture_output=True, text=True, timeout=2)
        info['os'] = result.stdout.strip() if result.returncode == 0 else 'Linux'

        # Kernel
        result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=2)
        info['kernel'] = result.stdout.strip()

        # Hostname
        result = subprocess.run(['hostname'], capture_output=True, text=True, timeout=2)
        info['hostname'] = result.stdout.strip()

        # Disk usage
        result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=2)
        lines = result.stdout.strip().split('\n')
        if len(lines) > 1:
            parts = lines[1].split()
            info['disk_total'] = parts[1]
            info['disk_used'] = parts[2]
            info['disk_free'] = parts[3]
            info['disk_pct'] = parts[4]

        # Xray version
        result = subprocess.run([XRAY_BIN, 'version'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            info['xray_version'] = result.stdout.split('\n')[0]

    except Exception as e:
        info['error'] = str(e)
    return jsonify({'success': True, 'info': info})


# ─── Speedtest ──────────────────────────────────────────────────────────────
_speedtest_result = None
_speedtest_running = False


def _run_speedtest():
    """Run download/upload/ping test in background thread."""
    global _speedtest_result, _speedtest_running
    _speedtest_running = True
    result = {'status': 'running', 'started_at': datetime.now().isoformat()}
    try:
        # Ping test
        ping = subprocess.run(
            ['ping', '-c', '5', '-W', '2', '1.1.1.1'],
            capture_output=True, text=True, timeout=15
        )
        if ping.returncode == 0:
            for line in ping.stdout.split('\n'):
                if 'avg' in line:
                    # rtt min/avg/max/mdev = 1.234/5.678/...
                    parts = line.split('=')[1].strip().split('/')
                    result['ping_ms'] = float(parts[1])
                    break
        else:
            result['ping_ms'] = -1

        # Download test — Cloudflare 25MB test file
        dl = subprocess.run(
            ['curl', '-o', '/dev/null', '-s', '-w',
             '%{speed_download}|%{time_total}|%{size_download}',
             '--max-time', '15',
             'https://speed.cloudflare.com/__down?bytes=25000000'],
            capture_output=True, text=True, timeout=20
        )
        if dl.returncode == 0:
            parts = dl.stdout.strip().split('|')
            speed_bps = float(parts[0])  # bytes/sec
            result['download_mbps'] = round(speed_bps * 8 / 1_000_000, 2)
            result['download_time'] = float(parts[1])
            result['download_bytes'] = int(float(parts[2]))
        else:
            result['download_mbps'] = 0

        # Upload test — POST 2MB to Cloudflare
        ul = subprocess.run(
            ['curl', '-X', 'POST', '-o', '/dev/null', '-s', '-w',
             '%{speed_upload}|%{time_total}',
             '--max-time', '10',
             '-d', '@/dev/urandom', '--data-binary', '@-',
             'https://speed.cloudflare.com/__up'],
            input=b'\x00' * 2_000_000,
            capture_output=True, timeout=15
        )
        if ul.returncode == 0:
            parts = ul.stdout.decode().strip().split('|')
            speed_bps = float(parts[0])
            result['upload_mbps'] = round(speed_bps * 8 / 1_000_000, 2)
        else:
            result['upload_mbps'] = 0

        result['status'] = 'completed'
        result['completed_at'] = datetime.now().isoformat()
    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
    finally:
        _speedtest_result = result
        _speedtest_running = False


@app.route('/api/speedtest', methods=['POST'])
@login_required
def api_speedtest_run():
    global _speedtest_running
    if _speedtest_running:
        return jsonify({'success': False, 'msg': 'Speed test already running'})
    t = threading.Thread(target=_run_speedtest, daemon=True)
    t.start()
    return jsonify({'success': True, 'msg': 'Speed test started'})


@app.route('/api/speedtest/status')
@login_required
def api_speedtest_status():
    return jsonify({
        'success': True,
        'running': _speedtest_running,
        'result': _speedtest_result
    })


# ─── Main ───────────────────────────────────────────────────────────────────
def main():
    init_db()
    port = int(get_setting('panel_port', '8443'))
    cert = get_setting('panel_cert')
    key = get_setting('panel_key')

    ssl_ctx = None
    if cert and key and os.path.exists(cert) and os.path.exists(key):
        import ssl
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(cert, key)
        logger.info(f"Panel running with HTTPS on port {port}")
    else:
        logger.info(f"Panel running with HTTP on port {port} (no SSL configured)")

    app.run(host='0.0.0.0', port=port, ssl_context=ssl_ctx, debug=False)


if __name__ == '__main__':
    main()
