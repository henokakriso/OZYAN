#!/bin/bash
# Ozayn Deployment Script
# Installs and configures all Ozayn services

set -e

OZAYN_DIR="$(cd "$(dirname "$0")" && pwd)"
OZAYN_PARENT="$(dirname "$OZAYN_DIR")"
DATA_DIR="/var/lib/ozayn"
LOG_DIR="/var/log/ozayn"
RUN_DIR="/var/run/ozayn"
ML_PORT=8765
WS_PORT=8081
COLLAB_PORT=8082
PHP_PORT=9090

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[OZAYN]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Run as root: sudo ./deploy.sh"
    fi
}

check_deps() {
    log "Checking dependencies..."
    
    local missing=()
    for cmd in php python3 pip3 node npm; do
        if ! command -v $cmd &>/dev/null; then
            missing+=($cmd)
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        warn "Missing: ${missing[*]}"
        install_deps "${missing[@]}"
    fi
    
    php -m | grep -q sqlite3 || error "PHP SQLite extension required"
    log "Dependencies OK"
}

install_deps() {
    log "Installing system dependencies..."
    apt-get update -qq
    apt-get install -y -qq php php-cli php-sqlite3 php-curl php-mbstring \
        python3 python3-pip python3-venv \
        nodejs npm \
        nginx \
        curl git
}

setup_directories() {
    log "Creating directories..."
    mkdir -p "$DATA_DIR" "$LOG_DIR" "$RUN_DIR"
    mkdir -p "$OZAYN_DIR/ozayn/database"
    chown -R www-data:www-data "$DATA_DIR" "$LOG_DIR"
}

setup_python() {
    log "Setting up Python ML environment..."
    
    cd "$OZAYN_DIR/ozayn/ml"
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    
    log "Python ML environment ready"
}

setup_node() {
    log "Setting up Node.js dependencies..."
    
    cd "$OZAYN_DIR/ozayn/desktop"
    if [ ! -d "node_modules" ]; then
        npm install --silent 2>/dev/null || true
    fi
    
    log "Node.js dependencies ready"
}

init_database() {
    log "Initializing database..."
    
    cd "$OZAYN_DIR"
    php ozayn/install.php
    
    if [ ! -f "$OZAYN_DIR/ozayn/database/ozayn.db" ]; then
        error "Database initialization failed"
    fi
    
    chmod 660 "$OZAYN_DIR/ozayn/database/ozayn.db"
    chown www-data:www-data "$OZAYN_DIR/ozayn/database/ozayn.db"
    log "Database initialized"
}

setup_config() {
    log "Setting up configuration..."
    
    cat > "$OZAYN_DIR/ozayn/backend/config/deploy.php" << 'DEPLOY_CONFIG'
<?php
define('DEPLOY_MODE', 'production');
define('SESSION_LIFETIME', 3600 * 24);
define('LOG_LEVEL', 'warning');
define('AI_MODEL', 'local');
DEPLOY_CONFIG

    chmod 600 "$OZAYN_DIR/ozayn/backend/config/deploy.php"
    log "Configuration ready"
}

create_services() {
    log "Creating systemd services..."
    
    # ML Server
    cat > /etc/systemd/system/ozayn-ml.service << EOF
[Unit]
Description=Ozayn ML Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=$OZAYN_DIR/ozayn/ml
ExecStart=$OZAYN_DIR/ozayn/ml/venv/bin/python server.py
Restart=always
RestartSec=5
Environment=ML_HOST=0.0.0.0
Environment=ML_PORT=$ML_PORT

[Install]
WantedBy=multi-user.target
EOF

    # WebSocket Server
    cat > /etc/systemd/system/ozayn-ws.service << EOF
[Unit]
Description=Ozayn WebSocket Server
After=network.target ozayn-ml.service

[Service]
Type=simple
User=www-data
WorkingDirectory=$OZAYN_DIR/ozayn/backend
ExecStart=$OZAYN_DIR/ozayn/ml/venv/bin/python -c "
import asyncio, websockets, json
async def handler(ws, path=None):
    async for msg in ws:
        pass
async def main():
    async with websockets.serve(handler, '0.0.0.0', $WS_PORT):
        await asyncio.Future()
asyncio.run(main())
"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Collaboration Server
    cat > /etc/systemd/system/ozayn-collab.service << EOF
[Unit]
Description=Ozayn Collaboration Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=$OZAYN_DIR/ozayn/ml
ExecStart=$OZAYN_DIR/ozayn/ml/venv/bin/python -c "
import asyncio, websockets, json
clients = {}
async def handler(ws, path=None):
    async for msg in ws:
        data = json.loads(msg)
        if data.get('type') == 'join':
            sid = data.get('session_id', 'default')
            if sid not in clients:
                clients[sid] = set()
            clients[sid].add(ws)
        await ws.send(json.dumps({'type': 'ack'}))
async def main():
    async with websockets.serve(handler, '0.0.0.0', $COLLAB_PORT):
        await asyncio.Future()
asyncio.run(main())
"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ozayn-ml ozayn-ws ozayn-collab
    log "Systemd services created"
}

setup_nginx() {
    log "Configuring Nginx..."
    
    cat > /etc/nginx/sites-available/ozayn << NGINX
server {
    listen 80;
    server_name _;

    client_max_body_size 10M;

    # Block direct access to sensitive app data and config (DB, keys, logs, backups)
    location ~ ^/ozayn/(database|backend/config|logs|backups|data)/ {
        deny all;
        return 403;
    }

    location = /ozayn/install.php {
        deny all;
        return 403;
    }

    location ~ ^/ozayn/\. {
        deny all;
        return 403;
    }

    # PHP API
    location /ozayn/backend/ {
        root $OZAYN_PARENT;
        try_files \$uri \$uri/ =404;

        location ~ \.php\$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/var/run/php/php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-fpm.sock;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        }
    }

    # Frontend
    location /ozayn/ {
        root $OZAYN_PARENT;
        try_files \$uri \$uri/ =404;

        location ~* \.(js|css|png|jpg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 30d;
            add_header Cache-Control "public, immutable";
        }
    }

    # Root redirect
    location = / {
        return 302 /ozayn;
    }

    # WebSocket proxy
    location /ws/ {
        proxy_pass http://127.0.0.1:$WS_PORT/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400;
    }

    # ML WebSocket proxy
    location /ml/ {
        proxy_pass http://127.0.0.1:$ML_PORT/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400;
    }

    # Collaboration WebSocket proxy
    location /collab/ {
        proxy_pass http://127.0.0.1:$COLLAB_PORT/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400;
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Deny hidden files
    location ~ /\. {
        deny all;
    }
}
NGINX

    ln -sf /etc/nginx/sites-available/ozayn /etc/nginx/sites-enabled/ozayn
    rm -f /etc/nginx/sites-enabled/default

    nginx -t || error "Nginx config test failed"
    systemctl reload nginx
    log "Nginx configured"
}

setup_firewall() {
    log "Configuring firewall..."
    
    if command -v ufw &>/dev/null; then
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow $ML_PORT/tcp
        ufw allow $WS_PORT/tcp
        ufw allow $COLLAB_PORT/tcp
        log "Firewall rules added"
    else
        warn "UFW not found, skipping firewall config"
    fi
}

start_services() {
    log "Starting services..."
    
    systemctl start ozayn-ml
    systemctl start ozayn-ws
    systemctl start ozayn-collab
    systemctl restart nginx
    
    sleep 2
    
    for svc in ozayn-ml ozayn-ws ozayn-collab nginx; do
        if systemctl is-active --quiet $svc; then
            log "  $svc: running"
        else
            warn "  $svc: failed to start"
        fi
    done
}

setup_ssl() {
    log "Setting up Let's Encrypt SSL..."
    
    read -p "Enter domain name (e.g., ozayn.example.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        warn "No domain provided, skipping SSL"
        return
    fi
    
    apt-get install -y -qq certbot python3-certbot-nginx
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN"
    log "SSL configured for $DOMAIN"
}

print_status() {
    echo ""
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Ozayn Deployment Complete!${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    echo -e "Web Interface:  ${GREEN}http://localhost${NC}"
    echo -e "ML Server:      ${GREEN}ws://localhost:$ML_PORT${NC}"
    echo -e "WebSocket:      ${GREEN}ws://localhost:$WS_PORT${NC}"
    echo -e "Collaboration:  ${GREEN}ws://localhost:$COLLAB_PORT${NC}"
    echo ""
    echo -e "Database:       $OZAYN_DIR/ozayn/database/ozayn.db"
    echo -e "Logs:           $LOG_DIR"
    echo ""
    echo -e "Services:"
    echo -e "  systemctl status ozayn-ml"
    echo -e "  systemctl status ozayn-ws"
    echo -e "  systemctl status ozayn-collab"
    echo ""
    echo -e "To register:    curl -X POST http://localhost/ozayn/backend/api/auth/register \\"
    echo -e "  -H 'Content-Type: application/json' \\"
    echo -e "  -d '{\"username\":\"admin\",\"password\":\"changeme\"}'"
    echo ""
}

usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install     Full installation (default)"
    echo "  update      Update dependencies and restart"
    echo "  start       Start all services"
    echo "  stop        Stop all services"
    echo "  restart     Restart all services"
    echo "  status      Show service status"
    echo "  logs        Show recent logs"
    echo "  ssl         Setup SSL certificate"
    echo ""
}

case "${1:-install}" in
    install)
        check_root
        check_deps
        setup_directories
        setup_python
        setup_node
        init_database
        setup_config
        create_services
        setup_nginx
        setup_firewall
        start_services
        print_status
        ;;
    update)
        check_root
        setup_python
        setup_node
        systemctl restart ozayn-ml ozayn-ws ozayn-collab
        log "Updated and restarted"
        ;;
    start)
        check_root
        systemctl start ozayn-ml ozayn-ws ozayn-collab nginx
        ;;
    stop)
        check_root
        systemctl stop ozayn-ml ozayn-ws ozayn-collab
        ;;
    restart)
        check_root
        systemctl restart ozayn-ml ozayn-ws ozayn-collab nginx
        ;;
    status)
        systemctl status ozayn-ml ozayn-ws ozayn-collab nginx --no-pager
        ;;
    logs)
        journalctl -u ozayn-ml -u ozayn-ws -u ozayn-collab --no-pager -n 50
        ;;
    ssl)
        check_root
        setup_ssl
        ;;
    *)
        usage
        ;;
esac
