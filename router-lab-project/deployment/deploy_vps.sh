#!/bin/bash

# VPS C2 Server Deployment Script
# For Ubuntu 20.04+ VPS

set -e

echo "=== C2 Server Deployment for Educational Router Monitoring ==="
echo "⚠️  For educational purposes only!"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Configuration
C2_USER="c2server"
C2_DIR="/opt/c2_server"
WEB_DIR="/var/www/c2_dashboard"
SSL_DIR="/etc/c2_server"

# Get VPS IP and domain
read -p "Enter your VPS public IP address: " VPS_IP
read -p "Enter domain name (optional, press enter to skip): " DOMAIN_NAME
read -p "Enter authentication key (leave blank for random): " AUTH_KEY

if [ -z "$AUTH_KEY" ]; then
    AUTH_KEY=$(openssl rand -hex 32)
fi

echo ""
echo "Installing with:"
echo "  VPS IP: $VPS_IP"
echo "  Domain: ${DOMAIN_NAME:-none}"
echo "  Auth Key: $AUTH_KEY"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Update system
echo "[*] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install dependencies
echo "[*] Installing dependencies..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    certbot \
    python3-certbot-nginx \
    sqlite3 \
    supervisor \
    ufw

# Create user
echo "[*] Creating service user..."
if ! id -u $C2_USER > /dev/null 2>&1; then
    useradd -r -s /bin/false -m -d /var/lib/$C2_USER $C2_USER
fi

# Create directories
echo "[*] Creating directories..."
mkdir -p $C2_DIR
mkdir -p $WEB_DIR/static
mkdir -p $SSL_DIR
mkdir -p /var/lib/c2_server
mkdir -p /var/log/c2_server

# Copy files
echo "[*] Copying C2 server files..."
cp /workspace/router-lab-project/c2_server/c2_server.py $C2_DIR/
cp /workspace/router-lab-project/c2_server/dashboard/index.html $WEB_DIR/

# Create Python virtual environment
echo "[*] Setting up Python environment..."
cd $C2_DIR
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install \
    websockets \
    aiohttp \
    aiohttp-cors \
    cryptography

# Generate SSL certificates
echo "[*] Generating SSL certificates..."
if [ -n "$DOMAIN_NAME" ]; then
    # Use Let's Encrypt for domain
    certbot certonly --standalone -d $DOMAIN_NAME --non-interactive --agree-tos --email admin@$DOMAIN_NAME
    ln -sf /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem $SSL_DIR/cert.pem
    ln -sf /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem $SSL_DIR/key.pem
else
    # Self-signed certificate for IP
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout $SSL_DIR/key.pem \
        -out $SSL_DIR/cert.pem \
        -subj "/C=US/ST=Lab/L=Educational/O=C2Server/CN=$VPS_IP"
fi

# Configure environment
echo "[*] Creating environment configuration..."
cat > /etc/c2_server/config.env << EOF
C2_WS_PORT=8443
C2_WEB_PORT=8080
C2_DB_PATH=/var/lib/c2_server/c2.db
C2_SSL_CERT=$SSL_DIR/cert.pem
C2_SSL_KEY=$SSL_DIR/key.pem
C2_AUTH_KEY=$AUTH_KEY
EOF

# Create systemd service
echo "[*] Creating systemd service..."
cat > /etc/systemd/system/c2-server.service << EOF
[Unit]
Description=C2 Server for Educational Router Monitoring
After=network.target

[Service]
Type=simple
User=$C2_USER
Group=$C2_USER
WorkingDirectory=$C2_DIR
EnvironmentFile=/etc/c2_server/config.env
ExecStart=$C2_DIR/venv/bin/python $C2_DIR/c2_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
echo "[*] Configuring Nginx..."
cat > /etc/nginx/sites-available/c2-dashboard << EOF
server {
    listen 80;
    server_name ${DOMAIN_NAME:-$VPS_IP};

    # Redirect HTTP to HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${DOMAIN_NAME:-$VPS_IP};

    ssl_certificate $SSL_DIR/cert.pem;
    ssl_certificate_key $SSL_DIR/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /ws/ {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
EOF

ln -sf /etc/nginx/sites-available/c2-dashboard /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Configure firewall
echo "[*] Configuring firewall..."
ufw --force enable
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/tcp

# Set permissions
echo "[*] Setting permissions..."
chown -R $C2_USER:$C2_USER $C2_DIR
chown -R $C2_USER:$C2_USER /var/lib/c2_server
chown -R $C2_USER:$C2_USER /var/log/c2_server
chown -R www-data:www-data $WEB_DIR
chmod 600 $SSL_DIR/*.pem
chmod 600 /etc/c2_server/config.env

# Enable and start services
echo "[*] Starting services..."
systemctl daemon-reload
systemctl enable c2-server
systemctl start c2-server
systemctl restart nginx

# Create client configuration
echo "[*] Creating router client configuration..."
cat > /root/router_config.txt << EOF
# Router C2 Client Configuration
# Add these to your router's environment

export C2_SERVER="wss://$VPS_IP:8443"
export C2_AUTH_KEY="$AUTH_KEY"

# For router startup script:
/usr/bin/python3 /usr/lib/c2-client.py &
EOF

# Status check
echo ""
echo "=== Deployment Complete ==="
echo ""
echo "C2 Server Status:"
systemctl status c2-server --no-pager

echo ""
echo "Dashboard URL: https://${DOMAIN_NAME:-$VPS_IP}/"
echo "WebSocket URL: wss://${DOMAIN_NAME:-$VPS_IP}:8443"
echo ""
echo "Router configuration saved to: /root/router_config.txt"
echo ""
echo "To view logs:"
echo "  journalctl -u c2-server -f"
echo "  tail -f /var/log/c2_server/c2_server.log"
echo ""
echo "⚠️  Remember: This is for educational purposes only!"