#!/bin/bash

# Script to add C2 client to OpenWrt firmware
# Run this after custom_openwrt_config.sh

set -e

OPENWRT_DIR="/workspace/router-lab-project/openwrt"
MODULES_DIR="/workspace/router-lab-project/modules"

echo "=== Adding C2 Client to Firmware ==="

# Create C2 client package directory
C2_PKG_DIR="$MODULES_DIR/c2-client"
mkdir -p "$C2_PKG_DIR/files"

# Create Makefile for C2 client package
cat > "$C2_PKG_DIR/Makefile" << 'EOF'
include $(TOPDIR)/rules.mk

PKG_NAME:=c2-client
PKG_VERSION:=1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/c2-client
  SECTION:=net
  CATEGORY:=Network
  TITLE:=C2 Client for Router Monitoring
  DEPENDS:=+python3 +python3-asyncio +python3-websockets +python3-logging +tcpdump
endef

define Package/c2-client/description
  C2 client for educational router traffic monitoring
endef

define Package/c2-client/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) ./files/c2-client.py $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/c2-client.init $(1)/etc/init.d/c2-client
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/c2-client.config $(1)/etc/config/c2-client
endef

$(eval $(call BuildPackage,c2-client))
EOF

# Copy C2 client script
cp "$MODULES_DIR/c2_client/c2-client.py" "$C2_PKG_DIR/files/"

# Create init script
cat > "$C2_PKG_DIR/files/c2-client.init" << 'EOF'
#!/bin/sh /etc/rc.common

START=99
STOP=10

USE_PROCD=1
PROG=/usr/bin/python3

start_service() {
    # Load configuration
    . /etc/config/c2-client
    
    # Check if enabled
    [ "$ENABLED" != "1" ] && return 0
    
    # Export environment variables
    export C2_SERVER="$C2_SERVER"
    export C2_AUTH_KEY="$C2_AUTH_KEY"
    
    procd_open_instance
    procd_set_param command $PROG /usr/lib/c2-client.py
    procd_set_param respawn
    procd_set_param stderr 1
    procd_set_param pidfile /var/run/c2-client.pid
    procd_close_instance
}

stop_service() {
    killall -9 c2-client.py 2>/dev/null
}
EOF

chmod +x "$C2_PKG_DIR/files/c2-client.init"

# Create default configuration
cat > "$C2_PKG_DIR/files/c2-client.config" << 'EOF'
# C2 Client Configuration
# Update these values after deployment

ENABLED="0"
C2_SERVER="wss://your-vps-ip:8443"
C2_AUTH_KEY="your-auth-key"
EOF

# Update OpenWrt configuration to include C2 client
cd "$OPENWRT_DIR"

# Add C2 client to config
cat >> "$OPENWRT_DIR/.config" << 'EOF'

# C2 Client
CONFIG_PACKAGE_c2-client=y
CONFIG_PACKAGE_python3-websockets=y
EOF

# Create post-flash configuration script
cat > "$OPENWRT_DIR/files/etc/uci-defaults/98-c2-client" << 'EOF'
#!/bin/sh

# C2 Client Auto-Configuration
# This runs on first boot after flashing

# Create marker file
touch /etc/c2_configured

# Note: Update /etc/config/c2-client with your VPS details
# Then run: /etc/init.d/c2-client enable && /etc/init.d/c2-client start

exit 0
EOF

chmod +x "$OPENWRT_DIR/files/etc/uci-defaults/98-c2-client"

# Add startup delay for C2 client
cat > "$OPENWRT_DIR/files/etc/rc.local" << 'EOF'
#!/bin/sh

# Wait for network to be ready
sleep 30

# Start C2 client if configured
if [ -f /etc/config/c2-client ] && [ -f /etc/c2_configured ]; then
    . /etc/config/c2-client
    if [ "$ENABLED" = "1" ]; then
        /etc/init.d/c2-client start
    fi
fi

exit 0
EOF

chmod +x "$OPENWRT_DIR/files/etc/rc.local"

# Create helper script for router configuration
cat > "$OPENWRT_DIR/files/usr/bin/configure-c2" << 'EOF'
#!/bin/sh

echo "=== C2 Client Configuration ==="
echo ""

read -p "Enter C2 server URL (wss://your-vps:8443): " C2_SERVER
read -p "Enter authentication key: " C2_AUTH_KEY

# Update configuration
cat > /etc/config/c2-client << EOC
ENABLED="1"
C2_SERVER="$C2_SERVER"
C2_AUTH_KEY="$C2_AUTH_KEY"
EOC

echo ""
echo "Configuration saved. Starting C2 client..."

/etc/init.d/c2-client enable
/etc/init.d/c2-client start

echo "C2 client started. Check status with: /etc/init.d/c2-client status"
EOF

chmod +x "$OPENWRT_DIR/files/usr/bin/configure-c2"

echo ""
echo "=== C2 Client Added to Firmware ==="
echo ""
echo "After flashing the router:"
echo "1. SSH into the router"
echo "2. Run: configure-c2"
echo "3. Enter your VPS details"
echo ""
echo "Or manually edit /etc/config/c2-client and restart the service"
echo ""
echo "Now run './build-firmware.sh' in the OpenWrt directory to build the firmware"