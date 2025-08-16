#!/bin/bash

# Custom OpenWrt Configuration Script
# For educational router firmware build

set -e

OPENWRT_DIR="/workspace/router-lab-project/openwrt"
CUSTOM_FEEDS_DIR="/workspace/router-lab-project/feeds"

echo "=== Configuring OpenWrt for Educational Router Firmware ==="

# Create custom feed for our modules
mkdir -p "$CUSTOM_FEEDS_DIR"

# Create feeds configuration
cat > "$OPENWRT_DIR/feeds.conf" << EOF
src-git packages https://github.com/openwrt/packages.git
src-git luci https://github.com/openwrt/luci.git
src-git routing https://github.com/openwrt/routing.git
src-link custom $CUSTOM_FEEDS_DIR
EOF

# Copy our custom modules to feeds
cp -r /workspace/router-lab-project/modules/* "$CUSTOM_FEEDS_DIR/"

# Update feeds
cd "$OPENWRT_DIR"
./scripts/feeds update -a
./scripts/feeds install -a

# Create custom configuration for TP-Link routers
cat > "$OPENWRT_DIR/.config" << 'EOF'
# Target System
CONFIG_TARGET_ath79=y
CONFIG_TARGET_ath79_generic=y
CONFIG_TARGET_ath79_generic_DEVICE_tplink_archer-c7-v2=y

# Target Images
CONFIG_TARGET_ROOTFS_SQUASHFS=y
CONFIG_TARGET_ROOTFS_TARGZ=y

# Global build settings
CONFIG_SIGNED_PACKAGES=n
CONFIG_BUILD_PATENTED=y
CONFIG_SHADOW_PASSWORDS=y

# Base system
CONFIG_PACKAGE_base-files=y
CONFIG_PACKAGE_busybox=y
CONFIG_PACKAGE_dropbear=y

# Kernel modules
CONFIG_PACKAGE_kmod-usb-core=y
CONFIG_PACKAGE_kmod-usb2=y
CONFIG_PACKAGE_kmod-usb-storage=y
CONFIG_PACKAGE_kmod-fs-ext4=y
CONFIG_PACKAGE_kmod-nfnetlink=y
CONFIG_PACKAGE_kmod-nfnetlink-queue=y
CONFIG_PACKAGE_kmod-nf-conntrack-netlink=y

# Network tools
CONFIG_PACKAGE_iptables=y
CONFIG_PACKAGE_iptables-mod-nfqueue=y
CONFIG_PACKAGE_iptables-mod-conntrack-extra=y
CONFIG_PACKAGE_iptables-mod-filter=y
CONFIG_PACKAGE_tcpdump=y
CONFIG_PACKAGE_netcat=y

# Libraries
CONFIG_PACKAGE_libpcap=y
CONFIG_PACKAGE_libnetfilter-queue=y
CONFIG_PACKAGE_libnfnetlink=y
CONFIG_PACKAGE_libmnl=y
CONFIG_PACKAGE_libopenssl=y
CONFIG_PACKAGE_libpthread=y

# Python for SSL interceptor
CONFIG_PACKAGE_python3=y
CONFIG_PACKAGE_python3-asyncio=y
CONFIG_PACKAGE_python3-cryptography=y
CONFIG_PACKAGE_python3-openssl=y
CONFIG_PACKAGE_python3-websockets=y

# VPN
CONFIG_PACKAGE_openvpn-openssl=y
CONFIG_PACKAGE_openvpn-easy-rsa=y

# LuCI Web Interface
CONFIG_PACKAGE_luci=y
CONFIG_PACKAGE_luci-ssl-openssl=y
CONFIG_PACKAGE_luci-app-openvpn=y
CONFIG_PACKAGE_luci-app-firewall=y

# Custom packages
CONFIG_PACKAGE_packet-interceptor=y

# Additional utilities
CONFIG_PACKAGE_htop=y
CONFIG_PACKAGE_nano=y
CONFIG_PACKAGE_screen=y
CONFIG_PACKAGE_rsync=y
CONFIG_PACKAGE_wget=y
CONFIG_PACKAGE_curl=y

# Filesystem
CONFIG_PACKAGE_block-mount=y
CONFIG_PACKAGE_e2fsprogs=y

# USB support
CONFIG_PACKAGE_kmod-usb-storage-uas=y
CONFIG_PACKAGE_usbutils=y

# Development tools (for on-device compilation)
CONFIG_PACKAGE_gcc=y
CONFIG_PACKAGE_make=y

# Enable all busybox applets
CONFIG_BUSYBOX_CUSTOM=y
CONFIG_BUSYBOX_CONFIG_FEATURE_EDITING=y
CONFIG_BUSYBOX_CONFIG_FEATURE_EDITING_SAVEHISTORY=y
CONFIG_BUSYBOX_CONFIG_FEATURE_EDITING_SAVE_ON_EXIT=y
CONFIG_BUSYBOX_CONFIG_FEATURE_LESS_FLAGS=y
CONFIG_BUSYBOX_CONFIG_FEATURE_LESS_MARKS=y
CONFIG_BUSYBOX_CONFIG_FEATURE_LESS_REGEXP=y
EOF

# Create startup script for our custom services
cat > "$CUSTOM_FEEDS_DIR/packet-interceptor/files/packet-interceptor.init" << 'EOF'
#!/bin/sh /etc/rc.common

START=95
STOP=10

USE_PROCD=1
PROG=/usr/sbin/packet-interceptor

start_service() {
    # Set up iptables rules for packet interception
    iptables -t raw -A PREROUTING -j NFQUEUE --queue-num 0
    iptables -t raw -A OUTPUT -j NFQUEUE --queue-num 0
    
    procd_open_instance
    procd_set_param command $PROG
    procd_set_param respawn
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    # Clean up iptables rules
    iptables -t raw -D PREROUTING -j NFQUEUE --queue-num 0 2>/dev/null
    iptables -t raw -D OUTPUT -j NFQUEUE --queue-num 0 2>/dev/null
}
EOF

chmod +x "$CUSTOM_FEEDS_DIR/packet-interceptor/files/packet-interceptor.init"

# Create configuration file
cat > "$CUSTOM_FEEDS_DIR/packet-interceptor/files/packet-interceptor.config" << 'EOF'
config interceptor 'main'
    option enabled '1'
    option interface 'br-lan'
    option log_file '/tmp/packet-interceptor.log'
    option log_level 'info'
EOF

# Create custom sysupgrade script for persistence
cat > "$OPENWRT_DIR/target/linux/ath79/base-files/lib/upgrade/platform.sh" << 'EOF'
#!/bin/sh

PART_NAME=firmware
REQUIRE_IMAGE_METADATA=1

platform_check_image() {
    return 0
}

platform_do_upgrade() {
    local board=$(board_name)
    
    case "$board" in
    tplink,archer-c7-v2|\
    tplink,tl-wr840n-v2)
        default_do_upgrade "$1"
        ;;
    *)
        echo "Unsupported board: $board"
        return 1
        ;;
    esac
}

# Custom persistence hook
platform_copy_config() {
    local board=$(board_name)
    
    # Save custom configuration
    mkdir -p /tmp/sysupgrade-config
    cp -r /etc/config/* /tmp/sysupgrade-config/
    cp /etc/openvpn/* /tmp/sysupgrade-config/ 2>/dev/null || true
}
EOF

# Create custom UCI defaults
mkdir -p "$OPENWRT_DIR/files/etc/uci-defaults"
cat > "$OPENWRT_DIR/files/etc/uci-defaults/99-custom-settings" << 'EOF'
#!/bin/sh

# Set up network configuration
uci set network.lan.ipaddr='192.168.1.1'
uci set network.lan.netmask='255.255.255.0'
uci commit network

# Configure firewall for VPN
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-OpenVPN'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='1194'
uci set firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].target='ACCEPT'

# Configure firewall for remote control
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-RemoteControl'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='9443'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'

uci commit firewall

# Enable services
/etc/init.d/packet-interceptor enable
/etc/init.d/openvpn enable

# Create directories
mkdir -p /etc/openvpn
mkdir -p /var/log

exit 0
EOF

chmod +x "$OPENWRT_DIR/files/etc/uci-defaults/99-custom-settings"

# Create build script
cat > "$OPENWRT_DIR/build-firmware.sh" << 'EOF'
#!/bin/bash

echo "Building educational router firmware..."
echo "This will take 30-60 minutes on first build"

# Clean previous builds
make clean

# Download sources
make download

# Build with parallel jobs
make -j$(nproc) V=s

if [ $? -eq 0 ]; then
    echo ""
    echo "=== Build Complete ==="
    echo "Firmware images are in: bin/targets/ath79/generic/"
    echo ""
    echo "For Archer C7 v2: openwrt-ath79-generic-tplink_archer-c7-v2-squashfs-*.bin"
    echo ""
    echo "Flash using:"
    echo "1. Web interface: System -> Backup/Flash Firmware"
    echo "2. TFTP recovery mode"
    echo "3. Serial console + TFTP"
else
    echo "Build failed! Check the error messages above."
fi
EOF

chmod +x "$OPENWRT_DIR/build-firmware.sh"

echo ""
echo "=== Configuration Complete ==="
echo "Next steps:"
echo "1. cd $OPENWRT_DIR"
echo "2. Run 'make menuconfig' to review/modify configuration"
echo "3. Run './build-firmware.sh' to build the firmware"
echo ""
echo "Note: First build will download ~500MB of sources and take 30-60 minutes"