#!/bin/bash

# OpenWrt Build Environment Setup Script
# For educational router firmware development

set -e

echo "=== Educational Router Firmware Build Environment Setup ==="
echo "This will install OpenWrt build dependencies and tools"
echo ""

# Update system
echo "[*] Updating system packages..."
sudo apt-get update

# Install build dependencies
echo "[*] Installing build dependencies..."
sudo apt-get install -y \
    build-essential \
    libncurses5-dev \
    libncursesw5-dev \
    zlib1g-dev \
    gawk \
    git \
    gettext \
    libssl-dev \
    xsltproc \
    rsync \
    wget \
    unzip \
    python3 \
    python3-distutils \
    python3-setuptools \
    python3-dev \
    python3-pyelftools \
    subversion \
    swig \
    time \
    help2man \
    pkg-config \
    libelf-dev \
    ecj \
    fastjar \
    java-propose-classpath \
    ccache \
    libffi-dev \
    libpython3-dev \
    qemu-utils

# Additional tools for our custom modules
echo "[*] Installing additional development tools..."
sudo apt-get install -y \
    tcpdump \
    wireshark-common \
    tshark \
    libpcap-dev \
    libnetfilter-queue-dev \
    iptables-dev \
    libnfnetlink-dev \
    libmnl-dev \
    libnl-3-dev \
    libnl-genl-3-dev

# Create workspace
WORKSPACE_DIR="/workspace/router-lab-project"
cd "$WORKSPACE_DIR"

# Clone OpenWrt
echo "[*] Cloning OpenWrt source..."
if [ ! -d "openwrt" ]; then
    git clone https://github.com/openwrt/openwrt.git
    cd openwrt
    
    # Use a stable version
    echo "[*] Checking out stable version..."
    git checkout v23.05.2
    
    # Update feeds
    echo "[*] Updating and installing feeds..."
    ./scripts/feeds update -a
    ./scripts/feeds install -a
else
    echo "[!] OpenWrt directory already exists, skipping clone"
    cd openwrt
fi

echo ""
echo "=== Build environment setup complete ==="
echo "Next steps:"
echo "1. Run 'make menuconfig' to configure your build"
echo "2. Select your target device (TP-Link WR840N or Archer C7)"
echo "3. Run 'make' to build the firmware"
echo ""
echo "Project directory: $WORKSPACE_DIR/openwrt"