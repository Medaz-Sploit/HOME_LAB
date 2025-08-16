# Educational Router Firmware Setup Guide

## ⚠️ IMPORTANT DISCLAIMER ⚠️
This project is for **EDUCATIONAL PURPOSES ONLY** in a controlled home lab environment. 
- Only use on devices you own
- Never deploy on production networks
- Follow all local laws and regulations
- This is for learning about network security

## Overview

This guide walks through building custom OpenWrt firmware with advanced networking capabilities for security education and research.

## Prerequisites

- Ubuntu 20.04+ or Debian 11+ system
- At least 15GB free disk space
- 4GB+ RAM
- TP-Link Archer C7 or WR840N router (for testing)
- Basic Linux command line knowledge

## Quick Start

### 1. Set Up Build Environment

```bash
cd /workspace/router-lab-project
./scripts/setup_build_env.sh
```

This installs all required dependencies and clones OpenWrt source.

### 2. Configure OpenWrt

```bash
./config/custom_openwrt_config.sh
```

This sets up the custom modules and configurations.

### 3. Build Firmware

```bash
cd openwrt
./build-firmware.sh
```

First build takes 30-60 minutes. Subsequent builds are faster.

### 4. Flash Router

Find firmware in `openwrt/bin/targets/ath79/generic/`:
- Archer C7: `openwrt-ath79-generic-tplink_archer-c7-v2-squashfs-factory.bin`

Flash via web interface or TFTP recovery.

## Features

### 1. Packet Interception
- Captures all network traffic
- Logs to `/tmp/packet-interceptor.log`
- Uses netfilter queues for transparent interception

### 2. SSL/TLS Interception
- Educational MITM demonstration
- Generates certificates on-the-fly
- Logs connections to `/tmp/ssl-connections.json`

### 3. DNS Tunneling
- Covert channel demonstration
- Base32 encoding for DNS-safe transmission
- Configurable tunnel domain

### 4. Remote Control
- WebSocket-based command interface
- Encrypted authentication
- Port 9443 (WSS)

### 5. VPN Server
- OpenVPN for secure access
- Internal network connectivity
- Port 1194 (UDP)

## Configuration

### Network Settings
- LAN IP: 192.168.1.1/24
- VPN Network: 10.8.0.0/24

### Service Ports
- SSH: 22
- HTTP/HTTPS: 80/443 (LuCI)
- OpenVPN: 1194 (UDP)
- Remote Control: 9443 (TCP)

### Default Credentials
- Router: root (set on first login)
- LuCI: same as root password

## Module Usage

### Packet Interceptor

Start/stop via init script:
```bash
/etc/init.d/packet-interceptor start
/etc/init.d/packet-interceptor stop
```

View logs:
```bash
tail -f /tmp/packet-interceptor.log
```

### SSL Interceptor

Run manually:
```bash
python3 /usr/lib/ssl-interceptor.py
```

Install CA certificate on test devices:
```bash
cat /tmp/lab-ca.crt
```

### DNS Tunnel

Configure tunnel domain:
```bash
dns-tunnel tunnel.yourdomain.com
```

### Remote Control

Connect with client:
```python
from remote_control import RemoteControlClient

client = RemoteControlClient('wss://192.168.1.1:9443', auth_key)
result = await client.connect_and_execute('ip addr show')
```

## Security Considerations

1. **Isolation**: Always use in isolated lab network
2. **Legal**: Ensure compliance with local laws
3. **Ethics**: Only test on your own devices
4. **Documentation**: Keep logs of all testing

## Troubleshooting

### Build Errors

1. Check disk space: `df -h`
2. Clean build: `make clean`
3. Check dependencies: `./scripts/feeds update -a`

### Flash Issues

1. Use TFTP recovery mode
2. Serial console access (3.3V TTL)
3. Factory reset: hold reset 10 seconds

### Service Issues

Check logs:
```bash
logread | grep packet-interceptor
cat /tmp/ssl-interceptor.log
```

Restart services:
```bash
/etc/init.d/packet-interceptor restart
```

## Advanced Usage

### Custom Module Development

1. Create module in `/workspace/router-lab-project/modules/`
2. Add Makefile following OpenWrt package format
3. Update feeds: `./scripts/feeds update custom`

### Persistence Across Updates

Configuration preserved in:
- `/etc/config/`
- `/etc/openvpn/`

Backup before updates:
```bash
sysupgrade -b /tmp/backup.tar.gz
```

## Ethical Guidelines

This firmware demonstrates security concepts for education:

1. **Consent**: Always get permission before testing
2. **Scope**: Limit testing to your lab network
3. **Documentation**: Record all activities
4. **Responsible Disclosure**: Report vulnerabilities properly
5. **Learning**: Focus on defense, not offense

## Resources

- OpenWrt Documentation: https://openwrt.org/docs/start
- Network Security Fundamentals
- Ethical Hacking Guidelines
- Legal Compliance Resources

## Support

This is an educational project. For questions:
1. Review OpenWrt documentation
2. Check module source code
3. Examine log files
4. Test in isolated environment

Remember: With great power comes great responsibility. Use this knowledge to improve security, not compromise it.