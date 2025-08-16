# C2 System Deployment Guide

## ⚠️ IMPORTANT DISCLAIMER
This system is for **EDUCATIONAL PURPOSES ONLY** in controlled lab environments.
- Only deploy on networks and devices you own
- Follow all local laws and regulations
- Use for learning network security, not exploitation

## Overview

This guide covers deploying a complete C2 (Command & Control) system for monitoring internal traffic from your Archer C7 router to an Ubuntu VPS.

## Architecture

```
[Archer C7 Router] <--WSS--> [Ubuntu VPS C2 Server]
      |                              |
   Internal                    Web Dashboard
   Network                    (HTTPS/443)
   Monitoring
```

## Prerequisites

- TP-Link Archer C7 router (or compatible)
- Ubuntu 20.04+ VPS with public IP
- Build environment for OpenWrt (15GB+ space)
- Basic Linux/networking knowledge

## Step 1: Build Custom Firmware

### 1.1 Set Up Build Environment

```bash
cd /workspace/router-lab-project
./scripts/setup_build_env.sh
```

### 1.2 Configure OpenWrt

```bash
./config/custom_openwrt_config.sh
```

### 1.3 Add C2 Client to Firmware

```bash
./config/add_c2_to_firmware.sh
```

### 1.4 Build Firmware

```bash
cd openwrt
./build-firmware.sh
```

This will take 30-60 minutes. The firmware will be in:
`openwrt/bin/targets/ath79/generic/openwrt-ath79-generic-tplink_archer-c7-v2-squashfs-factory.bin`

## Step 2: Deploy C2 Server on VPS

### 2.1 Transfer Files to VPS

```bash
# From your build machine
scp -r /workspace/router-lab-project/c2_server root@your-vps-ip:/tmp/
scp -r /workspace/router-lab-project/deployment root@your-vps-ip:/tmp/
```

### 2.2 Run VPS Deployment

SSH into your VPS and run:

```bash
cd /tmp
chmod +x deployment/deploy_vps.sh
sudo ./deployment/deploy_vps.sh
```

Follow the prompts:
- Enter your VPS public IP
- Optionally enter a domain name
- Note the generated auth key

### 2.3 Verify C2 Server

```bash
# Check service status
systemctl status c2-server

# View logs
journalctl -u c2-server -f

# Test dashboard
curl -k https://your-vps-ip/
```

## Step 3: Flash Router Firmware

### 3.1 Backup Current Settings

Access router web interface (usually 192.168.1.1):
- System → Backup/Flash Firmware → Generate archive

### 3.2 Flash Custom Firmware

**Method 1: Web Interface**
1. System → Backup/Flash Firmware
2. Flash new firmware image
3. Upload the .bin file
4. Uncheck "Keep settings"
5. Click "Flash image"

**Method 2: TFTP Recovery**
1. Set PC IP to 192.168.1.100/24
2. Start TFTP server with firmware
3. Hold reset while powering on router
4. Router will download and flash

### 3.3 Initial Router Setup

After flashing:
1. Connect to router (192.168.1.1)
2. Set root password
3. Configure network settings

## Step 4: Configure C2 Connection

### 4.1 SSH into Router

```bash
ssh root@192.168.1.1
```

### 4.2 Configure C2 Client

Run the configuration helper:

```bash
configure-c2
```

Enter:
- C2 server URL: `wss://your-vps-ip:8443`
- Auth key: (from VPS deployment)

Or manually edit:

```bash
vi /etc/config/c2-client

# Update these values:
ENABLED="1"
C2_SERVER="wss://your-vps-ip:8443"
C2_AUTH_KEY="your-auth-key"

# Start service
/etc/init.d/c2-client enable
/etc/init.d/c2-client start
```

### 4.3 Verify Connection

On router:
```bash
# Check service status
/etc/init.d/c2-client status

# View logs
logread | grep c2-client
tail -f /tmp/c2-client.log
```

On VPS:
```bash
# Check for connected client
journalctl -u c2-server | grep "connected"
```

## Step 5: Access Dashboard

### 5.1 Open Dashboard

Navigate to: `https://your-vps-ip/`

Features:
- Real-time traffic monitoring
- SSL/TLS interception logs
- DNS query analysis
- Remote command execution

### 5.2 Dashboard Usage

1. **Select Router**: Click on your router in sidebar
2. **View Traffic**: Click "Traffic" tab for real-time data
3. **SSL Intercepts**: View HTTPS connections
4. **Commands**: Execute remote commands

## Monitoring Features

### Traffic Analysis
- All internal network packets
- Source/destination IPs and ports
- Protocol identification
- Real-time streaming to dashboard

### SSL/TLS Interception
- HTTPS connection logging
- Certificate information
- Hostname tracking

### DNS Monitoring
- All DNS queries
- Detection of DNS tunneling
- Query type tracking

### Remote Control
- Execute system commands
- Service management
- Configuration updates
- Emergency wipe capability

## Security Considerations

### On VPS
- Firewall configured (ports 443, 8443)
- SSL/TLS encryption for all connections
- Authentication required
- Database stores all traffic data

### On Router
- All services run as root (required for packet capture)
- Logs stored in /tmp (RAM)
- Persistent configuration in /etc/config

### Best Practices
1. Use strong authentication keys
2. Regularly update VPS
3. Monitor VPS logs for unauthorized access
4. Limit dashboard access by IP if possible
5. Use VPN for additional security

## Troubleshooting

### C2 Client Won't Connect

1. Check network connectivity:
```bash
ping your-vps-ip
```

2. Verify configuration:
```bash
cat /etc/config/c2-client
```

3. Check firewall on VPS:
```bash
ufw status
```

4. Review logs:
```bash
# On router
tail -f /tmp/c2-client.log

# On VPS
journalctl -u c2-server -f
```

### No Traffic Data

1. Verify packet interceptor:
```bash
/etc/init.d/packet-interceptor status
pgrep -f tcpdump
```

2. Check iptables rules:
```bash
iptables -t raw -L
```

### Dashboard Not Loading

1. Check Nginx:
```bash
systemctl status nginx
nginx -t
```

2. Verify SSL certificates:
```bash
ls -la /etc/c2_server/*.pem
```

## Maintenance

### Regular Tasks
- Monitor disk space on VPS
- Rotate logs
- Update auth keys periodically
- Backup C2 database

### Updates
To update C2 server:
```bash
cd /opt/c2_server
git pull
systemctl restart c2-server
```

## Uninstallation

### Remove from Router
```bash
/etc/init.d/c2-client stop
/etc/init.d/c2-client disable
rm /etc/config/c2-client
```

### Remove from VPS
```bash
systemctl stop c2-server
systemctl disable c2-server
rm -rf /opt/c2_server
rm -rf /var/lib/c2_server
rm -rf /var/www/c2_dashboard
```

## Legal and Ethical Notes

This system demonstrates powerful capabilities that must be used responsibly:

1. **Consent**: Only monitor networks you own
2. **Privacy**: Respect user privacy
3. **Education**: Use for learning, not exploitation
4. **Compliance**: Follow all applicable laws
5. **Disclosure**: Be transparent about monitoring

## Conclusion

You now have a complete C2 system for educational network monitoring. Remember:
- This is for learning network security
- Always use ethically and legally
- Focus on defense, not offense
- Share knowledge responsibly

For questions or issues, review the source code and logs. This project is for educational purposes to understand network security concepts.