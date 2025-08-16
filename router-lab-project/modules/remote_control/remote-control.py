#!/usr/bin/env python3
"""
Educational Remote Control Module
For lab environment management and demonstration only
"""

import asyncio
import websockets
import json
import subprocess
import os
import sys
import hashlib
import hmac
import time
import logging
from cryptography.fernet import Fernet
import base64
import signal

class RemoteControlServer:
    def __init__(self, port=9443, auth_key=None):
        self.port = port
        self.auth_key = auth_key or os.urandom(32)
        self.cipher = Fernet(base64.urlsafe_b64encode(self.auth_key[:32]))
        self.sessions = {}
        self.running = True
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/tmp/remote-control.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def authenticate(self, auth_token):
        """Verify authentication token"""
        try:
            # Decrypt and verify token
            decrypted = self.cipher.decrypt(auth_token.encode())
            data = json.loads(decrypted)
            
            # Check timestamp (prevent replay attacks)
            if abs(time.time() - data.get('timestamp', 0)) > 300:  # 5 min window
                return False
                
            # Verify HMAC
            expected_hmac = hmac.new(
                self.auth_key,
                f"{data['user']}:{data['timestamp']}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            return data.get('hmac') == expected_hmac
            
        except Exception as e:
            self.logger.warning(f"Authentication failed: {e}")
            return False
            
    async def handle_command(self, websocket, command_data):
        """Execute command and return result"""
        command = command_data.get('command')
        cmd_type = command_data.get('type', 'system')
        
        self.logger.info(f"Executing command: {cmd_type} - {command}")
        
        result = {
            'success': False,
            'output': '',
            'error': ''
        }
        
        try:
            if cmd_type == 'system':
                # System command execution
                proc = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                result['success'] = proc.returncode == 0
                result['output'] = proc.stdout
                result['error'] = proc.stderr
                
            elif cmd_type == 'packet_capture':
                # Start/stop packet capture
                if command == 'start':
                    subprocess.Popen(['tcpdump', '-i', 'any', '-w', '/tmp/capture.pcap'])
                    result['success'] = True
                    result['output'] = 'Packet capture started'
                elif command == 'stop':
                    subprocess.run(['killall', 'tcpdump'])
                    result['success'] = True
                    result['output'] = 'Packet capture stopped'
                    
            elif cmd_type == 'network_info':
                # Get network information
                commands = [
                    'ip addr show',
                    'ip route show',
                    'netstat -tuln',
                    'iptables -L -n -v'
                ]
                output = []
                for cmd in commands:
                    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    output.append(f"=== {cmd} ===\n{proc.stdout}\n")
                result['success'] = True
                result['output'] = '\n'.join(output)
                
            elif cmd_type == 'update_config':
                # Update configuration
                config_file = command_data.get('file')
                config_data = command_data.get('data')
                
                if config_file and config_data:
                    # Validate path (prevent directory traversal)
                    if '..' not in config_file and config_file.startswith('/etc/'):
                        with open(config_file, 'w') as f:
                            f.write(config_data)
                        result['success'] = True
                        result['output'] = f'Configuration updated: {config_file}'
                    else:
                        result['error'] = 'Invalid configuration file path'
                        
            elif cmd_type == 'self_test':
                # Run self-diagnostic tests
                tests = []
                
                # Check services
                services = ['packet-interceptor', 'ssl-interceptor', 'dns-tunnel']
                for service in services:
                    proc = subprocess.run(
                        f'pgrep -f {service}',
                        shell=True,
                        capture_output=True
                    )
                    status = 'running' if proc.returncode == 0 else 'stopped'
                    tests.append(f"{service}: {status}")
                    
                # Check disk space
                proc = subprocess.run('df -h /', shell=True, capture_output=True, text=True)
                tests.append(f"Disk space:\n{proc.stdout}")
                
                # Check memory
                proc = subprocess.run('free -h', shell=True, capture_output=True, text=True)
                tests.append(f"Memory:\n{proc.stdout}")
                
                result['success'] = True
                result['output'] = '\n'.join(tests)
                
            elif cmd_type == 'emergency_wipe':
                # Emergency data wipe (educational demonstration only)
                self.logger.warning("EMERGENCY WIPE REQUESTED")
                
                # Clear logs
                log_files = [
                    '/tmp/packet-interceptor.log',
                    '/tmp/ssl-interceptor.log',
                    '/tmp/ssl-connections.json',
                    '/tmp/ssl-traffic.json',
                    '/tmp/remote-control.log'
                ]
                
                for log_file in log_files:
                    if os.path.exists(log_file):
                        os.remove(log_file)
                        
                # Stop services
                subprocess.run('killall packet-interceptor ssl-interceptor dns-tunnel', shell=True)
                
                result['success'] = True
                result['output'] = 'Emergency wipe completed'
                
        except subprocess.TimeoutExpired:
            result['error'] = 'Command timed out'
        except Exception as e:
            result['error'] = str(e)
            
        return result
        
    async def handle_client(self, websocket, path):
        """Handle WebSocket client connection"""
        client_addr = websocket.remote_address
        self.logger.info(f"New connection from {client_addr}")
        
        try:
            # Authentication
            auth_msg = await websocket.recv()
            auth_data = json.loads(auth_msg)
            
            if not self.authenticate(auth_data.get('token', '')):
                await websocket.send(json.dumps({
                    'error': 'Authentication failed'
                }))
                return
                
            # Session established
            session_id = hashlib.sha256(os.urandom(32)).hexdigest()
            self.sessions[session_id] = {
                'websocket': websocket,
                'address': client_addr,
                'authenticated': True
            }
            
            await websocket.send(json.dumps({
                'status': 'authenticated',
                'session_id': session_id
            }))
            
            # Command loop
            async for message in websocket:
                try:
                    command_data = json.loads(message)
                    
                    # Verify session
                    if command_data.get('session_id') != session_id:
                        await websocket.send(json.dumps({
                            'error': 'Invalid session'
                        }))
                        continue
                        
                    # Execute command
                    result = await self.handle_command(websocket, command_data)
                    
                    # Send result
                    await websocket.send(json.dumps(result))
                    
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({
                        'error': 'Invalid command format'
                    }))
                    
        except websockets.exceptions.ConnectionClosed:
            self.logger.info(f"Connection closed from {client_addr}")
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
        finally:
            # Clean up session
            if session_id in self.sessions:
                del self.sessions[session_id]
                
    async def start_server(self):
        """Start the WebSocket server"""
        self.logger.info(f"Starting remote control server on port {self.port}")
        
        # Generate SSL context for WSS
        ssl_context = None
        try:
            import ssl
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            
            # Use the lab CA certificate
            if os.path.exists('/tmp/lab-ca.crt') and os.path.exists('/tmp/lab-ca.key'):
                ssl_context.load_cert_chain('/tmp/lab-ca.crt', '/tmp/lab-ca.key')
        except:
            self.logger.warning("SSL not available, using unencrypted WebSocket")
            
        async with websockets.serve(
            self.handle_client,
            '0.0.0.0',
            self.port,
            ssl=ssl_context
        ):
            self.logger.info("Remote control server ready")
            await asyncio.Future()  # Run forever
            
    def run(self):
        """Run the server"""
        try:
            asyncio.run(self.start_server())
        except KeyboardInterrupt:
            self.logger.info("Server shutdown requested")
            
            
class RemoteControlClient:
    """Example client for testing"""
    
    def __init__(self, server_url, auth_key):
        self.server_url = server_url
        self.auth_key = auth_key
        self.cipher = Fernet(base64.urlsafe_b64encode(auth_key[:32]))
        
    def generate_auth_token(self, username='admin'):
        """Generate authentication token"""
        timestamp = time.time()
        auth_hmac = hmac.new(
            self.auth_key,
            f"{username}:{timestamp}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        auth_data = {
            'user': username,
            'timestamp': timestamp,
            'hmac': auth_hmac
        }
        
        return self.cipher.encrypt(json.dumps(auth_data).encode()).decode()
        
    async def connect_and_execute(self, command, cmd_type='system'):
        """Connect to server and execute command"""
        async with websockets.connect(self.server_url) as websocket:
            # Authenticate
            auth_token = self.generate_auth_token()
            await websocket.send(json.dumps({'token': auth_token}))
            
            # Get authentication response
            response = await websocket.recv()
            auth_response = json.loads(response)
            
            if 'error' in auth_response:
                print(f"Authentication failed: {auth_response['error']}")
                return
                
            session_id = auth_response['session_id']
            print(f"Authenticated with session: {session_id}")
            
            # Send command
            command_data = {
                'session_id': session_id,
                'command': command,
                'type': cmd_type
            }
            
            await websocket.send(json.dumps(command_data))
            
            # Get result
            result = await websocket.recv()
            return json.loads(result)


if __name__ == "__main__":
    # Start server
    server = RemoteControlServer()
    server.run()