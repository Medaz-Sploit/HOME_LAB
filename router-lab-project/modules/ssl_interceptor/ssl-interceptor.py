#!/usr/bin/env python3
"""
Educational SSL/TLS Interceptor
For lab environments only - demonstrates MITM concepts
"""

import ssl
import socket
import threading
import os
import sys
import logging
import json
from datetime import datetime, timedelta
import subprocess
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time

class SSLInterceptor:
    def __init__(self, listen_port=8443, target_port=443):
        self.listen_port = listen_port
        self.target_port = target_port
        self.ca_cert = None
        self.ca_key = None
        self.cert_cache = {}
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/tmp/ssl-interceptor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def generate_ca(self):
        """Generate a CA certificate for signing intercepted connections"""
        self.logger.info("Generating CA certificate...")
        
        # Generate CA private key
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lab"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Educational"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lab CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Educational Lab CA"),
        ])
        
        self.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(self.ca_key, hashes.SHA256())
        
        # Save CA cert and key
        with open("/tmp/lab-ca.crt", "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        
        with open("/tmp/lab-ca.key", "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        self.logger.info("CA certificate generated and saved")
        
    def generate_cert_for_host(self, hostname):
        """Generate a certificate for a specific hostname"""
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]
            
        self.logger.info(f"Generating certificate for {hostname}")
        
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lab"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Educational"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, hostname),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=90)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
            ]),
            critical=False
        ).sign(self.ca_key, hashes.SHA256())
        
        self.cert_cache[hostname] = (cert, key)
        return cert, key
        
    def handle_client(self, client_socket, client_address):
        """Handle incoming client connection"""
        try:
            # Get the SNI hostname from the client hello
            raw_data = client_socket.recv(1024, socket.MSG_PEEK)
            hostname = self.extract_sni(raw_data)
            
            if not hostname:
                hostname = "unknown.local"
                
            self.logger.info(f"Intercepting connection to {hostname}")
            
            # Generate certificate for this host
            cert, key = self.generate_cert_for_host(hostname)
            
            # Create SSL context for client
            client_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Save temporary cert and key
            cert_path = f"/tmp/{hostname}.crt"
            key_path = f"/tmp/{hostname}.key"
            
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                
            client_context.load_cert_chain(cert_path, key_path)
            
            # Wrap client socket with SSL
            client_ssl_socket = client_context.wrap_socket(
                client_socket, server_side=True
            )
            
            # Connect to real server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((hostname, self.target_port))
            
            # Create SSL context for server connection
            server_context = ssl.create_default_context()
            server_context.check_hostname = False
            server_context.verify_mode = ssl.CERT_NONE
            
            server_ssl_socket = server_context.wrap_socket(
                server_socket, server_hostname=hostname
            )
            
            # Log connection details
            self.log_connection(hostname, client_address)
            
            # Relay data between client and server
            self.relay_data(client_ssl_socket, server_ssl_socket, hostname)
            
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
        finally:
            client_socket.close()
            
    def extract_sni(self, data):
        """Extract SNI hostname from TLS Client Hello"""
        # This is a simplified SNI extraction
        # In production, use a proper TLS parser
        try:
            if len(data) > 43:
                # Look for server_name extension
                pos = 43
                while pos < len(data) - 5:
                    if data[pos:pos+2] == b'\x00\x00':  # server_name extension
                        # Extract hostname
                        name_len = int.from_bytes(data[pos+7:pos+9], 'big')
                        hostname = data[pos+9:pos+9+name_len].decode('utf-8')
                        return hostname
                    pos += 1
        except:
            pass
        return None
        
    def relay_data(self, client_socket, server_socket, hostname):
        """Relay data between client and server while logging"""
        def forward(src, dst, direction):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    
                    # Log data for educational purposes
                    self.log_traffic(hostname, direction, data)
                    
                    dst.send(data)
            except:
                pass
            finally:
                src.close()
                dst.close()
                
        # Create threads for bidirectional communication
        client_to_server = threading.Thread(
            target=forward, 
            args=(client_socket, server_socket, "C->S")
        )
        server_to_client = threading.Thread(
            target=forward,
            args=(server_socket, client_socket, "S->C")
        )
        
        client_to_server.start()
        server_to_client.start()
        
        client_to_server.join()
        server_to_client.join()
        
    def log_connection(self, hostname, client_address):
        """Log connection details"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "client": f"{client_address[0]}:{client_address[1]}",
            "event": "connection"
        }
        
        with open("/tmp/ssl-connections.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
            
    def log_traffic(self, hostname, direction, data):
        """Log traffic data (first 100 bytes for demo)"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "direction": direction,
            "size": len(data),
            "preview": data[:100].hex() if len(data) > 0 else ""
        }
        
        with open("/tmp/ssl-traffic.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
            
    def start(self):
        """Start the SSL interceptor"""
        self.logger.info(f"Starting SSL interceptor on port {self.listen_port}")
        
        # Generate CA if needed
        self.generate_ca()
        
        # Create listening socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.listen_port))
        server_socket.listen(5)
        
        self.logger.info("SSL interceptor ready")
        
        try:
            while True:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.start()
        except KeyboardInterrupt:
            self.logger.info("Shutting down SSL interceptor")
        finally:
            server_socket.close()

if __name__ == "__main__":
    # Educational SSL interceptor for lab use only
    interceptor = SSLInterceptor()
    interceptor.start()