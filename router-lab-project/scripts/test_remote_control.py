#!/usr/bin/env python3
"""
Test client for Educational Remote Control Interface
Demonstrates secure communication with the router
"""

import asyncio
import sys
import os
import json
import argparse

# Add parent directory to path to import the module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.remote_control.remote_control import RemoteControlClient

async def test_commands(server_url, auth_key):
    """Test various remote control commands"""
    
    client = RemoteControlClient(server_url, auth_key)
    
    print(f"Connecting to {server_url}...")
    
    # Test 1: System information
    print("\n[1] Getting system information...")
    result = await client.connect_and_execute('uname -a', 'system')
    if result['success']:
        print(f"System: {result['output']}")
    else:
        print(f"Error: {result['error']}")
    
    # Test 2: Network information
    print("\n[2] Getting network information...")
    result = await client.connect_and_execute('', 'network_info')
    if result['success']:
        print("Network configuration retrieved")
        print(result['output'][:500] + "..." if len(result['output']) > 500 else result['output'])
    
    # Test 3: Self test
    print("\n[3] Running self-diagnostic test...")
    result = await client.connect_and_execute('', 'self_test')
    if result['success']:
        print("Self-test results:")
        print(result['output'])
    
    # Test 4: Packet capture control
    print("\n[4] Starting packet capture...")
    result = await client.connect_and_execute('start', 'packet_capture')
    if result['success']:
        print("Packet capture started")
        await asyncio.sleep(2)
        
        # Stop capture
        result = await client.connect_and_execute('stop', 'packet_capture')
        if result['success']:
            print("Packet capture stopped")

def generate_test_auth_key():
    """Generate a test authentication key"""
    import hashlib
    # This is just for testing - in production use secure key generation
    return hashlib.sha256(b"educational-test-key").digest()

async def interactive_mode(server_url, auth_key):
    """Interactive command mode"""
    client = RemoteControlClient(server_url, auth_key)
    
    print("Educational Router Remote Control - Interactive Mode")
    print("Type 'help' for available commands, 'exit' to quit")
    print("-" * 50)
    
    commands = {
        'help': 'Show this help message',
        'sysinfo': 'Get system information',
        'netinfo': 'Get network configuration',
        'selftest': 'Run self-diagnostic tests',
        'capture start': 'Start packet capture',
        'capture stop': 'Stop packet capture',
        'exec <cmd>': 'Execute system command',
        'exit': 'Exit interactive mode'
    }
    
    while True:
        try:
            cmd = input("\n> ").strip()
            
            if cmd == 'exit':
                break
            elif cmd == 'help':
                print("\nAvailable commands:")
                for cmd_name, desc in commands.items():
                    print(f"  {cmd_name:<20} - {desc}")
            elif cmd == 'sysinfo':
                result = await client.connect_and_execute('uname -a; uptime', 'system')
                print(result['output'] if result['success'] else f"Error: {result['error']}")
            elif cmd == 'netinfo':
                result = await client.connect_and_execute('', 'network_info')
                print(result['output'] if result['success'] else f"Error: {result['error']}")
            elif cmd == 'selftest':
                result = await client.connect_and_execute('', 'self_test')
                print(result['output'] if result['success'] else f"Error: {result['error']}")
            elif cmd == 'capture start':
                result = await client.connect_and_execute('start', 'packet_capture')
                print(result['output'] if result['success'] else f"Error: {result['error']}")
            elif cmd == 'capture stop':
                result = await client.connect_and_execute('stop', 'packet_capture')
                print(result['output'] if result['success'] else f"Error: {result['error']}")
            elif cmd.startswith('exec '):
                command = cmd[5:]
                result = await client.connect_and_execute(command, 'system')
                print(result['output'] if result['success'] else f"Error: {result['error']}")
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Test client for Educational Router Remote Control'
    )
    parser.add_argument(
        '--server',
        default='wss://192.168.1.1:9443',
        help='WebSocket server URL (default: wss://192.168.1.1:9443)'
    )
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Run in interactive mode'
    )
    parser.add_argument(
        '--insecure',
        action='store_true',
        help='Use ws:// instead of wss:// (for testing only)'
    )
    
    args = parser.parse_args()
    
    # Adjust URL for insecure mode
    if args.insecure:
        args.server = args.server.replace('wss://', 'ws://')
    
    # Generate test auth key
    auth_key = generate_test_auth_key()
    
    print("=== Educational Router Remote Control Test Client ===")
    print("⚠️  For educational purposes only!")
    print("")
    
    # Run tests
    if args.interactive:
        asyncio.run(interactive_mode(args.server, auth_key))
    else:
        asyncio.run(test_commands(args.server, auth_key))

if __name__ == "__main__":
    main()