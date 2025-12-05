#!/usr/bin/env python3
"""
PCAP Reader for Security Suite v5.0
Extracts login events from network packet captures

Supported protocols:
- SSH (port 22)
- RDP (port 3389)
- HTTP/HTTPS authentication (ports 80, 443)
- LDAP/LDAPS (ports 389, 636)
- SMB (port 445)

Author: John Drexler
"""

import struct
import socket
from datetime import datetime
from collections import defaultdict
import json
import os


class PCAPReader:
    """
    Pure Python PCAP parser - no external dependencies
    Reads libpcap format and extracts login-related packets
    """
    
    # Protocol constants
    PROTO_TCP = 6
    PROTO_UDP = 17
    
    # Login-related ports
    LOGIN_PORTS = {
        22: 'SSH',
        3389: 'RDP',
        80: 'HTTP',
        443: 'HTTPS',
        389: 'LDAP',
        636: 'LDAPS',
        445: 'SMB',
        5900: 'VNC'
    }
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.connections = defaultdict(lambda: {
            'start_time': None,
            'packets': [],
            'bytes_sent': 0,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None
        })
        
    def read_pcap(self):
        """Read and parse PCAP file"""
        if not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        
        with open(self.pcap_file, 'rb') as f:
            # Read global header
            global_header = f.read(24)
            if len(global_header) < 24:
                raise ValueError("Invalid PCAP file: too short")
            
            magic, = struct.unpack('I', global_header[:4])
            
            # Check magic number and byte order
            if magic == 0xa1b2c3d4:
                endian = '<'  # Little endian
            elif magic == 0xd4c3b2a1:
                endian = '>'  # Big endian
            else:
                raise ValueError(f"Invalid PCAP magic number: {hex(magic)}")
            
            # Read packets
            packet_count = 0
            while True:
                # Read packet header (16 bytes)
                pkt_header = f.read(16)
                if len(pkt_header) < 16:
                    break
                
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', pkt_header)
                
                # Read packet data
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break
                
                timestamp = datetime.fromtimestamp(ts_sec + ts_usec / 1000000.0)
                
                # Parse packet
                try:
                    parsed = self._parse_packet(pkt_data, timestamp)
                    if parsed:
                        self.packets.append(parsed)
                        packet_count += 1
                except Exception as e:
                    # Skip malformed packets
                    continue
            
            return packet_count
    
    def _parse_packet(self, data, timestamp):
        """Parse packet data to extract relevant info"""
        if len(data) < 14:
            return None
        
        # Ethernet header (14 bytes)
        eth_header = data[:14]
        eth_protocol, = struct.unpack('!H', eth_header[12:14])
        
        # Check if IPv4 (0x0800)
        if eth_protocol != 0x0800:
            return None
        
        # IP header (starts at byte 14)
        if len(data) < 34:
            return None
        
        ip_header = data[14:34]
        
        # Parse IP header
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4  # Header length in bytes
        
        if version != 4:
            return None
        
        protocol = ip_header[9]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])
        
        # Only process TCP for now (most login protocols use TCP)
        if protocol != self.PROTO_TCP:
            return None
        
        # TCP header starts after IP header
        tcp_start = 14 + ihl
        if len(data) < tcp_start + 20:
            return None
        
        tcp_header = data[tcp_start:tcp_start + 20]
        src_port, = struct.unpack('!H', tcp_header[0:2])
        dst_port, = struct.unpack('!H', tcp_header[2:4])
        seq_num, = struct.unpack('!I', tcp_header[4:8])
        ack_num, = struct.unpack('!I', tcp_header[8:12])
        tcp_flags = tcp_header[13]
        
        # Check if this is a login-related port
        is_login_port = dst_port in self.LOGIN_PORTS or src_port in self.LOGIN_PORTS
        
        if not is_login_port:
            return None
        
        # Determine protocol
        protocol_name = self.LOGIN_PORTS.get(dst_port) or self.LOGIN_PORTS.get(src_port)
        
        # TCP payload
        tcp_offset = ((tcp_header[12] >> 4) * 4)
        payload_start = tcp_start + tcp_offset
        payload = data[payload_start:] if payload_start < len(data) else b''
        
        return {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol_name,
            'payload': payload,
            'payload_len': len(payload),
            'tcp_flags': tcp_flags,
            'seq': seq_num,
            'ack': ack_num
        }
    
    def extract_login_events(self):
        """
        Extract login events from parsed packets
        Returns list of events compatible with login_anomaly_detector_ml.py
        """
        events = []
        connection_tracker = defaultdict(lambda: {
            'first_seen': None,
            'last_seen': None,
            'packet_count': 0,
            'syn_time': None,
            'auth_detected': False
        })
        
        # Track SSH connection attempts
        ssh_attempts = []
        rdp_attempts = []
        http_auth_attempts = []
        
        for pkt in self.packets:
            conn_key = f"{pkt['src_ip']}:{pkt['src_port']}->{pkt['dst_ip']}:{pkt['dst_port']}"
            conn = connection_tracker[conn_key]
            
            if conn['first_seen'] is None:
                conn['first_seen'] = pkt['timestamp']
            conn['last_seen'] = pkt['timestamp']
            conn['packet_count'] += 1
            
            # Detect SYN packets (start of TCP connection)
            if pkt['tcp_flags'] & 0x02:  # SYN flag
                conn['syn_time'] = pkt['timestamp']
            
            # Protocol-specific login detection
            if pkt['protocol'] == 'SSH':
                # SSH: Look for SSH protocol negotiation in payload
                if b'SSH-' in pkt['payload']:
                    user = self._extract_ssh_user(pkt)
                    location = self._geolocate_ip(pkt['src_ip'])
                    
                    # Calculate time since last login for this source IP
                    time_since_last = self._calculate_time_delta(pkt['src_ip'], pkt['timestamp'], ssh_attempts)
                    
                    event = {
                        'user': user,
                        'timestamp': pkt['timestamp'],
                        'location': location,
                        'failed_attempts': 0,  # Will be updated by tracking multiple attempts
                        'time_since_last': time_since_last,
                        'success': True,
                        'protocol': 'SSH',
                        'src_ip': pkt['src_ip'],
                        'dst_ip': pkt['dst_ip']
                    }
                    ssh_attempts.append(event)
            
            elif pkt['protocol'] == 'RDP':
                # RDP: Look for RDP handshake
                if len(pkt['payload']) > 10:
                    user = self._extract_rdp_user(pkt)
                    location = self._geolocate_ip(pkt['src_ip'])
                    time_since_last = self._calculate_time_delta(pkt['src_ip'], pkt['timestamp'], rdp_attempts)
                    
                    event = {
                        'user': user,
                        'timestamp': pkt['timestamp'],
                        'location': location,
                        'failed_attempts': 0,
                        'time_since_last': time_since_last,
                        'success': True,
                        'protocol': 'RDP',
                        'src_ip': pkt['src_ip'],
                        'dst_ip': pkt['dst_ip']
                    }
                    rdp_attempts.append(event)
            
            elif pkt['protocol'] in ['HTTP', 'HTTPS']:
                # HTTP: Look for authentication headers
                if b'Authorization:' in pkt['payload'] or b'WWW-Authenticate:' in pkt['payload']:
                    user = self._extract_http_user(pkt)
                    location = self._geolocate_ip(pkt['src_ip'])
                    time_since_last = self._calculate_time_delta(pkt['src_ip'], pkt['timestamp'], http_auth_attempts)
                    
                    event = {
                        'user': user,
                        'timestamp': pkt['timestamp'],
                        'location': location,
                        'failed_attempts': 0,
                        'time_since_last': time_since_last,
                        'success': True,
                        'protocol': pkt['protocol'],
                        'src_ip': pkt['src_ip'],
                        'dst_ip': pkt['dst_ip']
                    }
                    http_auth_attempts.append(event)
        
        # Combine all login attempts
        events = ssh_attempts + rdp_attempts + http_auth_attempts
        
        # Post-process: Detect failed attempts (multiple connections from same IP in short time)
        events = self._detect_failed_attempts(events)
        
        return events
    
    def _extract_ssh_user(self, pkt):
        """Extract username from SSH packet (best effort)"""
        # SSH username extraction is complex - for now use source IP as identifier
        return f"user_{pkt['src_ip'].replace('.', '_')}"
    
    def _extract_rdp_user(self, pkt):
        """Extract username from RDP packet (best effort)"""
        return f"rdp_user_{pkt['src_ip'].replace('.', '_')}"
    
    def _extract_http_user(self, pkt):
        """Extract username from HTTP auth (best effort)"""
        # Look for Basic auth or username in payload
        payload_str = pkt['payload'].decode('utf-8', errors='ignore')
        if 'Authorization: Basic' in payload_str:
            # Could decode base64, but just use IP for now
            return f"http_user_{pkt['src_ip'].replace('.', '_')}"
        return f"http_user_{pkt['src_ip'].replace('.', '_')}"
    
    def _geolocate_ip(self, ip):
        """
        Simple IP geolocation (for production, use GeoIP database)
        For now, classify by IP range
        """
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
            return 'Internal Network'
        elif ip.startswith('127.'):
            return 'Localhost'
        else:
            return f'External ({ip})'
    
    def _calculate_time_delta(self, src_ip, current_time, previous_attempts):
        """Calculate hours since last login from this IP"""
        matching = [a for a in previous_attempts if a['src_ip'] == src_ip]
        if not matching:
            return 24.0  # Default: assume 24 hours
        
        last_attempt = max(matching, key=lambda x: x['timestamp'])
        delta = (current_time - last_attempt['timestamp']).total_seconds() / 3600.0
        return max(0.01, delta)  # Minimum 0.01 hours (36 seconds)
    
    def _detect_failed_attempts(self, events):
        """
        Detect failed login attempts by analyzing connection patterns
        Multiple connections from same IP in <5 minutes = likely failed attempts
        """
        ip_timeline = defaultdict(list)
        
        for event in events:
            ip_timeline[event['src_ip']].append(event)
        
        # Update failed_attempts count
        for ip, attempts in ip_timeline.items():
            attempts.sort(key=lambda x: x['timestamp'])
            
            for i, event in enumerate(attempts):
                # Count how many attempts happened in previous 5 minutes
                failed_count = 0
                current_time = event['timestamp']
                
                for j in range(max(0, i-10), i):  # Look at previous 10 attempts
                    prev_time = attempts[j]['timestamp']
                    if (current_time - prev_time).total_seconds() < 300:  # 5 minutes
                        failed_count += 1
                
                event['failed_attempts'] = failed_count
        
        return events


def main():
    """Test PCAP reader with sample file"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        PCAP READER - Security Suite v5.0                     ║
║                  Extract Login Events from Network Captures                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 pcap_reader.py <pcap_file>")
        print("\nExample: python3 pcap_reader.py /var/lib/security_suite/pcap/capture.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    print(f"[*] Reading PCAP file: {pcap_file}")
    
    reader = PCAPReader(pcap_file)
    
    # Read and parse PCAP
    try:
        packet_count = reader.read_pcap()
        print(f"[+] Parsed {packet_count} packets")
        print(f"[+] Found {len(reader.packets)} login-related packets")
        
        # Extract login events
        print("\n[*] Extracting login events...")
        events = reader.extract_login_events()
        
        print(f"[+] Extracted {len(events)} login events")
        
        # Display summary
        if events:
            print("\n" + "=" * 80)
            print("LOGIN EVENTS SUMMARY")
            print("=" * 80)
            
            protocols = defaultdict(int)
            users = set()
            locations = set()
            
            for event in events:
                protocols[event['protocol']] += 1
                users.add(event['user'])
                locations.add(event['location'])
            
            print(f"\nProtocol Breakdown:")
            for proto, count in protocols.items():
                print(f"  {proto}: {count} events")
            
            print(f"\nUnique Users: {len(users)}")
            print(f"Unique Locations: {len(locations)}")
            
            print("\n" + "=" * 80)
            print("SAMPLE EVENTS (first 5)")
            print("=" * 80)
            
            for i, event in enumerate(events[:5]):
                print(f"\nEvent #{i+1}:")
                print(f"  Time: {event['timestamp']}")
                print(f"  User: {event['user']}")
                print(f"  Protocol: {event['protocol']}")
                print(f"  Source: {event['src_ip']}")
                print(f"  Location: {event['location']}")
                print(f"  Failed Attempts: {event['failed_attempts']}")
                print(f"  Time Since Last: {event['time_since_last']:.2f} hours")
        
        # Export to JSON
        output_file = pcap_file.replace('.pcap', '_events.json')
        with open(output_file, 'w') as f:
            # Convert datetime to ISO format for JSON
            events_json = []
            for e in events:
                e_copy = e.copy()
                e_copy['timestamp'] = e_copy['timestamp'].isoformat()
                events_json.append(e_copy)
            
            json.dump({
                'source_pcap': pcap_file,
                'extraction_time': datetime.now().isoformat(),
                'total_events': len(events),
                'events': events_json
            }, f, indent=2)
        
        print(f"\n[+] Events exported to: {output_file}")
        print("\n[SUCCESS] PCAP processing complete!")
        
    except Exception as e:
        print(f"[ERROR] Failed to process PCAP: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
