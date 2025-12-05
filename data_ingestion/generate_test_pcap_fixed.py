#!/usr/bin/env python3
"""
Synthetic PCAP Generator for Testing
Generates realistic network traffic with login attempts
"""

import struct
import random
from datetime import datetime, timedelta
import os


class PCAPGenerator:
    """Generate synthetic PCAP files for testing"""
    
    def __init__(self, output_file):
        self.output_file = output_file
        self.packets = []
        
    def write_pcap(self):
        """Write PCAP file with global header and packets"""
        with open(self.output_file, 'wb') as f:
            # Global PCAP header
            magic = 0xa1b2c3d4  # Little endian
            version_major = 2
            version_minor = 4
            thiszone = 0
            sigfigs = 0
            snaplen = 65535
            network = 1  # Ethernet
            
            f.write(struct.pack('<IHHIIII', magic, version_major, version_minor, 
                              thiszone, sigfigs, snaplen, network))
            
            # Write packets
            for pkt_data, timestamp in self.packets:
                ts_sec = int(timestamp.timestamp())
                ts_usec = int((timestamp.timestamp() % 1) * 1000000)
                incl_len = len(pkt_data)
                orig_len = len(pkt_data)
                
                # Packet header
                f.write(struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len))
                # Packet data
                f.write(pkt_data)
    
    def add_ssh_connection(self, src_ip, dst_ip, timestamp, username="testuser"):
        """Add SSH connection packets"""
        # TCP SYN
        syn_pkt = self._create_tcp_packet(src_ip, dst_ip, 
                                          random.randint(40000, 60000), 22,
                                          flags=0x02, payload=b'')
        self.packets.append((syn_pkt, timestamp))
        
        # TCP SYN-ACK
        synack_pkt = self._create_tcp_packet(dst_ip, src_ip,
                                             22, random.randint(40000, 60000),
                                             flags=0x12, payload=b'')
        self.packets.append((synack_pkt, timestamp + timedelta(milliseconds=10)))
        
        # TCP ACK
        ack_pkt = self._create_tcp_packet(src_ip, dst_ip,
                                          random.randint(40000, 60000), 22,
                                          flags=0x10, payload=b'')
        self.packets.append((ack_pkt, timestamp + timedelta(milliseconds=20)))
        
        # SSH protocol negotiation
        ssh_banner = b'SSH-2.0-OpenSSH_8.2p1\r\n'
        ssh_pkt = self._create_tcp_packet(dst_ip, src_ip,
                                         22, random.randint(40000, 60000),
                                         flags=0x18, payload=ssh_banner)
        self.packets.append((ssh_pkt, timestamp + timedelta(milliseconds=50)))
        
        # Client response
        client_banner = b'SSH-2.0-OpenSSH_8.9p1\r\n'
        client_pkt = self._create_tcp_packet(src_ip, dst_ip,
                                            random.randint(40000, 60000), 22,
                                            flags=0x18, payload=client_banner)
        self.packets.append((client_pkt, timestamp + timedelta(milliseconds=60)))
    
    def add_rdp_connection(self, src_ip, dst_ip, timestamp):
        """Add RDP connection packets"""
        # TCP SYN for RDP
        syn_pkt = self._create_tcp_packet(src_ip, dst_ip,
                                          random.randint(40000, 60000), 3389,
                                          flags=0x02, payload=b'')
        self.packets.append((syn_pkt, timestamp))
        
        # RDP handshake data
        rdp_data = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00' + b'\x00' * 20
        rdp_pkt = self._create_tcp_packet(src_ip, dst_ip,
                                         random.randint(40000, 60000), 3389,
                                         flags=0x18, payload=rdp_data)
        self.packets.append((rdp_pkt, timestamp + timedelta(milliseconds=100)))
    
    def add_http_auth(self, src_ip, dst_ip, timestamp, username="admin"):
        """Add HTTP authentication attempt"""
        # TCP connection
        syn_pkt = self._create_tcp_packet(src_ip, dst_ip,
                                          random.randint(40000, 60000), 80,
                                          flags=0x02, payload=b'')
        self.packets.append((syn_pkt, timestamp))
        
        # HTTP GET with auth
        http_request = (
            b'GET / HTTP/1.1\r\n'
            b'Host: server.local\r\n'
            b'Authorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n'
            b'User-Agent: Mozilla/5.0\r\n'
            b'\r\n'
        )
        http_pkt = self._create_tcp_packet(src_ip, dst_ip,
                                          random.randint(40000, 60000), 80,
                                          flags=0x18, payload=http_request)
        self.packets.append((http_pkt, timestamp + timedelta(milliseconds=50)))
    
    def _create_tcp_packet(self, src_ip, dst_ip, src_port, dst_port, 
                          flags=0x18, payload=b'', seq=None, ack=None):
        """Create a TCP packet with Ethernet + IP + TCP headers"""
        # Ethernet header (14 bytes)
        dst_mac = b'\x00\x11\x22\x33\x44\x55'
        src_mac = b'\x00\xaa\xbb\xcc\xdd\xee'
        eth_type = struct.pack('!H', 0x0800)  # IPv4
        eth_header = dst_mac + src_mac + eth_type
        
        # IP header (20 bytes)
        version_ihl = 0x45  # IPv4, header length 20
        tos = 0
        total_length = 20 + 20 + len(payload)  # IP + TCP + payload
        identification = random.randint(0, 65535)
        flags_fragment = 0x4000  # Don't fragment
        ttl = 64
        protocol = 6  # TCP
        checksum = 0  # Will be ignored
        src_ip_bytes = bytes(map(int, src_ip.split('.')))
        dst_ip_bytes = bytes(map(int, dst_ip.split('.')))
        
        ip_header = struct.pack('!BBHHHBBH',
                               version_ihl, tos, total_length, identification,
                               flags_fragment, ttl, protocol, checksum)
        ip_header += src_ip_bytes + dst_ip_bytes
        
        # TCP header (20 bytes minimum)
        seq_num = seq if seq else random.randint(0, 0xffffffff)
        ack_num = ack if ack else random.randint(0, 0xffffffff)
        data_offset = 0x50  # 20 bytes, no options
        window = 65535
        checksum_tcp = 0
        urgent = 0
        
        tcp_header = struct.pack('!HHIIBBHHH',
                                src_port, dst_port, seq_num, ack_num,
                                data_offset, flags, window, checksum_tcp, urgent)
        
        # Combine
        packet = eth_header + ip_header + tcp_header + payload
        return packet


def generate_sample_pcap():
    """Generate sample PCAP file with various login attempts"""
    print("[*] Generating synthetic PCAP file...")
    
    # Use current directory
    output_file = os.path.join(os.getcwd(), 'sample_traffic.pcap')
    gen = PCAPGenerator(output_file)
    
    base_time = datetime.now() - timedelta(hours=1)
    
    # Normal office hours logins
    print("[*] Adding normal SSH logins...")
    for i in range(5):
        src_ip = f'192.168.1.{100 + i}'
        dst_ip = '192.168.1.10'  # SSH server
        timestamp = base_time + timedelta(minutes=i*10)
        gen.add_ssh_connection(src_ip, dst_ip, timestamp, f"user{i}")
    
    # Normal RDP sessions
    print("[*] Adding normal RDP sessions...")
    for i in range(3):
        src_ip = f'192.168.1.{150 + i}'
        dst_ip = '192.168.1.20'  # RDP server
        timestamp = base_time + timedelta(minutes=5 + i*15)
        gen.add_rdp_connection(src_ip, dst_ip, timestamp)
    
    # HTTP auth attempts
    print("[*] Adding HTTP auth attempts...")
    for i in range(2):
        src_ip = f'192.168.1.{200 + i}'
        dst_ip = '192.168.1.30'  # Web server
        timestamp = base_time + timedelta(minutes=10 + i*5)
        gen.add_http_auth(src_ip, dst_ip, timestamp)
    
    # ANOMALY: After-hours SSH from external IP
    print("[*] Adding anomalous after-hours SSH...")
    anomaly_time = base_time.replace(hour=3, minute=0)
    gen.add_ssh_connection('203.0.113.50', '192.168.1.10', anomaly_time)
    
    # ANOMALY: Rapid-fire SSH attempts (brute force)
    print("[*] Adding brute force SSH attempts...")
    brute_time = base_time + timedelta(minutes=30)
    for i in range(15):  # 15 rapid attempts
        gen.add_ssh_connection('198.51.100.25', '192.168.1.10', 
                             brute_time + timedelta(seconds=i*2))
    
    # ANOMALY: Weekend RDP from unusual location
    print("[*] Adding weekend anomaly...")
    weekend_time = base_time + timedelta(days=2)  # Move to weekend
    gen.add_rdp_connection('198.51.100.100', '192.168.1.20', weekend_time)
    
    # Write PCAP
    print("[*] Writing PCAP file...")
    gen.write_pcap()
    
    print(f"[+] Generated {len(gen.packets)} packets")
    print(f"[+] PCAP file: {output_file}")
    print(f"[+] File size: {os.path.getsize(output_file)} bytes")
    
    return output_file


if __name__ == '__main__':
    output = generate_sample_pcap()
    print(f"\n[SUCCESS] Sample PCAP ready for testing!")
    print(f"\nTest with: python3 pcap_reader.py {output}")
