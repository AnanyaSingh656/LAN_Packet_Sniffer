from scapy.all import Ether, IP, TCP
from packet_parser import parse_packet


# Test HTTP
http_packet = (
    Ether()
    / IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=12345, dport=80)
)

print("HTTP TEST")
print(parse_packet(http_packet))


# Test FTP
ftp_packet = (
    Ether()
    / IP(src="192.168.1.10", dst="192.168.1.30")
    / TCP(sport=12346, dport=21)
)

print("\nFTP TEST")
print(parse_packet(ftp_packet))