from scapy.all import Ether, IP, IPv6, TCP, UDP, DNS, DNSQR
from application_identifier import ApplicationIdentifier

app_identifier = ApplicationIdentifier()

def identify_protocol(packet):

    # DNS
    if DNS in packet:
        return "DNS"

    # TCP protocols
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        if src_port == 80 or dst_port == 80:
            return "HTTP"

        if src_port == 21 or dst_port == 21:
            return "FTP"

        if src_port == 443 or dst_port == 443:
            return "HTTPS"

        return "TCP"

    # UDP
    if UDP in packet:
        return "UDP"

    return "OTHER"

def get_dns_domain(packet):
    if DNS in packet and DNSQR in packet:
        try:
            domain = packet[DNSQR].qname.decode("utf-8")
            return domain.rstrip(".")
        except:
            return None

    return None



def parse_packet(packet):

    app_identifier.process_dns_packet(packet)
    app_identifier.process_tls_packet(packet)

    data = {
        "source_mac": None,
        "destination_mac": None,
        "ip_version": None,
        "source_ip": None,
        "destination_ip": None,
        "ip_header_length": None,
        "transport": None,
        "source_port": None,
        "destination_port": None,
        "protocol": identify_protocol(packet),
        "packet_length": len(packet),
        "security_warning": None,
        "domain": get_dns_domain(packet),
        "application": None
    }

    # Data Link Layer
    if Ether in packet:
        data["source_mac"] = packet[Ether].src
        data["destination_mac"] = packet[Ether].dst

    # IPv4
    if IP in packet:
        data["ip_version"] = "IPv4"
        data["source_ip"] = packet[IP].src
        data["destination_ip"] = packet[IP].dst
        if packet[IP].ihl is not None:
            data["ip_header_length"] = packet[IP].ihl * 4
        else:
            data["ip_header_length"] = 20

    # IPv6
    elif IPv6 in packet:
        data["ip_version"] = "IPv6"
        data["source_ip"] = packet[IPv6].src
        data["destination_ip"] = packet[IPv6].dst

    # Application / Domain identification

    if data["destination_ip"]:
        data["domain"] = (
            data["domain"]
            or app_identifier.get_domain(data["destination_ip"])
        )

    if data["source_ip"] and not data["domain"]:
        data["domain"] = app_identifier.get_domain(data["source_ip"])

    data["application"] = app_identifier.get_application(
        data["domain"],
        data["destination_ip"]
    )  

    # TCP
    if TCP in packet:
        data["transport"] = "TCP"
        data["source_port"] = packet[TCP].sport
        data["destination_port"] = packet[TCP].dport

    # UDP
    elif UDP in packet:
        data["transport"] = "UDP"
        data["source_port"] = packet[UDP].sport
        data["destination_port"] = packet[UDP].dport

    # Security Warning
    if data["protocol"] == "HTTP":
        data["security_warning"] = "Unencrypted HTTP traffic detected"

    elif data["protocol"] == "FTP":
        data["security_warning"] = "Unencrypted FTP traffic detected"


    return data