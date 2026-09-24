from scapy.all import sniff
from packet_parser import parse_packet


INTERFACE = r"\Device\NPF_{0DDED875-66AB-4375-9A33-FBA11C9086F6}"


def process_packet(packet, callback=None):

    data = parse_packet(packet)

    if callback:
        callback(data)

    return data


def start_capture(callback=None):

    sniff(
        iface=INTERFACE,
        prn=lambda packet: process_packet(packet, callback),
        store=False
    )


if __name__ == "__main__":

    print("==============================================")
    print("REAL-TIME LAN PACKET SNIFFER")
    print("==============================================")
    print("Interface: Airtel Hotspot (Qualcomm Wi-Fi)")
    print("Press CTRL+C to stop.\n")

    start_capture()