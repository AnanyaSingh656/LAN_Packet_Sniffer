from scapy.all import sniff, conf
from packet_parser import parse_packet


def get_wifi_interface():
    for interface in conf.ifaces.values():
        name = str(interface.name).lower()

        if "wi-fi" in name or "wireless" in name or "wlan" in name:
            return interface.name

    raise RuntimeError("Wi-Fi interface not found")


def process_packet(packet, callback=None):

    data = parse_packet(packet)

    if callback:
        callback(data)

    return data


def start_capture(callback=None):

    interface = get_wifi_interface()

    sniff(
        iface=interface,
        prn=lambda packet: process_packet(packet, callback),
        store=False
    )


if __name__ == "__main__":

    print("==============================================")
    print("REAL-TIME LAN PACKET SNIFFER")
    print("==============================================")
    print("Press CTRL+C to stop.\n")

    start_capture()