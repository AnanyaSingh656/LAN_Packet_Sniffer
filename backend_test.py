from packet_sniffer import start_capture


def receive_packet(data):
    print("\nGUI RECEIVED:")
    print("Protocol:", data["protocol"])
    print("Source:", data["source_ip"])
    print("Destination:", data["destination_ip"])
    print("Size:", data["packet_length"], "bytes")


print("Starting backend test...")
print("Press CTRL+C to stop.\n")

start_capture(callback=receive_packet)