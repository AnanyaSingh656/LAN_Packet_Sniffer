from packet_sniffer import start_capture
from feature_extractor import TrafficFeatureExtractor


extractor = TrafficFeatureExtractor()


def receive_packet(data):

    features = extractor.extract(data)

    if features is None:
        return

    print("\n--- 5 SECOND WINDOW ---")
    print("Packet Size:", features["packet_size"])
    print("Protocol:", features["protocol"])
    print("Destination Port:", features["destination_port"])
    print("Packet Rate:", features["packet_rate"])
    print("Bytes/sec:", features["bytes_per_second"])
    print("Unique Destination Ports:",
          features["unique_destination_ports"])
    print("Unique Destination IPs:",
          features["unique_destination_ips"])


print("Starting feature extraction...")
print("Generate some network traffic.")
print("Press CTRL+C to stop.\n")

start_capture(callback=receive_packet)