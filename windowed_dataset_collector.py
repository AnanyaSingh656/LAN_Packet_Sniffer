import csv
from packet_sniffer import start_capture
from feature_extractor import TrafficFeatureExtractor


extractor = TrafficFeatureExtractor(window_seconds=5)

csv_file = open("windowed_features_v2.csv", "w", newline="")
writer = csv.writer(csv_file)

writer.writerow([
    "packet_count",
    "avg_packet_size",
    "max_packet_size",
    "packet_rate",
    "bytes_per_second",
    "unique_destination_ports",
    "unique_destination_ips",
    "dns_packets",
    "http_packets",
    "https_packets",
    "tcp_packets",
    "udp_packets",
    "other_packets"
])


window_number = 0


def receive_packet(data):
    global window_number

    features = extractor.extract(data)

    if features is None:
        return

    writer.writerow([
        features["packet_count"],
        features["avg_packet_size"],
        features["max_packet_size"],
        features["packet_rate"],
        features["bytes_per_second"],
        features["unique_destination_ports"],
        features["unique_destination_ips"],
        features["dns_packets"],
        features["http_packets"],
        features["https_packets"],
        features["tcp_packets"],
        features["udp_packets"],
        features["other_packets"]
    ])

    csv_file.flush()

    window_number += 1

    print(
        f"Window {window_number}: "
        f"{features['packet_rate']} pkt/s | "
        f"{features['bytes_per_second']} bytes/s | "
        f"{features['unique_destination_ports']} ports | "
        f"{features['unique_destination_ips']} IPs"
    )


print("================================")
print("WINDOWED NETWORK DATASET V2")
print("================================")
print("Collecting 5-second traffic windows...")
print("Press CTRL+C to stop.\n")


try:
    start_capture(callback=receive_packet)

except KeyboardInterrupt:
    print("\nCollection stopped.")

finally:
    csv_file.close()
    print("\nDataset saved as windowed_features_v2.csv")