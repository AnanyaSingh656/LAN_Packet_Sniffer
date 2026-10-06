import csv

from packet_sniffer import start_capture
from feature_extractor import TrafficFeatureExtractor


extractor = TrafficFeatureExtractor()

csv_file = open("network_features.csv", "w", newline="")

writer = csv.writer(csv_file)

writer.writerow([
    "packet_size",
    "protocol",
    "destination_port",
    "packet_rate",
    "bytes_per_second",
    "unique_destination_ports",
    "unique_destination_ips"
])


packet_number = 0


def receive_packet(data):

    global packet_number

    features = extractor.extract(data)

    writer.writerow([
        features["packet_size"],
        features["protocol"],
        features["destination_port"],
        features["packet_rate"],
        features["bytes_per_second"],
        features["unique_destination_ports"],
        features["unique_destination_ips"]
    ])

    csv_file.flush()

    packet_number += 1

    if packet_number % 100 == 0:
        print(f"{packet_number} packets collected")


print("================================")
print("NETWORK DATASET COLLECTOR")
print("================================")
print("Collecting normal network traffic...")
print("Press CTRL+C to stop.\n")


try:
    start_capture(callback=receive_packet)

except KeyboardInterrupt:
    print("\nCollection stopped.")

finally:
    csv_file.close()
    print("Dataset saved as network_features.csv")