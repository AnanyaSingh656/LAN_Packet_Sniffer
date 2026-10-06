import pandas as pd

df = pd.read_csv("anomaly_results.csv")

# Keep only anomalies
anomalies = df[df["prediction"] == -1]

print("================================")
print("ANOMALOUS TRAFFIC")
print("================================")

print("Total anomalies:", len(anomalies))

print("\nFirst 20 anomalies:\n")

print(
    anomalies[
        [
            "packet_size",
            "destination_port",
            "packet_rate",
            "bytes_per_second",
            "unique_destination_ports",
            "unique_destination_ips",
            "prediction"
        ]
    ].head(20).to_string(index=False)
)

print("\n\nProtocol distribution:")
print(anomalies.filter(like="protocol_").sum())

print("\n\nHighest packet rates:")
print(
    anomalies.nlargest(10, "packet_rate")[
        [
            "packet_size",
            "destination_port",
            "packet_rate",
            "bytes_per_second",
            "unique_destination_ports",
            "unique_destination_ips"
        ]
    ].to_string(index=False)
)