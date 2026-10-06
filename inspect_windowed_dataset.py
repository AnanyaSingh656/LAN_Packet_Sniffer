import pandas as pd

df = pd.read_csv("windowed_features_v2.csv")

print("================================")
print("WINDOWED DATASET INSPECTION")
print("================================")

print("Total windows:", len(df))

print("\nMissing values:")
print(df.isnull().sum())

print("\nFirst 10 windows:")
print(df.head(10).to_string(index=False))

print("\nStatistics:")
print(
    df[
        [
            "packet_count",
            "packet_rate",
            "bytes_per_second",
            "unique_destination_ports",
            "unique_destination_ips"
        ]
    ].describe()
)

print("\nProtocol packet totals:")

protocol_columns = [
    "dns_packets",
    "http_packets",
    "https_packets",
    "tcp_packets",
    "udp_packets",
    "other_packets"
]

print(df[protocol_columns].sum())