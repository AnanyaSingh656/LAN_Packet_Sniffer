import pandas as pd
import joblib
from security_analyzer import calculate_risk


# Load trained ML model
model = joblib.load("isolation_forest_model.pkl")


# Load normal dataset to calculate real thresholds
df = pd.read_csv("anomaly_results_v2.csv")

normal = df[df["prediction"] == 1]

packet_rate_limit = normal["packet_rate"].quantile(0.95)
bandwidth_limit = normal["bytes_per_second"].quantile(0.95)
ports_limit = normal["unique_destination_ports"].quantile(0.95)
ips_limit = normal["unique_destination_ips"].quantile(0.95)


features = [
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
]


# Controlled abnormal scenarios
simulated = pd.DataFrame([

    # Scenario 1: High packet rate
    {
        "packet_count": 5000,
        "avg_packet_size": 900,
        "max_packet_size": 1500,
        "packet_rate": 1000,
        "bytes_per_second": 900000,
        "unique_destination_ports": 20,
        "unique_destination_ips": 10,
        "dns_packets": 50,
        "http_packets": 0,
        "https_packets": 100,
        "tcp_packets": 4000,
        "udp_packets": 850,
        "other_packets": 0
    },

    # Scenario 2: Many destination ports/IPs
    {
        "packet_count": 500,
        "avg_packet_size": 300,
        "max_packet_size": 700,
        "packet_rate": 100,
        "bytes_per_second": 30000,
        "unique_destination_ports": 500,
        "unique_destination_ips": 100,
        "dns_packets": 0,
        "http_packets": 0,
        "https_packets": 0,
        "tcp_packets": 500,
        "udp_packets": 0,
        "other_packets": 0
    },

    # Scenario 3: High bandwidth
    {
        "packet_count": 3000,
        "avg_packet_size": 1400,
        "max_packet_size": 1500,
        "packet_rate": 600,
        "bytes_per_second": 840000,
        "unique_destination_ports": 5,
        "unique_destination_ips": 3,
        "dns_packets": 0,
        "http_packets": 0,
        "https_packets": 2800,
        "tcp_packets": 200,
        "udp_packets": 0,
        "other_packets": 0
    }
])


X = simulated[features]

# ML prediction
predictions = model.predict(X)
scores = model.decision_function(X)


print("================================")
print("CONTROLLED ANOMALY TEST")
print("================================")


for i, row in simulated.iterrows():

    is_anomaly = predictions[i] == -1

    result = calculate_risk(
        packet_rate=row["packet_rate"],
        bytes_per_second=row["bytes_per_second"],
        unique_destination_ports=row["unique_destination_ports"],
        unique_destination_ips=row["unique_destination_ips"],
        is_ml_anomaly=is_anomaly,
        packet_rate_limit=packet_rate_limit,
        bandwidth_limit=bandwidth_limit,
        ports_limit=ports_limit,
        ips_limit=ips_limit
    )

    print(f"\nScenario {i + 1}")
    print("--------------------------------")
    print("ML Result:", "ANOMALY" if is_anomaly else "NORMAL")
    print("Anomaly Score:", round(scores[i], 4))
    print("Risk Score:", result["risk_score"])
    print("Risk Level:", result["risk_level"])

    print("Reasons:")
    for reason in result["reasons"]:
        print(" -", reason)