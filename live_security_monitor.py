import pandas as pd
import joblib

from packet_sniffer import start_capture
from feature_extractor import TrafficFeatureExtractor
from security_analyzer import calculate_risk


# Load trained ML model
model = joblib.load("isolation_forest_model.pkl")

# Load normal traffic results to calculate thresholds
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


extractor = TrafficFeatureExtractor(window_seconds=5)


def receive_packet(data):

    # Build 5-second feature window
    window = extractor.extract(data)

    if window is None:
        return

    # Convert to DataFrame for ML
    X = pd.DataFrame([window])[features]

    # ML prediction
    prediction = model.predict(X)[0]
    anomaly_score = model.decision_function(X)[0]

    is_anomaly = prediction == -1

    # Explainable risk analysis
    result = calculate_risk(
        packet_rate=window["packet_rate"],
        bytes_per_second=window["bytes_per_second"],
        unique_destination_ports=window["unique_destination_ports"],
        unique_destination_ips=window["unique_destination_ips"],
        is_ml_anomaly=is_anomaly,
        packet_rate_limit=packet_rate_limit,
        bandwidth_limit=bandwidth_limit,
        ports_limit=ports_limit,
        ips_limit=ips_limit
    )

    security_result = {
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "is_anomaly": result["is_anomaly"],
        "reasons": result["reasons"],
        "anomaly_score": round(anomaly_score, 4),
        "packet_rate": window["packet_rate"],
        "bytes_per_second": window["bytes_per_second"],
        "unique_destination_ports": window["unique_destination_ports"],
        "unique_destination_ips": window["unique_destination_ips"]
    }

    print("\nSecurity Result:")
    print(security_result)


    print("\n================================")
    print("LIVE SECURITY ANALYSIS")
    print("================================")

    print("Packet Rate:",
          window["packet_rate"], "packets/sec")

    print("Bandwidth:",
          window["bytes_per_second"], "bytes/sec")

    print("Destination Ports:",
          window["unique_destination_ports"])

    print("Destination IPs:",
          window["unique_destination_ips"])

    print("ML Result:",
          "ANOMALY" if is_anomaly else "NORMAL")

    print("Anomaly Score:",
          round(anomaly_score, 4))

    print("Risk Score:",
          result["risk_score"])

    print("Risk Level:",
          result["risk_level"])

    if result["reasons"]:
        print("Reasons:")
        for reason in result["reasons"]:
            print(" -", reason)
    else:
        print("Reasons: None")


print("================================")
print("LIVE SECURITY MONITOR")
print("================================")
print("Monitoring 5-second traffic windows...")
print("Press CTRL+C to stop.\n")


try:
    start_capture(callback=receive_packet)

except KeyboardInterrupt:
    print("\nMonitoring stopped.")