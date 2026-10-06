import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

# Load dataset
df = pd.read_csv("windowed_features_v2.csv")

# Features used by the ML model
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

X = df[features]

# Train Isolation Forest
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42
)

model.fit(X)
joblib.dump(model, "isolation_forest_model.pkl")
print("ML model saved as isolation_forest_model.pkl")

# Predict
df["prediction"] = model.predict(X)

# Calculate anomaly score
df["anomaly_score"] = model.decision_function(X)

normal = (df["prediction"] == 1).sum()
anomalies = (df["prediction"] == -1).sum()

print("================================")
print("ANOMALY DETECTION RESULTS")
print("================================")

print("Total windows:", len(df))
print("Normal windows:", normal)
print("Anomalous windows:", anomalies)
print(
    "Anomaly percentage:",
    round((anomalies / len(df)) * 100, 2),
    "%"
)

print("\nMost anomalous windows:")

print(
    df[df["prediction"] == -1]
    .sort_values("anomaly_score")
    [
        [
            "packet_count",
            "packet_rate",
            "bytes_per_second",
            "unique_destination_ports",
            "unique_destination_ips",
            "anomaly_score"
        ]
    ]
    .head(10)
    .to_string(index=False)
)

# Save results
df.to_csv("anomaly_results_v2.csv", index=False)

print("\nResults saved as anomaly_results_v2.csv")