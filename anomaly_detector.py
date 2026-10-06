import pandas as pd
from sklearn.ensemble import IsolationForest

# Load prepared dataset
df = pd.read_csv("prepared_features.csv")

# Features used by the model
X = df[
    [
        "packet_size",
        "destination_port",
        "packet_rate",
        "bytes_per_second",
        "unique_destination_ports",
        "unique_destination_ips",
        "protocol_DNS",
        "protocol_HTTP",
        "protocol_HTTPS",
        "protocol_TCP",
        "protocol_UDP"
    ]
]

# Create Isolation Forest model
model = IsolationForest(
    n_estimators=100,
    contamination=0.01,
    random_state=42
)

# Train model
model.fit(X)

# Predict
predictions = model.predict(X)

# -1 = anomaly
#  1 = normal
df["prediction"] = predictions

# Count results
normal = (predictions == 1).sum()
anomalies = (predictions == -1).sum()

print("================================")
print("ANOMALY DETECTION RESULTS")
print("================================")

print("Total packets:", len(df))
print("Normal packets:", normal)
print("Anomalous packets:", anomalies)

print(
    "Anomaly percentage:",
    round((anomalies / len(df)) * 100, 2),
    "%"
)

# Save results
df.to_csv("anomaly_results.csv", index=False)

print("\nResults saved as anomaly_results.csv")
