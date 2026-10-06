from security_analyzer import calculate_risk


result = calculate_risk(
    packet_rate=500,
    bytes_per_second=400000,
    unique_destination_ports=40,
    unique_destination_ips=25,
    is_ml_anomaly=True,

    packet_rate_limit=300,
    bandwidth_limit=300000,
    ports_limit=30,
    ips_limit=20
)

print("================================")
print("SECURITY ANALYZER TEST")
print("================================")

print("Risk Score:", result["risk_score"])
print("Risk Level:", result["risk_level"])
print("ML Anomaly:", result["is_anomaly"])

print("\nReasons:")
for reason in result["reasons"]:
    print("-", reason)