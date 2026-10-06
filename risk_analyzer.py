import pandas as pd


# Load ML results
df = pd.read_csv("anomaly_results_v2.csv")


# Calculate normal-traffic baselines
normal = df[df["prediction"] == 1]

packet_rate_limit = normal["packet_rate"].quantile(0.95)
bandwidth_limit = normal["bytes_per_second"].quantile(0.95)
ports_limit = normal["unique_destination_ports"].quantile(0.95)
ips_limit = normal["unique_destination_ips"].quantile(0.95)


def analyze_risk(row):

    score = 0
    reasons = []

    # ML anomaly
    if row["prediction"] == -1:
        score += 40
        reasons.append("ML model detected unusual traffic")


    # High packet rate
    if row["packet_rate"] > packet_rate_limit:
        score += 20
        reasons.append("High packet rate")


    # High bandwidth
    if row["bytes_per_second"] > bandwidth_limit:
        score += 20
        reasons.append("High bandwidth usage")


    # Many destination ports
    if row["unique_destination_ports"] > ports_limit:
        score += 20
        reasons.append("Large number of destination ports")


    # Many destination IPs
    if row["unique_destination_ips"] > ips_limit:
        score += 10
        reasons.append("High destination IP diversity")


    # Maximum score = 100
    score = min(score, 100)


    # Risk level
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"


    return score, level, reasons


# Analyze every window
results = []

for _, row in df.iterrows():

    score, level, reasons = analyze_risk(row)

    results.append({
        "risk_score": score,
        "risk_level": level,
        "is_anomaly": row["prediction"] == -1,
        "reasons": "; ".join(reasons)
    })


risk_df = pd.DataFrame(results)

# Add results to original dataset
df["risk_score"] = risk_df["risk_score"]
df["risk_level"] = risk_df["risk_level"]
df["is_anomaly"] = risk_df["is_anomaly"]
df["reasons"] = risk_df["reasons"]


# Save
df.to_csv("risk_analysis_results.csv", index=False)


print("================================")
print("EXPLAINABLE RISK ANALYSIS")
print("================================")

print("\nRisk distribution:")
print(df["risk_level"].value_counts())

print("\nPotentially risky windows:")

print(
    df[df["risk_score"] >= 30]
    .sort_values("risk_score", ascending=False)
    [
        [
            "packet_count",
            "packet_rate",
            "bytes_per_second",
            "unique_destination_ports",
            "unique_destination_ips",
            "risk_score",
            "risk_level",
            "is_anomaly",
            "reasons"
        ]
    ]
    .head(15)
    .to_string(index=False)
)

print("\nResults saved as risk_analysis_results.csv")