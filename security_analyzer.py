def calculate_risk(
    packet_rate,
    bytes_per_second,
    unique_destination_ports,
    unique_destination_ips,
    is_ml_anomaly,
    packet_rate_limit,
    bandwidth_limit,
    ports_limit,
    ips_limit
):

    score = 0
    reasons = []

    # ML anomaly
    if is_ml_anomaly:
        score += 40
        reasons.append("ML model detected unusual traffic")

    # High packet rate
    if packet_rate > packet_rate_limit:
        score += 20
        reasons.append("High packet rate")

    # High bandwidth
    if bytes_per_second > bandwidth_limit:
        score += 20
        reasons.append("High bandwidth usage")

    # Many destination ports
    if unique_destination_ports > ports_limit:
        score += 20
        reasons.append("Large number of destination ports")

    # Many destination IPs
    if unique_destination_ips > ips_limit:
        score += 10
        reasons.append("High destination IP diversity")

    # Maximum score
    score = min(score, 100)

    # Risk level
    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "is_anomaly": is_ml_anomaly,
        "reasons": reasons
    }