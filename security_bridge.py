import pandas as pd
import joblib

from feature_extractor import TrafficFeatureExtractor
from security_analyzer import calculate_risk


class SecurityBridge:

    def __init__(self):
        # Load the already-trained Isolation Forest model
        self.model = joblib.load(
            "isolation_forest_model.pkl"
        )

        # Load previous ML results to calculate
        # normal-traffic thresholds
        df = pd.read_csv(
            "anomaly_results_v2.csv"
        )

        normal = df[
            df["prediction"] == 1
        ]

        self.packet_rate_limit = (
            normal["packet_rate"].quantile(0.95)
        )

        self.bandwidth_limit = (
            normal["bytes_per_second"].quantile(0.95)
        )

        self.ports_limit = (
            normal["unique_destination_ports"].quantile(0.95)
        )

        self.ips_limit = (
            normal["unique_destination_ips"].quantile(0.95)
        )

        # Same 5-second feature extractor
        # used by Ananya's security backend
        self.extractor = TrafficFeatureExtractor(
            window_seconds=5
        )

        self.features = [
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

    def process_packet(self, data):

        # Add packet to the current 5-second window
        window = self.extractor.extract(data)

        # Not enough time for a complete window yet
        if window is None:
            return None

        # Convert features into the format expected
        # by the trained Isolation Forest model
        X = pd.DataFrame(
            [window]
        )[self.features]

        # ML prediction
        prediction = self.model.predict(X)[0]

        anomaly_score = (
            self.model.decision_function(X)[0]
        )

        is_anomaly = (
            prediction == -1
        )

        # Existing explainable risk engine
        result = calculate_risk(
            packet_rate=window["packet_rate"],
            bytes_per_second=window["bytes_per_second"],
            unique_destination_ports=
                window["unique_destination_ports"],
            unique_destination_ips=
                window["unique_destination_ips"],
            is_ml_anomaly=is_anomaly,
            packet_rate_limit=
                self.packet_rate_limit,
            bandwidth_limit=
                self.bandwidth_limit,
            ports_limit=
                self.ports_limit,
            ips_limit=
                self.ips_limit
        )

        return {
            "risk_score":
                result["risk_score"],

            "risk_level":
                result["risk_level"],

            "is_anomaly":
                result["is_anomaly"],

            "reasons":
                result["reasons"],

            "anomaly_score":
                round(anomaly_score, 4),

            "packet_rate":
                window["packet_rate"],

            "bytes_per_second":
                window["bytes_per_second"],

            "unique_destination_ports":
                window["unique_destination_ports"],

            "unique_destination_ips":
                window["unique_destination_ips"],

            "packet_count":
                window["packet_count"],

            "avg_packet_size":
                window["avg_packet_size"]
        }