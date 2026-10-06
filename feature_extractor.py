import time


class TrafficFeatureExtractor:

    def __init__(self, window_seconds=5):
        self.window_seconds = window_seconds
        self.reset_window()

    def reset_window(self):
        self.window_start = time.monotonic()

        self.packet_count = 0
        self.total_bytes = 0
        self.packet_sizes = []

        self.destination_ports = set()
        self.destination_ips = set()

        # Protocol counters
        self.protocol_counts = {
            "DNS": 0,
            "HTTP": 0,
            "HTTPS": 0,
            "TCP": 0,
            "UDP": 0,
            "OTHER": 0
        }

    def extract(self, data):

        now = time.monotonic()

        # Add current packet
        self.packet_count += 1

        packet_size = data["packet_length"]
        self.total_bytes += packet_size
        self.packet_sizes.append(packet_size)

        # Destination port
        if data["destination_port"] is not None:
            self.destination_ports.add(data["destination_port"])

        # Destination IP
        if data["destination_ip"] is not None:
            self.destination_ips.add(data["destination_ip"])

        # Protocol
        protocol = data["protocol"]

        if protocol in self.protocol_counts:
            self.protocol_counts[protocol] += 1
        else:
            self.protocol_counts["OTHER"] += 1

        elapsed = now - self.window_start

        # Wait until 5-second window is complete
        if elapsed < self.window_seconds:
            return None

        # Calculate aggregated features
        packet_rate = self.packet_count / elapsed
        bytes_per_second = self.total_bytes / elapsed

        avg_packet_size = (
            self.total_bytes / self.packet_count
            if self.packet_count > 0 else 0
        )

        max_packet_size = (
            max(self.packet_sizes)
            if self.packet_sizes else 0
        )

        features = {
            "packet_count": self.packet_count,
            "avg_packet_size": round(avg_packet_size, 2),
            "max_packet_size": max_packet_size,
            "packet_rate": round(packet_rate, 2),
            "bytes_per_second": round(bytes_per_second, 2),

            "unique_destination_ports":
                len(self.destination_ports),

            "unique_destination_ips":
                len(self.destination_ips),

            "dns_packets": self.protocol_counts["DNS"],
            "http_packets": self.protocol_counts["HTTP"],
            "https_packets": self.protocol_counts["HTTPS"],
            "tcp_packets": self.protocol_counts["TCP"],
            "udp_packets": self.protocol_counts["UDP"],
            "other_packets": self.protocol_counts["OTHER"]
        }

        # Start a fresh window
        self.reset_window()

        return features