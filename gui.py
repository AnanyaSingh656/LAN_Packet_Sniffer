import sys
import time

from PySide6.QtCore import Qt, QThread
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QGroupBox,
    QFormLayout,
    QListWidget,
    QSplitter,
    QHeaderView,
    QMessageBox,
    QScrollArea,
    QSizePolicy,
)

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from capture_worker import CaptureWorker


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle(
            "Real-Time LAN Packet Sniffer and "
            "Protocol Security Inspection System"
        )

        self.resize(1500, 950)

        # ==================================================
        # BASIC STATISTICS
        # ==================================================

        self.packet_count = 0
        self.total_bytes = 0
        self.security_alert_count = 0

        self.protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "HTTP": 0,
            "HTTPS": 0,
            "DNS": 0,
            "FTP": 0,
            "OTHER": 0,
        }

        self.capture_start_time = None

        # ==================================================
        # ML / SECURITY STATISTICS
        # ==================================================

        self.anomaly_count = 0

        self.latest_risk_score = 0
        self.latest_risk_level = "LOW"
        self.latest_anomaly_score = 0

        # ==================================================
        # GRAPH DATA
        # ==================================================

        self.graph_times = []
        self.graph_packet_counts = []
        self.graph_bandwidth = []

        self.last_graph_update = time.time()

        # ==================================================
        # CAPTURE THREAD
        # ==================================================

        self.capture_thread = None
        self.capture_worker = None

        # ==================================================
        # MAIN SCROLL AREA
        # ==================================================

        scroll_area = QScrollArea()

        scroll_area.setWidgetResizable(True)

        scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarAlwaysOff
        )

        scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )

        self.setCentralWidget(
            scroll_area
        )

        # This widget contains the entire dashboard.
        dashboard = QWidget()

        dashboard.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Preferred
        )

        scroll_area.setWidget(
            dashboard
        )

        # ==================================================
        # MAIN DASHBOARD LAYOUT
        # ==================================================

        main_layout = QVBoxLayout(
            dashboard
        )

        main_layout.setContentsMargins(
            8,
            8,
            8,
            8
        )

        main_layout.setSpacing(8)

        # ==================================================
        # TITLE
        # ==================================================

        title = QLabel(
            "Real-Time LAN Packet Sniffer\n"
            "and Protocol Security Inspection System"
        )

        title.setAlignment(
            Qt.AlignCenter
        )

        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                padding: 10px;
            }
        """)

        main_layout.addWidget(
            title
        )

        # ==================================================
        # START / STOP BUTTONS
        # ==================================================

        button_layout = QHBoxLayout()

        self.start_button = QPushButton(
            "Start Capture"
        )

        self.stop_button = QPushButton(
            "Stop Capture"
        )

        self.stop_button.setEnabled(
            False
        )

        self.start_button.clicked.connect(
            self.start_capture
        )

        self.stop_button.clicked.connect(
            self.stop_capture
        )

        button_layout.addWidget(
            self.start_button
        )

        button_layout.addWidget(
            self.stop_button
        )

        main_layout.addLayout(
            button_layout
        )

        # ==================================================
        # BASIC STATISTICS
        # ==================================================

        stats_layout = QHBoxLayout()

        self.packet_count_label = QLabel(
            "Packets: 0"
        )

        self.traffic_label = QLabel(
            "Traffic: 0 B"
        )

        self.bandwidth_label = QLabel(
            "Bandwidth: 0 B/s"
        )

        self.alert_count_label = QLabel(
            "Security Alerts: 0"
        )

        for label in [
            self.packet_count_label,
            self.traffic_label,
            self.bandwidth_label,
            self.alert_count_label,
        ]:

            label.setAlignment(
                Qt.AlignCenter
            )

            label.setMinimumHeight(
                45
            )

            label.setStyleSheet("""
                QLabel {
                    border: 1px solid #cccccc;
                    border-radius: 8px;
                    padding: 8px;
                    font-size: 15px;
                    font-weight: bold;
                }
            """)

            stats_layout.addWidget(
                label
            )

        main_layout.addLayout(
            stats_layout
        )

        # ==================================================
        # ML SECURITY ANALYSIS
        # ==================================================

        ml_group = QGroupBox(
            "ML Security Analysis"
        )

        ml_layout = QVBoxLayout()

        # --------------------------------------------------
        # ML row 1
        # --------------------------------------------------

        ml_row_1 = QHBoxLayout()

        self.risk_score_label = QLabel(
            "Risk Score: 0 / 100"
        )

        self.risk_level_label = QLabel(
            "Risk Level: LOW"
        )

        self.ml_status_label = QLabel(
            "ML Status: NORMAL"
        )

        # --------------------------------------------------
        # ML row 2
        # --------------------------------------------------

        ml_row_2 = QHBoxLayout()

        self.anomaly_count_label = QLabel(
            "Anomalies: 0"
        )

        self.packet_rate_label = QLabel(
            "Packet Rate: 0 packets/s"
        )

        self.window_bandwidth_label = QLabel(
            "Window Bandwidth: 0 B/s"
        )

        # --------------------------------------------------
        # ML row 3
        # --------------------------------------------------

        ml_row_3 = QHBoxLayout()

        self.unique_ports_label = QLabel(
            "Unique Ports: 0"
        )

        self.unique_ips_label = QLabel(
            "Unique IPs: 0"
        )

        self.anomaly_score_label = QLabel(
            "Anomaly Score: 0"
        )

        ml_labels = [
            self.risk_score_label,
            self.risk_level_label,
            self.ml_status_label,
            self.anomaly_count_label,
            self.packet_rate_label,
            self.window_bandwidth_label,
            self.unique_ports_label,
            self.unique_ips_label,
            self.anomaly_score_label,
        ]

        for label in ml_labels:

            label.setAlignment(
                Qt.AlignCenter
            )

            label.setMinimumHeight(
                38
            )

            label.setSizePolicy(
                QSizePolicy.Expanding,
                QSizePolicy.Fixed
            )

            label.setStyleSheet("""
                QLabel {
                    border: 1px solid #cccccc;
                    border-radius: 8px;
                    padding: 6px;
                    font-weight: bold;
                }
            """)

        ml_row_1.addWidget(
            self.risk_score_label
        )

        ml_row_1.addWidget(
            self.risk_level_label
        )

        ml_row_1.addWidget(
            self.ml_status_label
        )

        ml_row_2.addWidget(
            self.anomaly_count_label
        )

        ml_row_2.addWidget(
            self.packet_rate_label
        )

        ml_row_2.addWidget(
            self.window_bandwidth_label
        )

        ml_row_3.addWidget(
            self.unique_ports_label
        )

        ml_row_3.addWidget(
            self.unique_ips_label
        )

        ml_row_3.addWidget(
            self.anomaly_score_label
        )

        ml_layout.addLayout(
            ml_row_1
        )

        ml_layout.addLayout(
            ml_row_2
        )

        ml_layout.addLayout(
            ml_row_3
        )

        ml_group.setLayout(
            ml_layout
        )

        main_layout.addWidget(
            ml_group
        )

        # ==================================================
        # PROTOCOL STATISTICS
        # ==================================================

        protocol_group = QGroupBox(
            "Protocol Statistics"
        )

        protocol_layout = QHBoxLayout()

        self.protocol_labels = {}

        for protocol in self.protocol_counts:

            label = QLabel(
                f"{protocol}: 0"
            )

            label.setAlignment(
                Qt.AlignCenter
            )

            label.setMinimumHeight(
                32
            )

            label.setStyleSheet("""
                QLabel {
                    padding: 6px;
                    border: 1px solid #dddddd;
                    border-radius: 5px;
                }
            """)

            self.protocol_labels[
                protocol
            ] = label

            protocol_layout.addWidget(
                label
            )

        protocol_group.setLayout(
            protocol_layout
        )

        main_layout.addWidget(
            protocol_group
        )

        # ==================================================
        # TRAFFIC ANALYTICS
        # ==================================================

        analytics_group = QGroupBox(
            "Traffic Analytics"
        )

        analytics_layout = QHBoxLayout()

        analytics_layout.setContentsMargins(
            8,
            8,
            8,
            8
        )

        # --------------------------------------------------
        # Protocol Distribution
        # --------------------------------------------------

        protocol_graph_widget = QWidget()

        protocol_graph_layout = QVBoxLayout(
            protocol_graph_widget
        )

        protocol_graph_title = QLabel(
            "Protocol Distribution"
        )

        protocol_graph_title.setAlignment(
            Qt.AlignCenter
        )

        protocol_graph_title.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
            }
        """)

        protocol_graph_layout.addWidget(
            protocol_graph_title
        )

        self.protocol_figure = Figure(
            figsize=(5, 3)
        )

        self.protocol_canvas = FigureCanvas(
            self.protocol_figure
        )

        self.protocol_canvas.setMinimumHeight(
            220
        )

        self.protocol_canvas.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding
        )

        protocol_graph_layout.addWidget(
            self.protocol_canvas
        )

        # --------------------------------------------------
        # Traffic Over Time
        # --------------------------------------------------

        traffic_graph_widget = QWidget()

        traffic_graph_layout = QVBoxLayout(
            traffic_graph_widget
        )

        traffic_graph_title = QLabel(
            "Traffic Over Time"
        )

        traffic_graph_title.setAlignment(
            Qt.AlignCenter
        )

        traffic_graph_title.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
            }
        """)

        traffic_graph_layout.addWidget(
            traffic_graph_title
        )

        self.traffic_figure = Figure(
            figsize=(5, 3)
        )

        self.traffic_canvas = FigureCanvas(
            self.traffic_figure
        )

        self.traffic_canvas.setMinimumHeight(
            220
        )

        self.traffic_canvas.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding
        )

        traffic_graph_layout.addWidget(
            self.traffic_canvas
        )

        analytics_layout.addWidget(
            protocol_graph_widget
        )

        analytics_layout.addWidget(
            traffic_graph_widget
        )

        analytics_group.setLayout(
            analytics_layout
        )

        main_layout.addWidget(
            analytics_group
        )

        # Initial graphs
        self.update_protocol_graph()

        self.update_traffic_graph()

        # ==================================================
        # LIVE PACKET CAPTURE
        # ==================================================

        table_group = QGroupBox(
            "Live Packet Capture"
        )

        table_layout = QVBoxLayout()

        self.packet_table = QTableWidget()

        # The table gets enough space to show
        # multiple packets, but the whole dashboard
        # can still scroll.
        self.packet_table.setMinimumHeight(
            300
        )

        columns = [
            "No.",
            "Time",
            "Protocol",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Length",
            "Security",
        ]

        self.packet_table.setColumnCount(
            len(columns)
        )

        self.packet_table.setHorizontalHeaderLabels(
            columns
        )

        self.packet_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        self.packet_table.setSelectionMode(
            QTableWidget.SingleSelection
        )

        self.packet_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        self.packet_table.setAlternatingRowColors(
            True
        )

        self.packet_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        self.packet_table.itemSelectionChanged.connect(
            self.show_packet_details
        )

        table_layout.addWidget(
            self.packet_table
        )

        table_group.setLayout(
            table_layout
        )

        main_layout.addWidget(
            table_group
        )

        # ==================================================
        # PACKET DETAILS + SECURITY ALERTS
        # ==================================================

        splitter = QSplitter(
            Qt.Horizontal
        )

        splitter.setMinimumHeight(
            300
        )

        # --------------------------------------------------
        # Packet Details
        # --------------------------------------------------

        details_group = QGroupBox(
            "Packet Details"
        )

        details_layout = QFormLayout()

        self.detail_labels = {}

        detail_fields = [
            "Source MAC",
            "Destination MAC",
            "IP Version",
            "Source IP",
            "Destination IP",
            "IP Header Length",
            "Transport Protocol",
            "Source Port",
            "Destination Port",
            "Protocol",
            "Packet Length",
            "Security Warning",
        ]

        for field in detail_fields:

            value_label = QLabel("-")

            value_label.setWordWrap(
                True
            )

            self.detail_labels[
                field
            ] = value_label

            details_layout.addRow(
                QLabel(
                    field + ":"
                ),
                value_label
            )

        details_group.setLayout(
            details_layout
        )

        # --------------------------------------------------
        # Security Alerts
        # --------------------------------------------------

        alerts_group = QGroupBox(
            "Security Alerts / Explanations"
        )

        alerts_layout = QVBoxLayout()

        self.alert_list = QListWidget()

        alerts_layout.addWidget(
            self.alert_list
        )

        alerts_group.setLayout(
            alerts_layout
        )

        splitter.addWidget(
            details_group
        )

        splitter.addWidget(
            alerts_group
        )

        splitter.setSizes(
            [500, 900]
        )

        main_layout.addWidget(
            splitter
        )

        # Small bottom spacing
        main_layout.addSpacing(
            15
        )

    # ==================================================
    # START CAPTURE
    # ==================================================

    def start_capture(self):

        if self.capture_thread is not None:
            return

        # --------------------------------------------------
        # Reset statistics
        # --------------------------------------------------

        self.packet_count = 0

        self.total_bytes = 0

        self.security_alert_count = 0

        self.anomaly_count = 0

        self.latest_risk_score = 0

        self.latest_risk_level = "LOW"

        self.latest_anomaly_score = 0

        self.protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "HTTP": 0,
            "HTTPS": 0,
            "DNS": 0,
            "FTP": 0,
            "OTHER": 0,
        }

        # --------------------------------------------------
        # Reset graphs
        # --------------------------------------------------

        self.graph_times.clear()

        self.graph_packet_counts.clear()

        self.graph_bandwidth.clear()

        self.last_graph_update = time.time()

        self.update_protocol_graph()

        self.update_traffic_graph()

        # --------------------------------------------------
        # Reset packet table
        # --------------------------------------------------

        self.packet_table.setRowCount(
            0
        )

        # --------------------------------------------------
        # Reset alerts
        # --------------------------------------------------

        self.alert_list.clear()

        # --------------------------------------------------
        # Reset protocol labels
        # --------------------------------------------------

        for protocol, label in (
            self.protocol_labels.items()
        ):

            label.setText(
                f"{protocol}: 0"
            )

        # --------------------------------------------------
        # Reset basic statistics
        # --------------------------------------------------

        self.packet_count_label.setText(
            "Packets: 0"
        )

        self.traffic_label.setText(
            "Traffic: 0 B"
        )

        self.bandwidth_label.setText(
            "Bandwidth: 0 B/s"
        )

        self.alert_count_label.setText(
            "Security Alerts: 0"
        )

        # --------------------------------------------------
        # Reset ML dashboard
        # --------------------------------------------------

        self.risk_score_label.setText(
            "Risk Score: 0 / 100"
        )

        self.risk_level_label.setText(
            "Risk Level: LOW"
        )

        self.ml_status_label.setText(
            "ML Status: NORMAL"
        )

        self.anomaly_count_label.setText(
            "Anomalies: 0"
        )

        self.packet_rate_label.setText(
            "Packet Rate: 0 packets/s"
        )

        self.window_bandwidth_label.setText(
            "Window Bandwidth: 0 B/s"
        )

        self.unique_ports_label.setText(
            "Unique Ports: 0"
        )

        self.unique_ips_label.setText(
            "Unique IPs: 0"
        )

        self.anomaly_score_label.setText(
            "Anomaly Score: 0"
        )

        # --------------------------------------------------
        # Reset packet details
        # --------------------------------------------------

        for label in self.detail_labels.values():

            label.setText("-")

        # --------------------------------------------------
        # Start timer
        # --------------------------------------------------

        self.capture_start_time = time.time()

        # --------------------------------------------------
        # Button state
        # --------------------------------------------------

        self.start_button.setEnabled(
            False
        )

        self.stop_button.setEnabled(
            True
        )

        # --------------------------------------------------
        # Create thread
        # --------------------------------------------------

        self.capture_thread = QThread()

        self.capture_worker = CaptureWorker()

        self.capture_worker.moveToThread(
            self.capture_thread
        )

        # --------------------------------------------------
        # Connect signals
        # --------------------------------------------------

        self.capture_thread.started.connect(
            self.capture_worker.start
        )

        self.capture_worker.packet_received.connect(
            self.receive_packet
        )

        if hasattr(
            self.capture_worker,
            "security_received"
        ):

            self.capture_worker.security_received.connect(
                self.receive_security_result
            )

        self.capture_worker.capture_finished.connect(
            self.capture_finished
        )

        self.capture_worker.capture_error.connect(
            self.capture_error
        )

        self.capture_worker.capture_finished.connect(
            self.capture_thread.quit
        )

        self.capture_worker.capture_finished.connect(
            self.capture_worker.deleteLater
        )

        self.capture_thread.finished.connect(
            self.capture_thread.deleteLater
        )

        self.capture_thread.finished.connect(
            self.thread_finished
        )

        # --------------------------------------------------
        # Start
        # --------------------------------------------------

        self.capture_thread.start()

        print(
            "Capture started"
        )

    # ==================================================
    # STOP CAPTURE
    # ==================================================

    def stop_capture(self):

        if self.capture_worker is None:
            return

        self.capture_worker.stop()

    # ==================================================
    # PACKET RECEIVED
    # ==================================================

    def receive_packet(
        self,
        data
    ):

        self.packet_count += 1

        packet_length = (
            data.get(
                "packet_length"
            )
            or 0
        )

        self.total_bytes += (
            packet_length
        )

        protocol = (
            data.get(
                "protocol"
            )
            or "OTHER"
        )

        if protocol not in self.protocol_counts:

            protocol = "OTHER"

        self.protocol_counts[
            protocol
        ] += 1

        # --------------------------------------------------
        # Security warning
        # --------------------------------------------------

        security_warning = data.get(
            "security_warning"
        )

        if security_warning:

            self.security_alert_count += 1

            self.alert_list.insertItem(
                0,
                "⚠ "
                + security_warning
            )

        # --------------------------------------------------
        # Basic statistics
        # --------------------------------------------------

        self.packet_count_label.setText(
            f"Packets: "
            f"{self.packet_count}"
        )

        self.traffic_label.setText(
            "Traffic: "
            + self.format_bytes(
                self.total_bytes
            )
        )

        if self.capture_start_time:

            elapsed = (
                time.time()
                - self.capture_start_time
            )

            if elapsed > 0:

                bandwidth = (
                    self.total_bytes
                    / elapsed
                )

                self.bandwidth_label.setText(
                    "Bandwidth: "
                    + self.format_bytes(
                        bandwidth
                    )
                    + "/s"
                )

        self.alert_count_label.setText(
            "Security Alerts: "
            f"{self.security_alert_count}"
        )

        # --------------------------------------------------
        # Protocol counters
        # --------------------------------------------------

        for (
            protocol_name,
            label
        ) in self.protocol_labels.items():

            label.setText(
                f"{protocol_name}: "
                f"{self.protocol_counts[protocol_name]}"
            )

        # --------------------------------------------------
        # Add packet to table
        # --------------------------------------------------

        row = (
            self.packet_table.rowCount()
        )

        self.packet_table.insertRow(
            row
        )

        current_time = time.strftime(
            "%H:%M:%S"
        )

        values = [
            str(
                self.packet_count
            ),

            current_time,

            data.get(
                "protocol"
            )
            or "-",

            data.get(
                "source_ip"
            )
            or "-",

            data.get(
                "destination_ip"
            )
            or "-",

            str(
                data.get(
                    "source_port"
                )
                if data.get(
                    "source_port"
                ) is not None
                else "-"
            ),

            str(
                data.get(
                    "destination_port"
                )
                if data.get(
                    "destination_port"
                ) is not None
                else "-"
            ),

            str(
                packet_length
            ),

            security_warning
            or "-",
        ]

        for column, value in enumerate(
            values
        ):

            item = QTableWidgetItem(
                value
            )

            self.packet_table.setItem(
                row,
                column,
                item
            )

        # --------------------------------------------------
        # Store complete packet data
        # --------------------------------------------------

        first_item = (
            self.packet_table.item(
                row,
                0
            )
        )

        if first_item is not None:

            first_item.setData(
                Qt.UserRole,
                data
            )

        # --------------------------------------------------
        # Automatically select first packet
        # --------------------------------------------------

        if row == 0:

            self.packet_table.selectRow(
                0
            )

        # --------------------------------------------------
        # Graph update
        # --------------------------------------------------

        current_time_seconds = (
            time.time()
        )

        if (
            current_time_seconds
            - self.last_graph_update
            >= 1
        ):

            elapsed = 0

            if self.capture_start_time:

                elapsed = (
                    current_time_seconds
                    - self.capture_start_time
                )

            self.graph_times.append(
                round(
                    elapsed,
                    1
                )
            )

            self.graph_packet_counts.append(
                self.packet_count
            )

            if elapsed > 0:

                current_bandwidth = (
                    self.total_bytes
                    / elapsed
                )

            else:

                current_bandwidth = 0

            self.graph_bandwidth.append(
                current_bandwidth
            )

            # Keep last 60 points
            if len(
                self.graph_times
            ) > 60:

                self.graph_times.pop(
                    0
                )

                self.graph_packet_counts.pop(
                    0
                )

                self.graph_bandwidth.pop(
                    0
                )

            self.update_protocol_graph()

            self.update_traffic_graph()

            self.last_graph_update = (
                current_time_seconds
            )

    # ==================================================
    # ML SECURITY RESULT
    # ==================================================

    def receive_security_result(
        self,
        result
    ):

        if not result:
            return

        risk_score = result.get(
            "risk_score",
            0
        )

        risk_level = result.get(
            "risk_level",
            "LOW"
        )

        is_anomaly = result.get(
            "is_anomaly",
            False
        )

        reasons = result.get(
            "reasons",
            []
        )

        anomaly_score = result.get(
            "anomaly_score",
            0
        )

        packet_rate = result.get(
            "packet_rate",
            0
        )

        bytes_per_second = result.get(
            "bytes_per_second",
            0
        )

        unique_ports = result.get(
            "unique_destination_ports",
            0
        )

        unique_ips = result.get(
            "unique_destination_ips",
            0
        )

        # --------------------------------------------------
        # Count anomaly windows
        # --------------------------------------------------

        if is_anomaly:

            self.anomaly_count += 1

        # --------------------------------------------------
        # Store latest values
        # --------------------------------------------------

        self.latest_risk_score = (
            risk_score
        )

        self.latest_risk_level = (
            risk_level
        )

        self.latest_anomaly_score = (
            anomaly_score
        )

        # --------------------------------------------------
        # Update labels
        # --------------------------------------------------

        self.risk_score_label.setText(
            f"Risk Score: "
            f"{risk_score} / 100"
        )

        self.risk_level_label.setText(
            f"Risk Level: "
            f"{risk_level}"
        )

        if is_anomaly:

            self.ml_status_label.setText(
                "ML Status: ANOMALY"
            )

        else:

            self.ml_status_label.setText(
                "ML Status: NORMAL"
            )

        self.anomaly_count_label.setText(
            f"Anomalies: "
            f"{self.anomaly_count}"
        )

        self.packet_rate_label.setText(
            "Packet Rate: "
            f"{packet_rate:.2f} packets/s"
        )

        self.window_bandwidth_label.setText(
            "Window Bandwidth: "
            + self.format_bytes(
                bytes_per_second
            )
            + "/s"
        )

        self.unique_ports_label.setText(
            f"Unique Ports: "
            f"{unique_ports}"
        )

        self.unique_ips_label.setText(
            f"Unique IPs: "
            f"{unique_ips}"
        )

        self.anomaly_score_label.setText(
            f"Anomaly Score: "
            f"{anomaly_score:.4f}"
        )

        # --------------------------------------------------
        # Security explanations
        # --------------------------------------------------

        self.alert_list.clear()

        if reasons:

            for reason in reasons:

                self.alert_list.addItem(
                    "• "
                    + str(reason)
                )

        else:

            self.alert_list.addItem(
                "• No unusual behavior detected"
            )

        self.alert_list.addItem(
            ""
        )

        self.alert_list.addItem(
            f"Risk Score: "
            f"{risk_score}/100"
        )

        self.alert_list.addItem(
            ""
        )

        if risk_level == "CRITICAL":

            self.alert_list.addItem(
                "⚠ CRITICAL RISK"
            )

        elif risk_level == "HIGH":

            self.alert_list.addItem(
                "⚠ HIGH RISK"
            )

        elif risk_level == "MEDIUM":

            self.alert_list.addItem(
                "⚠ MEDIUM RISK"
            )

        else:

            self.alert_list.addItem(
                "✓ LOW RISK"
            )

    # ==================================================
    # PROTOCOL GRAPH
    # ==================================================

    def update_protocol_graph(
        self
    ):

        self.protocol_figure.clear()

        ax = (
            self.protocol_figure.add_subplot(
                111
            )
        )

        protocols = list(
            self.protocol_counts.keys()
        )

        values = [
            self.protocol_counts[
                protocol
            ]
            for protocol in protocols
        ]

        ax.bar(
            protocols,
            values
        )

        ax.set_title(
            "Protocol Distribution"
        )

        ax.set_ylabel(
            "Packets"
        )

        ax.tick_params(
            axis="x",
            rotation=30
        )

        self.protocol_figure.tight_layout()

        self.protocol_canvas.draw_idle()

    # ==================================================
    # TRAFFIC OVER TIME GRAPH
    # ==================================================

    def update_traffic_graph(
        self
    ):

        self.traffic_figure.clear()

        ax = (
            self.traffic_figure.add_subplot(
                111
            )
        )

        if not self.graph_times:

            ax.set_title(
                "Traffic Over Time"
            )

            ax.set_xlabel(
                "Time (seconds)"
            )

            ax.set_ylabel(
                "Packets"
            )

            self.traffic_figure.tight_layout()

            self.traffic_canvas.draw_idle()

            return

        ax.plot(
            self.graph_times,
            self.graph_packet_counts,
            marker="o"
        )

        ax.set_title(
            "Packets Over Time"
        )

        ax.set_xlabel(
            "Time (seconds)"
        )

        ax.set_ylabel(
            "Packets"
        )

        ax.grid(
            True,
            alpha=0.3
        )

        self.traffic_figure.tight_layout()

        self.traffic_canvas.draw_idle()

    # ==================================================
    # PACKET DETAILS
    # ==================================================

    def show_packet_details(
        self
    ):

        selected_items = (
            self.packet_table.selectedItems()
        )

        if not selected_items:
            return

        row = selected_items[
            0
        ].row()

        item = self.packet_table.item(
            row,
            0
        )

        if item is None:
            return

        data = item.data(
            Qt.UserRole
        )

        if not data:
            return

        field_mapping = {

            "Source MAC":
                "source_mac",

            "Destination MAC":
                "destination_mac",

            "IP Version":
                "ip_version",

            "Source IP":
                "source_ip",

            "Destination IP":
                "destination_ip",

            "IP Header Length":
                "ip_header_length",

            "Transport Protocol":
                "transport",

            "Source Port":
                "source_port",

            "Destination Port":
                "destination_port",

            "Protocol":
                "protocol",

            "Packet Length":
                "packet_length",

            "Security Warning":
                "security_warning",
        }

        for field, key in (
            field_mapping.items()
        ):

            value = data.get(
                key
            )

            if value is None:

                value = "-"

            self.detail_labels[
                field
            ].setText(
                str(value)
            )

    # ==================================================
    # CAPTURE FINISHED
    # ==================================================

    def capture_finished(
        self
    ):

        self.start_button.setEnabled(
            True
        )

        self.stop_button.setEnabled(
            False
        )

    # ==================================================
    # THREAD FINISHED
    # ==================================================

    def thread_finished(
        self
    ):

        self.capture_thread = None

        self.capture_worker = None

    # ==================================================
    # CAPTURE ERROR
    # ==================================================

    def capture_error(
        self,
        error
    ):

        self.start_button.setEnabled(
            True
        )

        self.stop_button.setEnabled(
            False
        )

        QMessageBox.critical(
            self,
            "Capture Error",
            "Unable to start packet capture.\n\n"
            + error
        )

    # ==================================================
    # WINDOW CLOSE
    # ==================================================

    def closeEvent(
        self,
        event
    ):

        if self.capture_worker is not None:

            self.capture_worker.stop()

        event.accept()

    # ==================================================
    # BYTE FORMATTER
    # ==================================================

    @staticmethod
    def format_bytes(
        value
    ):

        if value < 1024:

            return (
                f"{value:.1f} B"
            )

        if value < 1024 * 1024:

            return (
                f"{value / 1024:.1f} KB"
            )

        if value < 1024 * 1024 * 1024:

            return (
                f"{value / (1024 * 1024):.1f} MB"
            )

        return (
            f"{value / (1024 * 1024 * 1024):.1f} GB"
        )


# ======================================================
# APPLICATION
# ======================================================

if __name__ == "__main__":

    app = QApplication(
        sys.argv
    )

    window = MainWindow()

    window.show()

    sys.exit(
        app.exec()
    )