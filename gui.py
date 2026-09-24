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
)

from capture_worker import CaptureWorker


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle(
            "Real-Time LAN Packet Sniffer and "
            "Protocol Security Inspection System"
        )

        self.resize(1400, 850)

        # ==========================================
        # Statistics
        # ==========================================

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

        # ==========================================
        # Capture thread
        # ==========================================

        self.capture_thread = None
        self.capture_worker = None

        # ==========================================
        # Main widget
        # ==========================================

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        # ==========================================
        # Title
        # ==========================================

        title = QLabel(
            "Real-Time LAN Packet Sniffer\n"
            "and Protocol Security Inspection System"
        )

        title.setAlignment(Qt.AlignCenter)

        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                padding: 15px;
            }
        """)

        main_layout.addWidget(title)

        # ==========================================
        # Capture buttons
        # ==========================================

        button_layout = QHBoxLayout()

        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop Capture")

        self.stop_button.setEnabled(False)

        self.start_button.clicked.connect(
            self.start_capture
        )

        self.stop_button.clicked.connect(
            self.stop_capture
        )

        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)

        main_layout.addLayout(button_layout)

        # ==========================================
        # Statistics cards
        # ==========================================

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

            label.setAlignment(Qt.AlignCenter)

            label.setStyleSheet("""
                QLabel {
                    border: 1px solid #cccccc;
                    border-radius: 8px;
                    padding: 15px;
                    font-size: 16px;
                    font-weight: bold;
                }
            """)

            stats_layout.addWidget(label)

        main_layout.addLayout(stats_layout)

        # ==========================================
        # Protocol statistics
        # ==========================================

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

            label.setStyleSheet("""
                QLabel {
                    padding: 8px;
                    border: 1px solid #dddddd;
                    border-radius: 5px;
                }
            """)

            self.protocol_labels[
                protocol
            ] = label

            protocol_layout.addWidget(label)

        protocol_group.setLayout(
            protocol_layout
        )

        main_layout.addWidget(
            protocol_group
        )

        # ==========================================
        # Live packet table
        # ==========================================

        table_group = QGroupBox(
            "Live Packet Capture"
        )

        table_layout = QVBoxLayout()

        self.packet_table = QTableWidget()

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

        self.packet_table.setEditTriggers(
            QTableWidget.NoEditTriggers
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

        # ==========================================
        # Lower section
        # ==========================================

        splitter = QSplitter(
            Qt.Horizontal
        )

        # ==========================================
        # Packet details
        # ==========================================

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

            value_label.setWordWrap(True)

            self.detail_labels[
                field
            ] = value_label

            details_layout.addRow(
                QLabel(field + ":"),
                value_label
            )

        details_group.setLayout(
            details_layout
        )

        # ==========================================
        # Security alerts
        # ==========================================

        alerts_group = QGroupBox(
            "Security Alerts"
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

        # ==========================================
        # Add sections to main layout
        # ==========================================

        main_layout.addWidget(
            table_group
        )

        main_layout.addWidget(
            splitter
        )

    # ==================================================
    # START CAPTURE
    # ==================================================

    def start_capture(self):

        if self.capture_thread is not None:
            return

        self.capture_start_time = time.time()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.capture_thread = QThread()

        self.capture_worker = CaptureWorker()

        self.capture_worker.moveToThread(
            self.capture_thread
        )

        self.capture_thread.started.connect(
            self.capture_worker.start
        )

        self.capture_worker.packet_received.connect(
            self.receive_packet
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

        self.capture_thread.start()

        print("Capture started")

    # ==================================================
    # STOP CAPTURE
    # ==================================================

    def stop_capture(self):

        """
        The current backend does not yet expose a
        stop mechanism for Scapy sniff().
        
        Therefore this function currently stops the
        GUI from starting another capture, but the
        running Scapy capture must be stopped by
        closing the application or by adding a
        backend stop_event later.
        """

        if self.capture_worker is None:
            return

        QMessageBox.information(
            self,
            "Capture Stop",
            "The capture worker is running.\n\n"
            "The backend currently does not expose "
            "a Scapy stop event. A small backend "
            "change is required for a fully functional "
            "Stop Capture button."
        )

    # ==================================================
    # PACKET RECEIVED
    # ==================================================

    def receive_packet(self, data):

        self.packet_count += 1

        packet_length = (
            data.get("packet_length") or 0
        )

        self.total_bytes += packet_length

        protocol = (
            data.get("protocol")
            or "OTHER"
        )

        if protocol not in self.protocol_counts:
            protocol = "OTHER"

        self.protocol_counts[
            protocol
        ] += 1

        # ----------------------------------------------
        # Security warning
        # ----------------------------------------------

        security_warning = data.get(
            "security_warning"
        )

        if security_warning:

            self.security_alert_count += 1

            self.alert_list.insertItem(
                0,
                "⚠ " + security_warning
            )

        # ----------------------------------------------
        # Dashboard
        # ----------------------------------------------

        self.packet_count_label.setText(
            f"Packets: {self.packet_count}"
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
            f"Security Alerts: "
            f"{self.security_alert_count}"
        )

        # ----------------------------------------------
        # Protocol counters
        # ----------------------------------------------

        for protocol_name, label in (
            self.protocol_labels.items()
        ):

            label.setText(
                f"{protocol_name}: "
                f"{self.protocol_counts[protocol_name]}"
            )

        # ----------------------------------------------
        # Packet table
        # ----------------------------------------------

        row = self.packet_table.rowCount()

        self.packet_table.insertRow(row)

        current_time = time.strftime(
            "%H:%M:%S"
        )

        values = [
            str(self.packet_count),
            current_time,
            data.get("protocol") or "-",
            data.get("source_ip") or "-",
            data.get("destination_ip") or "-",
            str(
                data.get("source_port")
                if data.get("source_port") is not None
                else "-"
            ),
            str(
                data.get("destination_port")
                if data.get("destination_port") is not None
                else "-"
            ),
            str(packet_length),
            security_warning or "-",
        ]

        for column, value in enumerate(values):

            item = QTableWidgetItem(
                value
            )

            self.packet_table.setItem(
                row,
                column,
                item
            )

        # Store complete packet dictionary
        # inside the first cell of the row.

        self.packet_table.item(
            row,
            0
        ).setData(
            Qt.UserRole,
            data
        )

    # ==================================================
    # PACKET DETAILS
    # ==================================================

    def show_packet_details(self):

        selected_items = (
            self.packet_table.selectedItems()
        )

        if not selected_items:
            return

        row = selected_items[0].row()

        item = self.packet_table.item(
            row,
            0
        )

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

            value = data.get(key)

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

    def capture_finished(self):

        self.start_button.setEnabled(True)

        self.stop_button.setEnabled(False)

    # ==================================================
    # THREAD FINISHED
    # ==================================================

    def thread_finished(self):

        self.capture_thread = None
        self.capture_worker = None

    # ==================================================
    # CAPTURE ERROR
    # ==================================================

    def capture_error(self, error):

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        QMessageBox.critical(
            self,
            "Capture Error",
            "Unable to start packet capture.\n\n"
            + error
        )

    # ==================================================
    # WINDOW CLOSE
    # ==================================================

    def closeEvent(self, event):

        if self.capture_worker is not None:

            self.capture_worker.stop()

        event.accept()

    # ==================================================
    # BYTE FORMATTER
    # ==================================================

    @staticmethod
    def format_bytes(value):

        if value < 1024:

            return f"{value:.1f} B"

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

app = QApplication(sys.argv)

window = MainWindow()

window.show()

sys.exit(app.exec())