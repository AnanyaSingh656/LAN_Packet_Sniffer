import threading

from PySide6.QtCore import (
    QObject,
    Signal,
    Slot
)

from packet_sniffer import start_capture
from security_bridge import SecurityBridge


class CaptureWorker(QObject):

    packet_received = Signal(dict)

    security_received = Signal(dict)

    capture_finished = Signal()

    capture_error = Signal(str)

    def __init__(self):
        super().__init__()

        self.stop_event = threading.Event()

        self.security_bridge = None

    @Slot()
    def start(self):

        self.stop_event.clear()

        try:

            # Create the ML/security bridge
            self.security_bridge = SecurityBridge()

            start_capture(
                callback=self.process_packet,
                stop_event=self.stop_event
            )

        except Exception as error:

            self.capture_error.emit(
                str(error)
            )

        finally:

            self.capture_finished.emit()

    def process_packet(self, data):

        # ------------------------------------------
        # Send packet to GUI
        # ------------------------------------------

        self.packet_received.emit(
            data
        )

        # ------------------------------------------
        # Send packet through ML security pipeline
        # ------------------------------------------

        if self.security_bridge is not None:

            try:

                security_result = (
                    self.security_bridge.process_packet(
                        data
                    )
                )

                # A result is generated only
                # after a complete 5-second window
                if security_result is not None:

                    self.security_received.emit(
                        security_result
                    )

            except Exception as error:

                self.capture_error.emit(
                    "Security analysis error: "
                    + str(error)
                )

    @Slot()
    def stop(self):

        self.stop_event.set()