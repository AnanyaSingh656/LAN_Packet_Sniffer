from PySide6.QtCore import QObject, Signal, Slot

from packet_sniffer import start_capture


class CaptureWorker(QObject):
    """
    Runs the existing Scapy packet capture outside
    the GUI's main thread.
    """

    packet_received = Signal(dict)
    capture_finished = Signal()
    capture_error = Signal(str)

    @Slot()
    def start(self):
        """
        Start Ananya's existing packet capture.

        The callback sends each parsed packet dictionary
        to the GUI through a Qt signal.
        """

        try:
            start_capture(
                callback=self.packet_received.emit
            )

        except Exception as error:
            self.capture_error.emit(str(error))

        finally:
            self.capture_finished.emit()