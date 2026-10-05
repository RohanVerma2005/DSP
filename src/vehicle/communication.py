import socket
import threading
from typing import Callable, Optional, Dict, Any

from src.utils.message_utils import canonical_dumps, canonical_loads


class V2VChannel:
    """Manages UDP broadcast transmission and reception for vehicle nodes."""

    def __init__(self, port: int = 5005, bind_ip: str = "0.0.0.0"):
        self.port = port
        self.bind_ip = bind_ip
        self.running = False

        # Sockets
        self._tx_sock: Optional[socket.socket] = None
        self._rx_sock: Optional[socket.socket] = None
        self._listener_thread: Optional[threading.Thread] = None

    def start_listener(self, on_message_received: Callable[[Dict[str, Any], tuple], None]) -> None:
        """Starts a background listening thread that receives inbound broadcast packets."""
        self._rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Windows-specific broadcast sharing flag if supported
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self._rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass

        self._rx_sock.bind((self.bind_ip, self.port))
        self.running = True

        def listen_loop():
            while self.running:
                try:
                    data, addr = self._rx_sock.recvfrom(65535)
                    parsed_packet = canonical_loads(data)
                    on_message_received(parsed_packet, addr)
                except (OSError, ValueError):
                    break

        self._listener_thread = threading.Thread(target=listen_loop, daemon=True)
        self._listener_thread.start()

    def broadcast(self, packet: Dict[str, Any], target_port: Optional[int] = None) -> None:
        """Broadcasts a structured packet over UDP."""
        dest_port = target_port if target_port is not None else self.port
        if self._tx_sock is None:
            self._tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        raw_bytes = canonical_dumps(packet)
        # Use 127.0.0.1 or <broadcast> for local loopback testing
        self._tx_sock.sendto(raw_bytes, ("127.0.0.1", dest_port))

    def close(self) -> None:
        """Shuts down transmitter and receiver sockets."""
        self.running = False
        if self._rx_sock:
            self._rx_sock.close()
        if self._tx_sock:
            self._tx_sock.close()
        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=0.5)