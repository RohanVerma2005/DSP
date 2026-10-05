import copy
from typing import Dict, Any

class ReplayAttacker:
    """Simulates passive eavesdropping and re-broadcasting of recorded authentic messages."""

    def __init__(self):
        self.captured_packets = []

    def capture_message(self, packet: Dict[str, Any]) -> None:
        """Saves a legitimate packet captured off the wireless medium."""
        self.captured_packets.append(copy.deepcopy(packet))

    def craft_delayed_replay(self, index: int = -1) -> Dict[str, Any]:
        """
        Returns a captured packet as-is.
        When transmitted later, it will violate receiver timestamp freshness constraints.
        """
        if not self.captured_packets:
            raise ValueError("No packets captured to replay.")
        return copy.deepcopy(self.captured_packets[index])