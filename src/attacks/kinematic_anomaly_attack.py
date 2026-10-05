from typing import Dict, Any
from src.vehicle.vehicle_node import VehicleNode

class KinematicAttacker:
    """Simulates an enrolled vehicle emitting physically impossible telemetry."""

    @staticmethod
    def craft_excessive_speed_beacon(node: VehicleNode) -> Dict[str, Any]:
        # Broadcasts 350 km/h (exceeds MAX_PLAUSIBLE_SPEED_KMH = 250 km/h)
        return node.create_safety_message(speed_kmh=350.0)

    @staticmethod
    def craft_teleportation_beacon(node: VehicleNode) -> Dict[str, Any]:
        # Jumps 2 km within a few milliseconds
        return node.create_safety_message(latitude=node.current_lat + 0.02, speed_kmh=60.0)