from typing import Dict, Any
from src.vehicle.vehicle_node import VehicleNode

class GeocastAttacker:
    """Generates validly signed messages from vehicles too far away to matter."""

    @staticmethod
    def craft_distant_beacon(node: VehicleNode) -> Dict[str, Any]:
        # Position vehicle 10km away (~0.09 degrees latitude offset)
        distant_lat = node.current_lat + 0.09
        distant_lon = node.current_lon
        return node.create_safety_message(latitude=distant_lat, longitude=distant_lon)