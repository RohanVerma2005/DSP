import copy
from typing import Dict, Any

class TamperingAttacker:
    """Simulates MITM modification of safety-critical telemetry fields."""

    @staticmethod
    def modify_telemetry(
        packet: Dict[str, Any],
        fake_speed: float = 0.0,
        fake_event: str = "EMERGENCY_BRAKE"
    ) -> Dict[str, Any]:
        """
        Modifies payload fields while retaining the original digital signature.
        This must trigger verification failure at receiver stage 4.
        """
        tampered = copy.deepcopy(packet)
        body = tampered.get("body", {})
        payload = body.get("payload", {})
        header = body.get("header", {})

        payload["speed_kmh"] = fake_speed
        header["message_type"] = fake_event

        return tampered