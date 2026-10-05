from typing import List, Dict, Any

class DoSAttacker:
    """Generates structural deformities to test defensive parsing resilience."""

    @staticmethod
    def generate_malformed_packets(count: int = 5) -> List[Dict[str, Any]]:
        packets = [
            {},  # Empty
            {"body": "corrupt_string_not_dict"},  # Type corruption
            {"body": {}, "signature": "abc"},  # Missing certificates
            {"body": {"header": {}}, "sender_certificate": {}},  # Incomplete fields
            {"malformed": True}  # Unknown protocol structure
        ]
        return packets[:count]