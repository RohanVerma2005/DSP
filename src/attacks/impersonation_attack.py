import time
import uuid
from typing import Dict, Any
from src.utils.crypto_utils import generate_ecc_keypair, sign_data, public_key_to_pem

class ImpersonationAttacker:
    """Attempts to spoof an emergency vehicle priority beacon."""

    def __init__(self):
        self.rogue_priv, self.rogue_pub = generate_ecc_keypair()

    def craft_fake_emergency_alert(self) -> Dict[str, Any]:
        """Crafts an emergency vehicle broadcast without valid authorization."""
        bogus_cert_data = {
            "serial_number": "ROGUE-EMERGENCY-01",
            "pseudonym_id": "PSEUDO-AMBULANCE-99",
            "public_key_pem": public_key_to_pem(self.rogue_pub),
            "valid_from": time.time() - 5,
            "valid_to": time.time() + 600
        }
        # Self-signed, invalid TA authority
        bogus_ta_sig = sign_data(self.rogue_priv, bogus_cert_data)

        body = {
            "header": {
                "protocol_version": "1.0",
                "message_id": str(uuid.uuid4()),
                "seq_no": 1,
                "timestamp": time.time(),
                "message_type": "EMERGENCY_BRAKE"
            },
            "payload": {
                "latitude": 37.7750,
                "longitude": -122.4190,
                "speed_kmh": 110.0,
                "heading_deg": 0.0
            }
        }
        sig = sign_data(self.rogue_priv, body)

        return {
            "body": body,
            "sender_certificate": {
                "certificate_data": bogus_cert_data,
                "ta_signature": bogus_ta_sig
            },
            "signature": sig
        }