import time
import uuid
from typing import List, Dict, Any
from src.utils.crypto_utils import generate_ecc_keypair, sign_data, public_key_to_pem


class SybilAttacker:
    """Generates multiple ghost vehicular identities to deceive traffic flow."""

    def __init__(self):
        pass

    def generate_ghost_beacons(self, count: int = 5) -> List[Dict[str, Any]]:
        """
        Generates packets claiming to be distinct vehicles.
        Because the attacker lacks TA private keys, certificates are self-generated
        and must fail TA signature verification at receiver stage 3.
        """
        ghost_packets = []
        for i in range(count):
            priv, pub = generate_ecc_keypair()
            fake_pseudo_id = f"PSEUDO-GHOST-{i:03d}"

            fake_cert_data = {
                "serial_number": str(uuid.uuid4()),
                "pseudonym_id": fake_pseudo_id,
                "public_key_pem": public_key_to_pem(pub),
                "valid_from": time.time() - 10,
                "valid_to": time.time() + 300
            }
            # Forged self-signature masquerading as TA
            forged_ta_sig = sign_data(priv, fake_cert_data)

            fake_cert = {
                "certificate_data": fake_cert_data,
                "ta_signature": forged_ta_sig
            }

            body = {
                "header": {
                    "protocol_version": "1.0",
                    "message_id": str(uuid.uuid4()),
                    "seq_no": 1,
                    "timestamp": time.time(),
                    "message_type": "BEACON"
                },
                "payload": {
                    "latitude": 37.7749 + (i * 0.001),
                    "longitude": -122.4194 + (i * 0.001),
                    "speed_kmh": 30.0,
                    "heading_deg": 90.0
                }
            }

            body_sig = sign_data(priv, body)

            ghost_packets.append({
                "body": body,
                "sender_certificate": fake_cert,
                "signature": body_sig
            })

        return ghost_packets