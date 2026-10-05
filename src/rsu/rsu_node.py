import time
import uuid
from typing import Dict, Any, Set, Optional
from cryptography.hazmat.primitives.asymmetric import ec

from src.utils.crypto_utils import (
    generate_ecc_keypair,
    public_key_to_pem,
    pem_to_public_key,
    sign_data,
    verify_signature
)


class RSUকারNode:
    """Roadside Unit (RSU) for infrastructure-to-vehicle (I2V) safety and CRL propagation."""

    def __init__(self, rsu_id: str, ta_public_key: ec.EllipticCurvePublicKey, rsu_cert: Optional[Dict[str, Any]] = None,
                 rsu_private_key: Optional[ec.EllipticCurvePrivateKey] = None):
        self.rsu_id = rsu_id
        self.ta_public_key = ta_public_key

        # Use provided registered keypair or generate standalone
        if rsu_private_key is not None:
            self.private_key = rsu_private_key
            self.public_key = rsu_private_key.public_key()
        else:
            self.private_key, self.public_key = generate_ecc_keypair()

        self.certificate = rsu_cert
        self.cached_revoked_serials: Set[str] = set()

    def receive_crl_update(self, crl_bundle: Dict[str, Any]) -> bool:
        """Verifies TA root signature and updates the RSU's local CRL cache."""
        crl_data = crl_bundle.get("crl_data", {})
        ta_sig = crl_bundle.get("ta_signature", "")

        if not verify_signature(self.ta_public_key, crl_data, ta_sig):
            return False

        revoked = crl_data.get("revoked_serials", [])
        self.cached_revoked_serials.update(revoked)
        return True

    def create_road_hazard_alert(
            self,
            hazard_type: str = "BLACK_ICE",
            latitude: float = 37.77580,
            longitude: float = -122.41940,
            recommended_speed_kmh: float = 30.0
    ) -> Dict[str, Any]:
        """
        Constructs an authenticated I2V advisory message signed with RSU credentials.
        """
        header = {
            "protocol_version": "1.0",
            "message_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "message_type": "ROAD_HAZARD"
        }

        payload = {
            "rsu_id": self.rsu_id,
            "hazard_type": hazard_type,
            "latitude": latitude,
            "longitude": longitude,
            "recommended_speed_kmh": recommended_speed_kmh,
            "severity": "CRITICAL"
        }

        body = {
            "header": header,
            "payload": payload
        }

        rsu_sig = sign_data(self.private_key, body)

        return {
            "body": body,
            "sender_certificate": self.certificate,
            "signature": rsu_sig
        }