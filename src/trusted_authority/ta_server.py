import time
from typing import Dict, Any, Optional
from src.utils.crypto_utils import generate_ecc_keypair, public_key_to_pem, sign_data
from src.trusted_authority.certificate_manager import CertificateManager
from src.trusted_authority.crl_manager import CRLManager

class TrustedAuthority:
    """Central PKI root orchestrator for vehicle registration and identity management."""

    def __init__(self):
        # Generate Master Root Keypair
        self.master_private_key, self.master_public_key = generate_ecc_keypair()
        self.cert_manager = CertificateManager(self.master_private_key, self.master_public_key)
        self.crl_manager = CRLManager()

        # Simulated secure registry: VID -> metadata
        self._registered_vehicles: Dict[str, Dict[str, Any]] = {}

    def get_public_key_pem(self) -> str:
        """Returns the TA root public key in PEM format."""
        return public_key_to_pem(self.master_public_key)

    def register_vehicle(self, real_vid: str, vehicle_type: str = "PERSONAL_CAR") -> bool:
        """Registers a vehicle hardware ID into the TA database."""
        if real_vid in self._registered_vehicles:
            return False
        self._registered_vehicles[real_vid] = {
            "vehicle_type": vehicle_type,
            "registered_at": time.time(),
            "status": "ACTIVE"
        }
        return True

    def request_pseudonyms(self, real_vid: str, count: int = 5) -> Optional[list]:
        """Issues a batch of pseudonym certificates if the vehicle is registered and active."""
        vehicle = self._registered_vehicles.get(real_vid)
        if not vehicle or vehicle["status"] != "ACTIVE":
            return None
        return self.cert_manager.issue_pseudonym_batch(real_vid=real_vid, batch_size=count)

    def revoke_vehicle(self, real_vid: str, cert_serials: list) -> None:
        """Revokes a vehicle and adds all its active pseudonym serials to the CRL."""
        if real_vid in self._registered_vehicles:
            self._registered_vehicles[real_vid]["status"] = "REVOKED"
        for serial in cert_serials:
            self.crl_manager.revoke_certificate(serial, reason=f"VID_{real_vid}_REVOKED")

    def enroll_rsu(self, rsu_id: str) -> Dict[str, Any]:
        """Issues an official civil infrastructure certificate for a Roadside Unit."""
        rsu_priv, rsu_pub = generate_ecc_keypair()
        pub_pem = public_key_to_pem(rsu_pub)

        cert_content = {
            "serial_number": f"RSU-CERT-{rsu_id}",
            "pseudonym_id": rsu_id,
            "public_key_pem": pub_pem,
            "valid_from": time.time() - 100,
            "valid_to": time.time() + (86400 * 365)  # 1-year operational validity
        }

        cert_sig = sign_data(self.master_private_key, cert_content)

        return {
            "certificate": {
                "certificate_data": cert_content,
                "ta_signature": cert_sig
            },
            "private_key": rsu_priv
        }