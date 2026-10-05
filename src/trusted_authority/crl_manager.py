import time
from typing import Set, Dict, Any
from src.utils.crypto_utils import sign_data, verify_signature
from cryptography.hazmat.primitives.asymmetric import ec


class CRLManager:
    """Manages revoked certificate serial numbers and issues signed CRL updates."""

    def __init__(self):
        self._revoked_serials: Set[str] = set()
        self.last_updated: float = time.time()

    def revoke_certificate(self, cert_serial: str, reason: str = "COMPROMISED") -> None:
        """Adds a certificate serial number to the revocation list."""
        self._revoked_serials.add(cert_serial)
        self.last_updated = time.time()

    def is_revoked(self, cert_serial: str) -> bool:
        """Checks if a certificate serial number has been revoked."""
        return cert_serial in self._revoked_serials

    def get_signed_crl(self, ta_private_key: ec.EllipticCurvePrivateKey) -> Dict[str, Any]:
        """Exports the CRL with a TA cryptographic signature for broadcast to RSUs and vehicles."""
        crl_payload = {
            "revoked_serials": sorted(list(self._revoked_serials)),
            "timestamp": time.time()
        }
        signature = sign_data(ta_private_key, crl_payload)
        return {
            "crl_data": crl_payload,
            "ta_signature": signature
        }

    @staticmethod
    def verify_and_import_crl(crl_bundle: Dict[str, Any], ta_public_key: ec.EllipticCurvePublicKey) -> Set[str]:
        """Verifies the TA signature on an external CRL bundle and returns revoked serials."""
        crl_data = crl_bundle.get("crl_data", {})
        ta_sig = crl_bundle.get("ta_signature", "")

        if not verify_signature(ta_public_key, crl_data, ta_sig):
            raise ValueError("CRL verification failed: Invalid TA signature!")

        return set(crl_data.get("revoked_serials", []))