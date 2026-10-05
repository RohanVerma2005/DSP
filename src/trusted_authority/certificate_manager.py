import uuid
import time
from typing import Dict, Any, List, Tuple
from cryptography.hazmat.primitives.asymmetric import ec

from src.utils.constants import PSEUDONYM_VALIDITY_SECONDS
from src.utils.crypto_utils import (
    generate_ecc_keypair,
    public_key_to_pem,
    pem_to_public_key,
    sign_data,
    verify_signature
)

class CertificateManager:
    """Handles pseudonym certificate issuance and verification under the TA master key."""

    def __init__(self, ta_private_key: ec.EllipticCurvePrivateKey, ta_public_key: ec.EllipticCurvePublicKey):
        self.ta_private_key = ta_private_key
        self.ta_public_key = ta_public_key

    def issue_pseudonym_batch(
        self,
        real_vid: str,
        batch_size: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generates a batch of ephemeral pseudonym certificates for an authorized vehicle.
        Returns a list of dicts containing the certificate and corresponding private key.
        """
        batch = []
        current_time = time.time()

        for i in range(batch_size):
            # Generate a fresh ephemeral keypair for this pseudonym
            pseudo_priv, pseudo_pub = generate_ecc_keypair()
            pub_pem = public_key_to_pem(pseudo_pub)

            cert_content = {
                "serial_number": str(uuid.uuid4()),
                "pseudonym_id": f"PSEUDO-{uuid.uuid4().hex[:8].upper()}",
                "public_key_pem": pub_pem,
                "valid_from": current_time + (i * PSEUDONYM_VALIDITY_SECONDS),
                "valid_to": current_time + ((i + 1) * PSEUDONYM_VALIDITY_SECONDS)
            }

            # Sign the certificate with the TA master private key
            cert_signature = sign_data(self.ta_private_key, cert_content)

            certificate = {
                "certificate_data": cert_content,
                "ta_signature": cert_signature
            }

            batch.append({
                "certificate": certificate,
                "private_key": pseudo_priv
            })

        return batch

    def verify_pseudonym_certificate(
        self,
        certificate: Dict[str, Any],
        current_time: float = None
    ) -> bool:
        """
        Validates that:
        1. TA signature on the certificate is cryptographically valid.
        2. Certificate is within its valid time window.
        """
        if current_time is None:
            current_time = time.time()

        cert_data = certificate.get("certificate_data")
        ta_sig = certificate.get("ta_signature")

        if not cert_data or not ta_sig:
            return False

        # 1. Verify cryptographic integrity against TA root key
        if not verify_signature(self.ta_public_key, cert_data, ta_sig):
            return False

        # 2. Verify temporal validity window
        valid_from = cert_data.get("valid_from", 0)
        valid_to = cert_data.get("valid_to", 0)
        if not (valid_from <= current_time <= valid_to):
            return False

        return True