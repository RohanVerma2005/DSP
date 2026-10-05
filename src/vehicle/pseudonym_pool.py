import time
from typing import List, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import ec


class PseudonymPool:
    """Manages active and queued pseudonym certificates for privacy preservation."""

    def __init__(self, cert_batch: List[Dict[str, Any]]):
        # List of items: {"certificate": {...}, "private_key": ec.EllipticCurvePrivateKey}
        self._pool: List[Dict[str, Any]] = cert_batch
        self._current_index: int = 0

    def get_active_credentials(self) -> Optional[Dict[str, Any]]:
        """
        Returns the current active pseudonym certificate and its private key.
        Automatically rolls over if the current certificate has expired.
        """
        current_time = time.time()

        while self._current_index < len(self._pool):
            candidate = self._pool[self._current_index]
            cert_data = candidate["certificate"]["certificate_data"]

            # Check if this certificate is still valid
            if current_time < cert_data["valid_to"]:
                return candidate

            # If expired, move to next pseudonym
            self._current_index += 1

        return None  # All certificates in the pool have expired

    def force_rollover(self) -> bool:
        """Manually rotate pseudonym for location unlinkability."""
        if self._current_index + 1 < len(self._pool):
            self._current_index += 1
            return True
        return False