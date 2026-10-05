import time
import uuid
from typing import Dict, Any, Tuple, Optional, Set
from cryptography.hazmat.primitives.asymmetric import ec
from src.vehicle.unicast_session import UnicastSessionManager

from src.utils.constants import MAX_CLOCK_SKEW_SECONDS, MSG_TYPE_BEACON
from src.utils.crypto_utils import (
    sign_data,
    verify_signature,
    pem_to_public_key
)
from src.utils.spatial_utils import (
    evaluate_geocast_relevance,
    check_kinematic_plausibility
)
from src.vehicle.pseudonym_pool import PseudonymPool


class VehicleNode:
    """Represents a connected vehicle's Onboard Unit (OBU)."""

    def __init__(
        self,
        real_vid: str,
        ta_public_key: ec.EllipticCurvePublicKey,
        cert_batch: list,
        initial_lat: float = 37.7749,
        initial_lon: float = -122.4194,
        initial_speed: float = 60.0
    ):
        self.real_vid = real_vid
        self.ta_public_key = ta_public_key
        self.pseudonym_pool = PseudonymPool(cert_batch)
        self.sequence_number: int = 0

        # Vehicle local state
        self.current_lat = initial_lat
        self.current_lon = initial_lon
        self.current_speed_kmh = initial_speed

        # Local CRL cache: Set of revoked serial numbers
        self.local_crl: Set[str] = set()

        # Replay cache: maps sender pseudonym_id -> highest seen sequence_number
        self._sender_seq_cache: Dict[str, int] = {}

        # Kinematic history cache: maps sender pseudonym_id -> last known telemetry state
        self._sender_kinematic_cache: Dict[str, Dict[str, Any]] = {}

        self.unicast_mgr = UnicastSessionManager(self)

    def set_position(self, lat: float, lon: float, speed_kmh: Optional[float] = None) -> None:
        """Updates the physical ego-vehicle position and velocity."""
        self.current_lat = lat
        self.current_lon = lon
        if speed_kmh is not None:
            self.current_speed_kmh = speed_kmh

    def update_crl(self, revoked_serials: Set[str]) -> None:
        """Updates local revocation cache."""
        self.local_crl.update(revoked_serials)

    def create_safety_message(
        self,
        event_type: str = MSG_TYPE_BEACON,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        speed_kmh: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """Constructs and signs a standardized V2V message frame using active pseudonym."""
        creds = self.pseudonym_pool.get_active_credentials()
        if not creds:
            return None

        self.sequence_number += 1
        current_time = time.time()

        lat = latitude if latitude is not None else self.current_lat
        lon = longitude if longitude is not None else self.current_lon
        spd = speed_kmh if speed_kmh is not None else self.current_speed_kmh

        header = {
            "protocol_version": "1.0",
            "message_id": str(uuid.uuid4()),
            "seq_no": self.sequence_number,
            "timestamp": current_time,
            "message_type": event_type
        }

        payload = {
            "latitude": lat,
            "longitude": lon,
            "speed_kmh": spd,
            "heading_deg": 180.0
        }

        signed_body = {
            "header": header,
            "payload": payload
        }

        vehicle_sig = sign_data(creds["private_key"], signed_body)

        return {
            "body": signed_body,
            "sender_certificate": creds["certificate"],
            "signature": vehicle_sig
        }

    def verify_inbound_message(
        self,
        packet: Dict[str, Any],
        current_time: Optional[float] = None,
        enforce_geocasting: bool = True
    ) -> Tuple[bool, str]:
        """
        Executes strict 6-stage inbound verification:
        1. Freshness & Monotonic Sequence Check
        2. Revocation Verification (CRL)
        3. TA Certificate Legitimacy Check
        4. ECDSA Payload Signature Verification
        5. Geocasting Relevance Check (distance filtering)
        6. Kinematic Plausibility Check (speed & acceleration consistency)
        """
        if current_time is None:
            current_time = time.time()

        body = packet.get("body")
        sender_cert = packet.get("sender_certificate")
        packet_sig = packet.get("signature")

        if not body or not sender_cert or not packet_sig:
            return False, "DROP_MALFORMED_STRUCTURE"

        header = body.get("header", {})
        payload = body.get("payload", {})
        cert_data = sender_cert.get("certificate_data", {})
        ta_sig = sender_cert.get("ta_signature", "")

        # ----------------------------------------------------
        # Stage 1: Timestamp Freshness & Monotonic Sequence
        # ----------------------------------------------------
        msg_time = header.get("timestamp", 0)
        if abs(current_time - msg_time) > MAX_CLOCK_SKEW_SECONDS:
            return False, "DROP_REPLAY_STALE_TIMESTAMP"

        pseudonym_id = cert_data.get("pseudonym_id")
        seq_no = header.get("seq_no", 0)
        last_seq = self._sender_seq_cache.get(pseudonym_id, -1)

        if seq_no <= last_seq:
            return False, "DROP_REPLAY_DUPLICATE_OR_REGRESSIVE_SEQ"

        # ----------------------------------------------------
        # Stage 2: Revocation Check
        # ----------------------------------------------------
        cert_serial = cert_data.get("serial_number")
        if cert_serial in self.local_crl:
            return False, "DROP_CERTIFICATE_REVOKED"

        # ----------------------------------------------------
        # Stage 3: TA Certificate Legitimacy & Expiry
        # ----------------------------------------------------
        if not verify_signature(self.ta_public_key, cert_data, ta_sig):
            return False, "DROP_INVALID_TA_SIGNATURE"

        valid_from = cert_data.get("valid_from", 0)
        valid_to = cert_data.get("valid_to", 0)
        if not (valid_from <= current_time <= valid_to):
            return False, "DROP_CERTIFICATE_EXPIRED"

        # ----------------------------------------------------
        # Stage 4: Vehicle ECDSA Signature Verification
        # ----------------------------------------------------
        try:
            sender_pubkey = pem_to_public_key(cert_data.get("public_key_pem", ""))
        except Exception:
            return False, "DROP_INVALID_PUBLIC_KEY"

        if not verify_signature(sender_pubkey, body, packet_sig):
            return False, "DROP_CORRUPTED_OR_TAMPERED_PAYLOAD"

        sender_lat = payload.get("latitude", 0.0)
        sender_lon = payload.get("longitude", 0.0)
        sender_speed = payload.get("speed_kmh", 0.0)

        # ----------------------------------------------------
        # Stage 5: Geocasting Distance Filter
        # ----------------------------------------------------
        if enforce_geocasting:
            is_relevant, distance = evaluate_geocast_relevance(
                receiver_pos=(self.current_lat, self.current_lon),
                sender_pos=(sender_lat, sender_lon)
            )
            if not is_relevant:
                return False, f"DROP_OUT_OF_RANGE_GEOCAST_{int(distance)}M"

        # ----------------------------------------------------
        # Stage 6: Kinematic Plausibility Validation
        # ----------------------------------------------------
        current_telemetry = {
            "timestamp": msg_time,
            "lat": sender_lat,
            "lon": sender_lon,
            "speed_kmh": sender_speed
        }
        prev_telemetry = self._sender_kinematic_cache.get(pseudonym_id)

        kinematics_ok, reason = check_kinematic_plausibility(prev_telemetry, current_telemetry)
        if not kinematics_ok:
            return False, reason

        # Message is authentic and physically valid: update caches
        self._sender_seq_cache[pseudonym_id] = seq_no
        self._sender_kinematic_cache[pseudonym_id] = current_telemetry

        return True, "ACCEPT_VERIFIED"