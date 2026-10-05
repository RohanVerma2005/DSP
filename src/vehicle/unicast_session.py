import time
import uuid
from typing import Dict, Any, Optional, Tuple

from src.utils.crypto_utils import (
    generate_ecc_keypair,
    public_key_to_pem,
    pem_to_public_key,
    derive_ecdh_shared_secret,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    sign_data,
    verify_signature
)


class UnicastSessionManager:
    """Manages ECDH key exchange and AES-256-GCM encrypted unicast channels."""

    def __init__(self, vehicle_node):
        self.node = vehicle_node
        # Maps peer_pseudonym_id -> derived_32byte_session_key
        self.active_sessions: Dict[str, bytes] = {}

        # Pending handshakes: peer_pseudonym_id -> ephemeral_ecdh_private_key
        self._pending_handshakes: Dict[str, Any] = {}

    def initiate_handshake(self, target_pseudonym_id: str) -> Optional[Dict[str, Any]]:
        """
        Stage 1: Generates an ephemeral ECDH keypair and signs a handshake request
        addressed to a specific peer.
        """
        creds = self.node.pseudonym_pool.get_active_credentials()
        if not creds:
            return None

        ecdh_priv, ecdh_pub = generate_ecc_keypair()
        self._pending_handshakes[target_pseudonym_id] = ecdh_priv

        body = {
            "header": {
                "message_type": "UNICAST_HANDSHAKE_INIT",
                "message_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "sender_pseudonym": creds["certificate"]["certificate_data"]["pseudonym_id"],
                "target_pseudonym": target_pseudonym_id
            },
            "ecdh_public_key_pem": public_key_to_pem(ecdh_pub)
        }

        signature = sign_data(creds["private_key"], body)

        return {
            "body": body,
            "sender_certificate": creds["certificate"],
            "signature": signature
        }

    def respond_to_handshake(self, init_packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Stage 2: Peer verifies initiator identity, generates its own ephemeral ECDH keypair,
        derives the shared key, and returns its public key.
        """
        is_valid, _ = self.node.verify_inbound_message(init_packet, enforce_geocasting=False)
        if not is_valid:
            return None

        body = init_packet.get("body", {})
        header = body.get("header", {})
        sender_pseudo = header.get("sender_pseudonym")
        peer_ecdh_pem = body.get("ecdh_public_key_pem")

        peer_ecdh_pub = pem_to_public_key(peer_ecdh_pem)

        # Generate responder's ephemeral ECDH keypair
        my_ecdh_priv, my_ecdh_pub = generate_ecc_keypair()

        # Derive shared 256-bit symmetric session key
        session_key = derive_ecdh_shared_secret(my_ecdh_priv, peer_ecdh_pub)
        self.active_sessions[sender_pseudo] = session_key

        creds = self.node.pseudonym_pool.get_active_credentials()
        if not creds:
            return None

        resp_body = {
            "header": {
                "message_type": "UNICAST_HANDSHAKE_RESP",
                "message_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "sender_pseudonym": creds["certificate"]["certificate_data"]["pseudonym_id"],
                "target_pseudonym": sender_pseudo
            },
            "ecdh_public_key_pem": public_key_to_pem(my_ecdh_pub)
        }

        resp_signature = sign_data(creds["private_key"], resp_body)

        return {
            "body": resp_body,
            "sender_certificate": creds["certificate"],
            "signature": resp_signature
        }

    def complete_handshake(self, resp_packet: Dict[str, Any]) -> bool:
        """
        Stage 3: Initiator verifies response, retrieves peer's ephemeral public key,
        and computes the identical symmetric key.
        """
        is_valid, _ = self.node.verify_inbound_message(resp_packet, enforce_geocasting=False)
        if not is_valid:
            return False

        body = resp_packet.get("body", {})
        header = body.get("header", {})
        peer_pseudo = header.get("sender_pseudonym")
        peer_ecdh_pem = body.get("ecdh_public_key_pem")

        if peer_pseudo not in self._pending_handshakes:
            return False

        my_ecdh_priv = self._pending_handshakes.pop(peer_pseudo)
        peer_ecdh_pub = pem_to_public_key(peer_ecdh_pem)

        session_key = derive_ecdh_shared_secret(my_ecdh_priv, peer_ecdh_pub)
        self.active_sessions[peer_pseudo] = session_key
        return True

    def encrypt_unicast_payload(self, target_pseudonym_id: str, secret_payload: Dict[str, Any]) -> Optional[
        Dict[str, Any]]:
        """Encrypts private JSON data using derived AES-256-GCM session key."""
        session_key = self.active_sessions.get(target_pseudonym_id)
        if not session_key:
            return None

        import json
        plaintext_bytes = json.dumps(secret_payload).encode("utf-8")
        encrypted_bundle = encrypt_aes_gcm(plaintext_bytes, session_key)

        creds = self.node.pseudonym_pool.get_active_credentials()
        my_pseudo = creds["certificate"]["certificate_data"]["pseudonym_id"]

        return {
            "header": {
                "message_type": "UNICAST_CONFIDENTIAL_PAYLOAD",
                "sender_pseudonym": my_pseudo,
                "target_pseudonym": target_pseudonym_id,
                "timestamp": time.time()
            },
            "encrypted": encrypted_bundle
        }

    def decrypt_unicast_payload(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Decrypts and authenticates AES-256-GCM unicast ciphertext."""
        header = packet.get("header", {})
        sender_pseudo = header.get("sender_pseudonym")
        encrypted_bundle = packet.get("encrypted")

        session_key = self.active_sessions.get(sender_pseudo)
        if not session_key or not encrypted_bundle:
            return None

        try:
            import json
            decrypted_bytes = decrypt_aes_gcm(encrypted_bundle, session_key)
            return json.loads(decrypted_bytes.decode("utf-8"))
        except Exception:
            return None