import os
import base64
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

from src.utils.message_utils import canonical_dumps


def generate_ecc_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generates an ECDSA keypair using the standard automotive NIST P-256 (secp256r1) curve."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    """Serializes an ECC public key into PEM string format."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode("utf-8")


def pem_to_public_key(pem_str: str) -> ec.EllipticCurvePublicKey:
    """Deserializes a PEM string back into an ECC public key object."""
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def sign_data(private_key: ec.EllipticCurvePrivateKey, data: Dict[str, Any]) -> str:
    """
    Signs canonical JSON data with ECDSA SHA-256.
    Returns the signature as a Base64-encoded string.
    """
    serialized = canonical_dumps(data)
    raw_signature = private_key.sign(
        serialized,
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(raw_signature).decode("utf-8")


def verify_signature(public_key: ec.EllipticCurvePublicKey, data: Dict[str, Any], signature_b64: str) -> bool:
    """
    Verifies an ECDSA SHA-256 signature against canonical data.
    Returns True if valid, False if altered or forged.
    """
    try:
        raw_signature = base64.b64decode(signature_b64.encode("utf-8"))
        serialized = canonical_dumps(data)
        public_key.verify(
            raw_signature,
            serialized,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> Dict[str, str]:
    """
    Encrypts sensitive data using AES-256-GCM.
    Returns base64 representations of nonce and ciphertext (which includes auth tag).
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes.")

    nonce = os.urandom(12)  # Standard 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }


def decrypt_aes_gcm(encrypted_dict: Dict[str, str], key: bytes) -> bytes:
    """
    Decrypts AES-256-GCM ciphertext. Raises an exception if integrity tag check fails.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes.")

    nonce = base64.b64decode(encrypted_dict["nonce"].encode("utf-8"))
    ciphertext = base64.b64decode(encrypted_dict["ciphertext"].encode("utf-8"))

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_ecdh_shared_secret(
        private_key: ec.EllipticCurvePrivateKey,
        peer_public_key: ec.EllipticCurvePublicKey,
        salt: bytes = b"v2v_secure_salt",
        info: bytes = b"v2v_unicast_channel"
) -> bytes:
    """
    Computes raw ECDH shared secret on secp256r1 and expands it into
    a 256-bit (32-byte) symmetric key using HKDF-SHA256.
    """
    raw_shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    derived_symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(raw_shared_key)

    return derived_symmetric_key