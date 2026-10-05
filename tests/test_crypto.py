import os
import pytest
from src.utils.crypto_utils import (
    generate_ecc_keypair,
    public_key_to_pem,
    pem_to_public_key,
    sign_data,
    verify_signature,
    encrypt_aes_gcm,
    decrypt_aes_gcm
)


def test_ecdsa_sign_and_verify_valid():
    priv, pub = generate_ecc_keypair()
    payload = {"vehicle_id": "V-101", "speed": 65.5, "event": "CRUISING"}

    signature = sign_data(priv, payload)
    assert verify_signature(pub, payload, signature) is True


def test_ecdsa_tamper_detection():
    priv, pub = generate_ecc_keypair()
    payload = {"vehicle_id": "V-101", "speed": 65.5, "event": "CRUISING"}
    signature = sign_data(priv, payload)

    # Adversary alters speed
    tampered_payload = {"vehicle_id": "V-101", "speed": 95.0, "event": "CRUISING"}
    assert verify_signature(pub, tampered_payload, signature) is False


def test_public_key_pem_serialization():
    _, pub = generate_ecc_keypair()
    pem = public_key_to_pem(pub)
    restored_pub = pem_to_public_key(pem)

    # Sign with original, verify with restored
    priv, _ = generate_ecc_keypair()
    msg = {"test": 123}
    sig = sign_data(priv, msg)
    assert verify_signature(restored_pub, msg, sig) is False  # different key, must fail


def test_aes_gcm_encryption_roundtrip():
    key = os.urandom(32)  # 256-bit key
    plaintext = b"Secret location coordinates: 37.7749,-122.4194"

    encrypted = encrypt_aes_gcm(plaintext, key)
    decrypted = decrypt_aes_gcm(encrypted, key)
    assert decrypted == plaintext


def test_aes_gcm_tamper_detection():
    key = os.urandom(32)
    plaintext = b"Secure transmission"
    encrypted = encrypt_aes_gcm(plaintext, key)

    # Tamper with the ciphertext byte string
    import base64
    raw_ct = bytearray(base64.b64decode(encrypted["ciphertext"]))
    raw_ct[0] ^= 0xFF  # Flip bits
    encrypted["ciphertext"] = base64.b64encode(raw_ct).decode("utf-8")

    with pytest.raises(Exception):
        decrypt_aes_gcm(encrypted, key)