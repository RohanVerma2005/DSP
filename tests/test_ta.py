import time
import pytest
from src.trusted_authority.ta_server import TrustedAuthority
from src.utils.crypto_utils import generate_ecc_keypair, sign_data


def test_vehicle_registration_and_pseudonym_issuance():
    ta = TrustedAuthority()
    vid = "VIN-AUDI-2026-99"

    # Register
    assert ta.register_vehicle(vid, "PERSONAL_CAR") is True
    assert ta.register_vehicle(vid) is False  # Duplicate rejection

    # Request Pseudonyms
    batch = ta.request_pseudonyms(vid, count=3)
    assert batch is not None
    assert len(batch) == 3

    # Check structure
    first_cert_bundle = batch[0]
    assert "certificate" in first_cert_bundle
    assert "private_key" in first_cert_bundle
    assert "pseudonym_id" in first_cert_bundle["certificate"]["certificate_data"]


def test_pseudonym_verification_valid():
    ta = TrustedAuthority()
    vid = "VIN-TESLA-101"
    ta.register_vehicle(vid)
    batch = ta.request_pseudonyms(vid, count=1)

    cert = batch[0]["certificate"]
    # Check valid at current timestamp
    assert ta.cert_manager.verify_pseudonym_certificate(cert) is True


def test_pseudonym_expiry_verification():
    ta = TrustedAuthority()
    vid = "VIN-BMW-303"
    ta.register_vehicle(vid)
    batch = ta.request_pseudonyms(vid, count=1)
    cert = batch[0]["certificate"]

    # Test future (before valid_from)
    future_time = cert["certificate_data"]["valid_from"] - 100
    assert ta.cert_manager.verify_pseudonym_certificate(cert, current_time=future_time) is False

    # Test past (after valid_to)
    past_time = cert["certificate_data"]["valid_to"] + 100
    assert ta.cert_manager.verify_pseudonym_certificate(cert, current_time=past_time) is False


def test_crl_revocation():
    ta = TrustedAuthority()
    vid = "VIN-MALICIOUS-007"
    ta.register_vehicle(vid)
    batch = ta.request_pseudonyms(vid, count=2)

    serial_to_revoke = batch[0]["certificate"]["certificate_data"]["serial_number"]
    valid_serial = batch[1]["certificate"]["certificate_data"]["serial_number"]

    # Initial check
    assert ta.crl_manager.is_revoked(serial_to_revoke) is False

    # Revoke
    ta.revoke_vehicle(vid, [serial_to_revoke])
    assert ta.crl_manager.is_revoked(serial_to_revoke) is True
    assert ta.crl_manager.is_revoked(valid_serial) is False


def test_forged_pseudonym_certificate():
    ta = TrustedAuthority()
    # Rogue actor creates self-signed cert
    rogue_priv, rogue_pub = generate_ecc_keypair()
    fake_cert_data = {
        "serial_number": "FORGED-001",
        "pseudonym_id": "PSEUDO-ROGUE",
        "public_key_pem": "dummy",
        "valid_from": time.time() - 10,
        "valid_to": time.time() + 100
    }
    fake_signature = sign_data(rogue_priv, fake_cert_data)

    forged_cert = {
        "certificate_data": fake_cert_data,
        "ta_signature": fake_signature
    }

    # TA verification must reject
    assert ta.cert_manager.verify_pseudonym_certificate(forged_cert) is False