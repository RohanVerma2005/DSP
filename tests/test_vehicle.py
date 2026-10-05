import time
import pytest
from src.trusted_authority.ta_server import TrustedAuthority
from src.vehicle.vehicle_node import VehicleNode


@pytest.fixture
def setup_environment():
    ta = TrustedAuthority()

    # Register Vehicle A and Vehicle B
    vid_a = "VIN-VEHICLE-ALPHA"
    vid_b = "VIN-VEHICLE-BETA"
    ta.register_vehicle(vid_a)
    ta.register_vehicle(vid_b)

    batch_a = ta.request_pseudonyms(vid_a, count=5)
    batch_b = ta.request_pseudonyms(vid_b, count=5)

    node_a = VehicleNode(vid_a, ta.master_public_key, batch_a)
    node_b = VehicleNode(vid_b, ta.master_public_key, batch_b)

    return ta, node_a, node_b


def test_legitimate_v2v_transmission(setup_environment):
    _, node_a, node_b = setup_environment
    msg = node_a.create_safety_message(event_type="BEACON", speed_kmh=80.0)

    assert msg is not None
    is_valid, reason = node_b.verify_inbound_message(msg)
    assert is_valid is True
    assert reason == "ACCEPT_VERIFIED"


def test_tampered_payload_rejection(setup_environment):
    _, node_a, node_b = setup_environment
    msg = node_a.create_safety_message(speed_kmh=50.0)

    # Attacker alters speed without vehicle A's private key
    msg["body"]["payload"]["speed_kmh"] = 120.0

    is_valid, reason = node_b.verify_inbound_message(msg)
    assert is_valid is False
    assert reason == "DROP_CORRUPTED_OR_TAMPERED_PAYLOAD"


def test_replay_attack_stale_timestamp(setup_environment):
    _, node_a, node_b = setup_environment
    msg = node_a.create_safety_message()

    # Replay simulated 5 seconds later
    current_time = time.time() + 5.0
    is_valid, reason = node_b.verify_inbound_message(msg, current_time=current_time)
    assert is_valid is False
    assert reason == "DROP_REPLAY_STALE_TIMESTAMP"


def test_replay_attack_duplicate_sequence(setup_environment):
    _, node_a, node_b = setup_environment
    msg = node_a.create_safety_message()

    # First receive succeeds
    is_valid, _ = node_b.verify_inbound_message(msg)
    assert is_valid is True

    # Replaying the exact same message must fail immediately
    is_valid_replay, reason = node_b.verify_inbound_message(msg)
    assert is_valid_replay is False
    assert reason == "DROP_REPLAY_DUPLICATE_OR_REGRESSIVE_SEQ"


def test_revoked_vehicle_message_rejection(setup_environment):
    ta, node_a, node_b = setup_environment
    msg = node_a.create_safety_message()
    serial = msg["sender_certificate"]["certificate_data"]["serial_number"]

    # TA revokes this serial and pushes to node B
    ta.crl_manager.revoke_certificate(serial)
    node_b.update_crl({serial})

    is_valid, reason = node_b.verify_inbound_message(msg)
    assert is_valid is False
    assert reason == "DROP_CERTIFICATE_REVOKED"


def test_pseudonym_rollover(setup_environment):
    _, node_a, _ = setup_environment
    creds_1 = node_a.pseudonym_pool.get_active_credentials()
    id_1 = creds_1["certificate"]["certificate_data"]["pseudonym_id"]

    # Force rollover to new pseudonym
    rolled = node_a.pseudonym_pool.force_rollover()
    assert rolled is True

    creds_2 = node_a.pseudonym_pool.get_active_credentials()
    id_2 = creds_2["certificate"]["certificate_data"]["pseudonym_id"]

    assert id_1 != id_2