import time
import pytest
from src.trusted_authority.ta_server import TrustedAuthority
from src.vehicle.vehicle_node import VehicleNode
from src.attacks.replay_attack import ReplayAttacker
from src.attacks.tampering_attack import TamperingAttacker
from src.attacks.sybil_attack import SybilAttacker
from src.attacks.impersonation_attack import ImpersonationAttacker
from src.attacks.dos_flooding import DoSAttacker

@pytest.fixture
def test_setup():
    ta = TrustedAuthority()
    vid_legit = "VIN-LEGIT-001"
    vid_target = "VIN-TARGET-002"

    ta.register_vehicle(vid_legit)
    ta.register_vehicle(vid_target)

    batch_legit = ta.request_pseudonyms(vid_legit, count=3)
    batch_target = ta.request_pseudonyms(vid_target, count=3)

    legit_node = VehicleNode(vid_legit, ta.master_public_key, batch_legit)
    target_node = VehicleNode(vid_target, ta.master_public_key, batch_target)

    return ta, legit_node, target_node

def test_simulate_replay_attack(test_setup):
    _, legit_node, target_node = test_setup
    attacker = ReplayAttacker()

    # Step 1: Attacker sniffs authentic packet
    legit_packet = legit_node.create_safety_message()
    attacker.capture_message(legit_packet)

    # Step 2: Attacker replays packet after clock skew expires
    replayed = attacker.craft_delayed_replay()
    simulated_future_time = time.time() + 10.0  # 10s elapsed (> 2.0s skew limit)

    is_valid, reason = target_node.verify_inbound_message(replayed, current_time=simulated_future_time)
    assert is_valid is False
    assert reason == "DROP_REPLAY_STALE_TIMESTAMP"

def test_simulate_tampering_attack(test_setup):
    _, legit_node, target_node = test_setup
    legit_packet = legit_node.create_safety_message(speed_kmh=60.0)

    # Adversary mutates speed to 0.0 and event to EMERGENCY_BRAKE
    tampered = TamperingAttacker.modify_telemetry(legit_packet, fake_speed=0.0, fake_event="EMERGENCY_BRAKE")

    is_valid, reason = target_node.verify_inbound_message(tampered)
    assert is_valid is False
    assert reason == "DROP_CORRUPTED_OR_TAMPERED_PAYLOAD"

def test_simulate_sybil_attack(test_setup):
    _, _, target_node = test_setup
    attacker = SybilAttacker()
    ghost_beacons = attacker.generate_ghost_beacons(count=3)

    for packet in ghost_beacons:
        is_valid, reason = target_node.verify_inbound_message(packet)
        assert is_valid is False
        assert reason == "DROP_INVALID_TA_SIGNATURE"

def test_simulate_impersonation_attack(test_setup):
    _, _, target_node = test_setup
    attacker = ImpersonationAttacker()
    fake_alert = attacker.craft_fake_emergency_alert()

    is_valid, reason = target_node.verify_inbound_message(fake_alert)
    assert is_valid is False
    assert reason == "DROP_INVALID_TA_SIGNATURE"

def test_simulate_dos_flooding(test_setup):
    _, _, target_node = test_setup
    malformed_packets = DoSAttacker.generate_malformed_packets(count=5)

    for packet in malformed_packets:
        is_valid, reason = target_node.verify_inbound_message(packet)
        assert is_valid is False
        assert reason == "DROP_MALFORMED_STRUCTURE"