import time
from src.trusted_authority.ta_server import TrustedAuthority
from src.vehicle.vehicle_node import VehicleNode
from src.attacks.tampering_attack import TamperingAttacker
from src.attacks.sybil_attack import SybilAttacker

def test_full_protocol_lifecycle():
    # 1. TA Setup
    ta = TrustedAuthority()
    vid_1 = "VIN-NODE-01"
    vid_2 = "VIN-NODE-02"

    assert ta.register_vehicle(vid_1) is True
    assert ta.register_vehicle(vid_2) is True

    # 2. Batch Pseudonym Issuance
    batch_1 = ta.request_pseudonyms(vid_1, count=3)
    batch_2 = ta.request_pseudonyms(vid_2, count=3)

    node_1 = VehicleNode(vid_1, ta.master_public_key, batch_1)
    node_2 = VehicleNode(vid_2, ta.master_public_key, batch_2)

    # 3. Legitimate V2V Transmission (seq_no: 1)
    msg_1 = node_1.create_safety_message(event_type="EMERGENCY_BRAKE", speed_kmh=75.0)
    valid, reason = node_2.verify_inbound_message(msg_1)
    assert valid is True
    assert reason == "ACCEPT_VERIFIED"

    # 4. Tampering Attempt on a Fresh Packet (seq_no: 2)
    # Using a fresh message ensures the packet passes Stage 1 (Replay) and reaches Stage 4 (Tampering detection)
    msg_2 = node_1.create_safety_message(event_type="BEACON", speed_kmh=80.0)
    tampered = TamperingAttacker.modify_telemetry(msg_2, fake_speed=0.0)
    valid_t, reason_t = node_2.verify_inbound_message(tampered)
    assert valid_t is False
    assert reason_t == "DROP_CORRUPTED_OR_TAMPERED_PAYLOAD"

    # 5. Sybil Attempt
    ghost_packet = SybilAttacker().generate_ghost_beacons(1)[0]
    valid_s, reason_s = node_2.verify_inbound_message(ghost_packet)
    assert valid_s is False
    assert reason_s == "DROP_INVALID_TA_SIGNATURE"