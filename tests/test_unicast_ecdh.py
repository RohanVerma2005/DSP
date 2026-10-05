import pytest
from src.trusted_authority.ta_server import TrustedAuthority
from src.vehicle.vehicle_node import VehicleNode


@pytest.fixture
def setup_two_vehicles():
    ta = TrustedAuthority()
    ta.register_vehicle("VIN-CAR-1")
    ta.register_vehicle("VIN-CAR-2")
    ta.register_vehicle("VIN-SNIFFER-3")

    batch_1 = ta.request_pseudonyms("VIN-CAR-1", count=3)
    batch_2 = ta.request_pseudonyms("VIN-CAR-2", count=3)
    batch_3 = ta.request_pseudonyms("VIN-SNIFFER-3", count=3)

    car_1 = VehicleNode("VIN-CAR-1", ta.master_public_key, batch_1)
    car_2 = VehicleNode("VIN-CAR-2", ta.master_public_key, batch_2)
    sniffer = VehicleNode("VIN-SNIFFER-3", ta.master_public_key, batch_3)

    return car_1, car_2, sniffer


def test_ecdh_handshake_and_key_agreement(setup_two_vehicles):
    car_1, car_2, _ = setup_two_vehicles

    pseudo_1 = car_1.pseudonym_pool.get_active_credentials()["certificate"]["certificate_data"]["pseudonym_id"]
    pseudo_2 = car_2.pseudonym_pool.get_active_credentials()["certificate"]["certificate_data"]["pseudonym_id"]

    # 1. Car 1 creates handshake init
    init_pkt = car_1.unicast_mgr.initiate_handshake(target_pseudonym_id=pseudo_2)
    assert init_pkt is not None

    # 2. Car 2 processes init and returns response
    resp_pkt = car_2.unicast_mgr.respond_to_handshake(init_pkt)
    assert resp_pkt is not None

    # 3. Car 1 finalizes handshake
    success = car_1.unicast_mgr.complete_handshake(resp_pkt)
    assert success is True

    # 4. Verify both derived identical 32-byte AES-GCM session keys
    key_1 = car_1.unicast_mgr.active_sessions.get(pseudo_2)
    key_2 = car_2.unicast_mgr.active_sessions.get(pseudo_1)

    assert key_1 is not None
    assert key_1 == key_2
    assert len(key_1) == 32


def test_aes_gcm_confidential_transmission(setup_two_vehicles):
    car_1, car_2, sniffer = setup_two_vehicles

    pseudo_1 = car_1.pseudonym_pool.get_active_credentials()["certificate"]["certificate_data"]["pseudonym_id"]
    pseudo_2 = car_2.pseudonym_pool.get_active_credentials()["certificate"]["certificate_data"]["pseudonym_id"]

    # Handshake
    init_pkt = car_1.unicast_mgr.initiate_handshake(pseudo_2)
    resp_pkt = car_2.unicast_mgr.respond_to_handshake(init_pkt)
    car_1.unicast_mgr.complete_handshake(resp_pkt)

    # Car 1 sends sensitive platooning data (intended strictly for Car 2)
    private_payload = {
        "platoon_id": "PLATOON-7",
        "planned_exit": "Exit 14B - 500m",
        "target_speed": 82.5,
        "inter_vehicle_gap_m": 5.0
    }

    encrypted_packet = car_1.unicast_mgr.encrypt_unicast_payload(pseudo_2, private_payload)
    assert encrypted_packet is not None

    # Car 2 decrypts successfully
    decrypted_data = car_2.unicast_mgr.decrypt_unicast_payload(encrypted_packet)
    assert decrypted_data == private_payload

    # Sniffer attempts to decrypt without shared key -> returns None
    sniffed_data = sniffer.unicast_mgr.decrypt_unicast_payload(encrypted_packet)
    assert sniffed_data is None


def test_unicast_ciphertext_tampering(setup_two_vehicles):
    car_1, car_2, _ = setup_two_vehicles
    pseudo_2 = car_2.pseudonym_pool.get_active_credentials()["certificate"]["certificate_data"]["pseudonym_id"]

    # Handshake
    init_pkt = car_1.unicast_mgr.initiate_handshake(pseudo_2)
    resp_pkt = car_2.unicast_mgr.respond_to_handshake(init_pkt)
    car_1.unicast_mgr.complete_handshake(resp_pkt)

    encrypted_packet = car_1.unicast_mgr.encrypt_unicast_payload(pseudo_2, {"secret": 123})

    # Tamper with base64 ciphertext
    raw_ct = encrypted_packet["encrypted"]["ciphertext"]
    encrypted_packet["encrypted"]["ciphertext"] = ("A" if raw_ct[0] != "A" else "B") + raw_ct[1:]

    # Decryption fails due to GCM authentication tag mismatch
    assert car_2.unicast_mgr.decrypt_unicast_payload(encrypted_packet) is None