import time
import pytest
from src.trusted_authority.ta_server import TrustedAuthority
from src.vehicle.vehicle_node import VehicleNode
from src.vehicle.communication import V2VChannel
from src.rsu.rsu_node import RSUকারNode

def test_live_udp_v2v_communication():
    ta = TrustedAuthority()
    vid_sender = "VIN-TX-101"
    vid_receiver = "VIN-RX-202"

    ta.register_vehicle(vid_sender)
    ta.register_vehicle(vid_receiver)

    batch_tx = ta.request_pseudonyms(vid_sender, count=3)
    batch_rx = ta.request_pseudonyms(vid_receiver, count=3)

    sender_node = VehicleNode(vid_sender, ta.master_public_key, batch_tx)
    receiver_node = VehicleNode(vid_receiver, ta.master_public_key, batch_rx)

    # Use unique ports for isolated socket testing
    tx_port = 5510
    rx_port = 5520

    tx_channel = V2VChannel(port=tx_port)
    rx_channel = V2VChannel(port=rx_port)

    received_packets = []

    def on_receive(packet, addr):
        is_valid, reason = receiver_node.verify_inbound_message(packet)
        received_packets.append((packet, is_valid, reason))

    rx_channel.start_listener(on_receive)
    time.sleep(0.05)  # Allow socket bind

    try:
        # Create authentic safety message and transmit to RX port
        msg = sender_node.create_safety_message(event_type="ROAD_HAZARD", speed_kmh=45.0)
        tx_channel.broadcast(msg, target_port=rx_port)

        # Wait up to 1 second for packet arrival
        timeout = time.time() + 1.0
        while len(received_packets) == 0 and time.time() < timeout:
            time.sleep(0.02)

        assert len(received_packets) == 1
        _, is_valid, reason = received_packets[0]
        assert is_valid is True
        assert reason == "ACCEPT_VERIFIED"

    finally:
        tx_channel.close()
        rx_channel.close()


def test_rsu_crl_sync_and_hazard_alert():
    ta = TrustedAuthority()
    rsu_creds = ta.enroll_rsu("RSU-METRO-01")
    rsu = RSUকারNode(
        rsu_id="RSU-METRO-01",
        ta_public_key=ta.master_public_key,
        rsu_cert=rsu_creds["certificate"],
        rsu_private_key=rsu_creds["private_key"]
    )

    # TA revokes a test serial
    ta.crl_manager.revoke_certificate("SERIAL-X-999")
    signed_crl = ta.crl_manager.get_signed_crl(ta.master_private_key)

    # RSU ingests CRL
    success = rsu.receive_crl_update(signed_crl)
    assert success is True
    assert "SERIAL-X-999" in rsu.cached_revoked_serials

    # RSU generates signed hazard advisory
    alert = rsu.create_road_hazard_alert(
        hazard_type="ICY_ROAD",
        latitude=37.77,
        longitude=-122.42
    )

    assert alert["body"]["header"]["message_type"] == "ROAD_HAZARD"
    assert alert["body"]["payload"]["hazard_type"] == "ICY_ROAD"
    assert "signature" in alert
    assert "sender_certificate" in alert