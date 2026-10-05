import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import time
import threading
import tkinter as tk

from src.trusted_authority.ta_server import TrustedAuthority
from src.vehicle.vehicle_node import VehicleNode
from src.vehicle.communication import V2VChannel
from src.rsu.rsu_node import RSUকারNode
from src.attacks.replay_attack import ReplayAttacker
from src.attacks.tampering_attack import TamperingAttacker
from src.attacks.sybil_attack import SybilAttacker
from src.attacks.dos_flooding import DoSAttacker
from src.attacks.kinematic_anomaly_attack import KinematicAttacker
from src.utils.spatial_utils import calculate_haversine_distance
from gui.dashboard import V2VDashboard


def main():
    print("[+] Initializing Trusted Authority (TA) PKI Root...")
    ta = TrustedAuthority()

    CAR_B_LAT, CAR_B_LON = 37.77490, -122.41940
    CAR_A_LAT, CAR_A_LON = 37.77560, -122.41940
    RSU_LAT, RSU_LON = 37.77580, -122.41940

    ta.register_vehicle("VIN-CAR-ALPHA")
    ta.register_vehicle("VIN-CAR-BETA")

    batch_a = ta.request_pseudonyms("VIN-CAR-ALPHA", count=10)
    batch_b = ta.request_pseudonyms("VIN-CAR-BETA", count=10)

    car_a = VehicleNode("VIN-CAR-ALPHA", ta.master_public_key, batch_a, initial_lat=CAR_A_LAT, initial_lon=CAR_A_LON, initial_speed=55.0)
    car_b = VehicleNode("VIN-CAR-BETA", ta.master_public_key, batch_b, initial_lat=CAR_B_LAT, initial_lon=CAR_B_LON, initial_speed=50.0)

    rsu_credentials = ta.enroll_rsu("RSU-SF-DOWNTOWN-01")
    rsu_node = RSUকারNode(
        rsu_id="RSU-SF-DOWNTOWN-01",
        ta_public_key=ta.master_public_key,
        rsu_cert=rsu_credentials["certificate"],
        rsu_private_key=rsu_credentials["private_key"]
    )

    PORT_A = 6001
    PORT_B = 6002

    chan_a = V2VChannel(port=PORT_A)
    chan_b = V2VChannel(port=PORT_B)

    replay_attacker = ReplayAttacker()
    root = tk.Tk()

    def handle_attack_injection(action_type: str):
        if action_type == "UNICAST_HANDSHAKE":
            pseudo_b = car_b.pseudonym_pool.get_active_credentials()["certificate"]["certificate_data"]["pseudonym_id"]
            dashboard.log_event(f"[ECDH INITIATION] Car ALPHA initiating ECDH handshake with {pseudo_b}...", "UNICAST")
            init_pkt = car_a.unicast_mgr.initiate_handshake(target_pseudonym_id=pseudo_b)
            if init_pkt:
                chan_a.broadcast(init_pkt, target_port=PORT_B)

        elif action_type == "RSU_BLACK_ICE":
            dashboard.log_event("[RSU SENSOR] Infrared surface sensor detected BLACK ICE! Broadcasting advisory...", "INFO")
            hazard_packet = rsu_node.create_road_hazard_alert(
                hazard_type="BLACK_ICE",
                latitude=RSU_LAT,
                longitude=RSU_LON,
                recommended_speed_kmh=25.0
            )
            chan_a.broadcast(hazard_packet, target_port=PORT_B)

        elif action_type == "TAMPER":
            legit = car_a.create_safety_message(speed_kmh=45.0)
            tampered = TamperingAttacker.modify_telemetry(legit, fake_speed=140.0, fake_event="EMERGENCY_BRAKE")
            dashboard.log_event("[ADVERSARY] Injected TAMPERED payload into channel...", "INFO")
            chan_a.broadcast(tampered, target_port=PORT_B)

        elif action_type == "REPLAY":
            legit = car_a.create_safety_message(speed_kmh=55.0)
            replay_attacker.capture_message(legit)
            dashboard.log_event("[ADVERSARY] Captured frame. Replaying after 3.5s delay...", "INFO")

            def delayed_send():
                time.sleep(3.5)
                pkt = replay_attacker.craft_delayed_replay()
                chan_a.broadcast(pkt, target_port=PORT_B)
            threading.Thread(target=delayed_send, daemon=True).start()

        elif action_type == "SYBIL":
            dashboard.log_event("[ADVERSARY] Injecting 3 uncertified ghost vehicles into radar range...", "INFO")
            ghosts = SybilAttacker().generate_ghost_beacons(count=3)
            for g in ghosts:
                chan_a.broadcast(g, target_port=PORT_B)

        elif action_type == "TELEPORT":
            dashboard.log_event("[ADVERSARY] Injecting impossible coordinate displacement (Teleportation)...", "INFO")
            teleport_msg = KinematicAttacker.craft_teleportation_beacon(car_a)
            chan_a.broadcast(teleport_msg, target_port=PORT_B)

        elif action_type == "DOS":
            dashboard.log_event("[ADVERSARY] Flooding broadcast channel with malformed DoS frames...", "INFO")
            malformed = DoSAttacker.generate_malformed_packets(count=5)
            for m in malformed:
                chan_a.broadcast(m, target_port=PORT_B)

    dashboard = V2VDashboard(root, trigger_attack_cb=handle_attack_injection)

    # Receiver Pipeline for Car ALPHA (Listens on PORT_A)
    def on_car_a_receive(packet, addr):
        if not isinstance(packet, dict):
            return
        header = packet.get("body", {}).get("header", {}) if isinstance(packet.get("body"), dict) else packet.get("header", {})
        msg_type = header.get("message_type")

        if msg_type == "UNICAST_HANDSHAKE_RESP":
            success = car_a.unicast_mgr.complete_handshake(packet)
            if success:
                peer_pseudo = header.get("sender_pseudonym")
                dashboard.log_event(f"[ECDH COMPLETE] Car ALPHA established shared key with {peer_pseudo}.", "UNICAST")

                # Transmit encrypted platooning instructions
                platoon_plan = {
                    "platoon_id": "PLATOON-ALPHA-BETA",
                    "inter_vehicle_gap_meters": 4.5,
                    "target_cruise_speed": 65.0,
                    "lane_change_intent": "LANE_2_TO_EXIT_3"
                }
                enc_msg = car_a.unicast_mgr.encrypt_unicast_payload(peer_pseudo, platoon_plan)
                dashboard.log_event(f"[AES-GCM CIPHERTEXT] Encrypted transmission: {enc_msg['encrypted']['ciphertext'][:32]}...", "UNICAST")
                chan_a.broadcast(enc_msg, target_port=PORT_B)

    chan_a.start_listener(on_car_a_receive)

    # Receiver Pipeline for Car BETA (Listens on PORT_B)
    def on_car_b_receive(packet, addr):
        if not isinstance(packet, dict):
            dashboard.update_stats(accepted=False)
            dashboard.log_event("[BLOCKED] Security Alert! Dropped: DROP_NON_DICT_PACKET", "DROP")
            return

        # Check for direct unicast messages
        header_direct = packet.get("header", {})
        if header_direct.get("message_type") == "UNICAST_CONFIDENTIAL_PAYLOAD":
            decrypted = car_b.unicast_mgr.decrypt_unicast_payload(packet)
            if decrypted:
                dashboard.update_stats(accepted=True)
                dashboard.log_event(
                    f"[DECRYPTED PLAINTEXT] Gap: {decrypted.get('inter_vehicle_gap_meters')}m | Cruise: {decrypted.get('target_cruise_speed')} km/h | Lane: {decrypted.get('lane_change_intent')}",
                    "ACCEPT"
                )
            else:
                dashboard.update_stats(accepted=False)
                dashboard.log_event("[BLOCKED] Unicast Decryption / Auth Tag Check Failed!", "DROP")
            return

        body_header = packet.get("body", {}).get("header", {}) if isinstance(packet.get("body"), dict) else {}
        if body_header.get("message_type") == "UNICAST_HANDSHAKE_INIT":
            dashboard.log_event("[ECDH INBOUND] Car BETA received handshake request. Deriving secret...", "UNICAST")
            resp = car_b.unicast_mgr.respond_to_handshake(packet)
            if resp:
                dashboard.update_stats(accepted=True)
                dashboard.log_event("[ECDH RESPONSE] Car BETA returning ephemeral public key to Car ALPHA.", "UNICAST")
                chan_b.broadcast(resp, target_port=PORT_A)
            return

        # General broadcast verification pipeline
        is_valid, reason = car_b.verify_inbound_message(packet, enforce_geocasting=True)
        dashboard.update_stats(accepted=is_valid)

        raw_body = packet.get("body")
        body = raw_body if isinstance(raw_body, dict) else {}

        raw_payload = body.get("payload")
        payload = raw_payload if isinstance(raw_payload, dict) else {}

        raw_header = body.get("header")
        header = raw_header if isinstance(raw_header, dict) else {}

        raw_cert = packet.get("sender_certificate")
        cert_dict = raw_cert if isinstance(raw_cert, dict) else {}
        cert_data = cert_dict.get("certificate_data")
        cert = cert_data if isinstance(cert_data, dict) else {}

        pseudo_id = cert.get("pseudonym_id", "UNKNOWN")
        speed = payload.get("speed_kmh", 0.0)
        target_lat = payload.get("latitude")
        target_lon = payload.get("longitude")
        heading = payload.get("heading_deg", 0.0)
        ev_type = header.get("message_type", "UNKNOWN")

        if is_valid:
            if ev_type == "ROAD_HAZARD":
                hazard = payload.get("hazard_type", "HAZARD")
                rec_spd = payload.get("recommended_speed_kmh", 30.0)
                dist = calculate_haversine_distance(car_b.current_lat, car_b.current_lon, target_lat, target_lon)
                dashboard.log_event(f"[RSU ADVISORY] {pseudo_id} reports {hazard} at {dist:.0f}m! Decelerating to {rec_spd} km/h.", "ACCEPT")
                dashboard.plot_radar_vehicle(
                    pseudo_id=f"RSU-{hazard}",
                    ego_lat=car_b.current_lat,
                    ego_lon=car_b.current_lon,
                    target_lat=target_lat,
                    target_lon=target_lon,
                    speed_kmh=0.0,
                    heading_deg=0.0,
                    event_type="ROAD_HAZARD",
                    is_attack=False
                )
            else:
                dashboard.log_event(f"[ACCEPTED] {pseudo_id} | {ev_type} | Speed: {speed:.1f} km/h", "ACCEPT")
                dashboard.plot_radar_vehicle(
                    pseudo_id=pseudo_id,
                    ego_lat=car_b.current_lat,
                    ego_lon=car_b.current_lon,
                    target_lat=target_lat if target_lat is not None else car_b.current_lat,
                    target_lon=target_lon if target_lon is not None else car_b.current_lon,
                    speed_kmh=speed,
                    heading_deg=heading,
                    event_type=ev_type,
                    is_attack=False
                )
        else:
            dashboard.log_event(f"[BLOCKED] Security Alert! Dropped: {reason}", "DROP")
            if isinstance(target_lat, (int, float)) and isinstance(target_lon, (int, float)):
                dashboard.plot_radar_vehicle(
                    pseudo_id=f"BLOCKED-{pseudo_id[:6]}",
                    ego_lat=car_b.current_lat,
                    ego_lon=car_b.current_lon,
                    target_lat=target_lat,
                    target_lon=target_lon,
                    speed_kmh=speed,
                    heading_deg=heading,
                    event_type=ev_type,
                    is_attack=True
                )

    chan_b.start_listener(on_car_b_receive)

    # Dynamic orbit loop for Car ALPHA
    def dynamic_movement_simulation():
        angle = 0.0
        radius_deg = 0.0012

        while True:
            time.sleep(1.5)
            alpha_lat = CAR_B_LAT + (radius_deg * 0.8 * (1.0 + 0.3 * (angle % 3)) * (1 if int(angle) % 2 == 0 else -1) * 0.5)
            alpha_lon = CAR_B_LON + (radius_deg * ((angle % 4) - 2) * 0.3)

            car_a.set_position(lat=alpha_lat, lon=alpha_lon, speed_kmh=52.0 + (angle % 5))
            msg = car_a.create_safety_message(event_type="BEACON")
            if msg:
                msg["body"]["payload"]["heading_deg"] = (angle * 45) % 360
                chan_a.broadcast(msg, target_port=PORT_B)

            angle += 0.5

    sim_thread = threading.Thread(target=dynamic_movement_simulation, daemon=True)
    sim_thread.start()

    dashboard.log_event("Radar and V2V Network Online. Monitoring 350m perimeter.", "INFO")

    try:
        root.mainloop()
    finally:
        chan_a.close()
        chan_b.close()

if __name__ == "__main__":
    main()