import time
import pytest
from src.trusted_authority.ta_server import TrustedAuthority
from src.vehicle.vehicle_node import VehicleNode
from src.attacks.geocast_spoof_attack import GeocastAttacker
from src.attacks.kinematic_anomaly_attack import KinematicAttacker
from src.utils.spatial_utils import calculate_haversine_distance


@pytest.fixture
def setup_nodes():
    ta = TrustedAuthority()
    vid_1 = "VIN-CAR-1"
    vid_2 = "VIN-CAR-2"

    ta.register_vehicle(vid_1)
    ta.register_vehicle(vid_2)

    batch_1 = ta.request_pseudonyms(vid_1, count=5)
    batch_2 = ta.request_pseudonyms(vid_2, count=5)

    # Both cars start close together (same intersection, ~50m apart)
    car_1 = VehicleNode(vid_1, ta.master_public_key, batch_1, initial_lat=37.77490, initial_lon=-122.41940)
    car_2 = VehicleNode(vid_2, ta.master_public_key, batch_2, initial_lat=37.77530, initial_lon=-122.41940)

    return ta, car_1, car_2


def test_haversine_distance_computation():
    # Known distance: (37.7749, -122.4194) to (37.7753, -122.4194) is ~44.47 meters
    dist = calculate_haversine_distance(37.7749, -122.4194, 37.7753, -122.4194)
    assert 40.0 < dist < 50.0


def test_geocasting_out_of_range_rejection(setup_nodes):
    _, car_1, car_2 = setup_nodes

    # Car 1 emits message from 10km away
    distant_msg = GeocastAttacker.craft_distant_beacon(car_1)

    is_valid, reason = car_2.verify_inbound_message(distant_msg, enforce_geocasting=True)
    assert is_valid is False
    assert "DROP_OUT_OF_RANGE_GEOCAST" in reason


def test_kinematic_implausible_speed_rejection(setup_nodes):
    _, car_1, car_2 = setup_nodes

    # Broadcast speed of 350 km/h
    bad_msg = KinematicAttacker.craft_excessive_speed_beacon(car_1)

    is_valid, reason = car_2.verify_inbound_message(bad_msg, enforce_geocasting=False)
    assert is_valid is False
    assert reason == "DROP_IMPLAUSIBLE_SPEED"


def test_kinematic_teleportation_rejection(setup_nodes):
    _, car_1, car_2 = setup_nodes

    # Packet 1: Normal cruising
    msg_1 = car_1.create_safety_message(speed_kmh=60.0)
    valid_1, _ = car_2.verify_inbound_message(msg_1, enforce_geocasting=False)
    assert valid_1 is True

    # Packet 2: 100ms later, coordinates jump by 2km (teleportation)
    time.sleep(0.1)
    msg_teleport = KinematicAttacker.craft_teleportation_beacon(car_1)
    valid_2, reason_2 = car_2.verify_inbound_message(msg_teleport, enforce_geocasting=False)

    assert valid_2 is False
    assert reason_2 == "DROP_TELEPORTATION_EXCESSIVE_VELOCITY"


def test_kinematic_impossible_acceleration_rejection(setup_nodes):
    _, car_1, car_2 = setup_nodes

    # Packet 1: 50 km/h
    msg_1 = car_1.create_safety_message(speed_kmh=50.0)
    valid_1, _ = car_2.verify_inbound_message(msg_1, enforce_geocasting=False)
    assert valid_1 is True

    # Packet 2: 100ms later, speed jumps to 150 km/h (100 km/h delta in 0.1s = ~277 m/s² accel!)
    time.sleep(0.1)
    msg_accel = car_1.create_safety_message(speed_kmh=150.0)
    valid_2, reason_2 = car_2.verify_inbound_message(msg_accel, enforce_geocasting=False)

    assert valid_2 is False
    assert reason_2 == "DROP_IMPLAUSIBLE_ACCELERATION"