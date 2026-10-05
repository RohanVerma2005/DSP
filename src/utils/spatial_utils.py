import math
from typing import Tuple, Dict, Any, Optional

from src.utils.constants import (
    MAX_GEOCAST_DISTANCE_METERS,
    MAX_PLAUSIBLE_SPEED_KMH,
    MAX_PLAUSIBLE_ACCEL_MS2,
    MIN_SAMPLING_DELTA_TIME
)

EARTH_RADIUS_METERS = 6371000.0


def calculate_haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculates the great-circle distance between two points on Earth in meters.
    """
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
            math.sin(delta_phi / 2.0) ** 2
            + math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2)
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return EARTH_RADIUS_METERS * c


def evaluate_geocast_relevance(
        receiver_pos: Tuple[float, float],
        sender_pos: Tuple[float, float],
        max_range_m: float = MAX_GEOCAST_DISTANCE_METERS
) -> Tuple[bool, float]:
    """
    Checks if the sender is within relevant spatial distance of the receiver.
    Returns (is_relevant, distance_in_meters).
    """
    dist = calculate_haversine_distance(
        receiver_pos[0], receiver_pos[1],
        sender_pos[0], sender_pos[1]
    )
    return dist <= max_range_m, dist


def check_kinematic_plausibility(
        prev_state: Optional[Dict[str, Any]],
        current_state: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Evaluates kinematic plausibility between consecutive telemetry frames for a single pseudonym.

    current_state format:
      {"timestamp": float, "lat": float, "lon": float, "speed_kmh": float}
    """
    current_speed = current_state["speed_kmh"]

    # 1. Absolute velocity ceiling check
    if current_speed < 0 or current_speed > MAX_PLAUSIBLE_SPEED_KMH:
        return False, "DROP_IMPLAUSIBLE_SPEED"

    # If no prior state exists for this pseudonym, no delta evaluation is possible
    if prev_state is None:
        return True, "ACCEPT_KINEMATICS"

    dt = current_state["timestamp"] - prev_state["timestamp"]
    if dt < MIN_SAMPLING_DELTA_TIME:
        # Received too close in time to evaluate derivatives reliably
        return True, "ACCEPT_KINEMATICS"

    # 2. Coordinate displacement velocity (detect GPS teleportation)
    displacement_m = calculate_haversine_distance(
        prev_state["lat"], prev_state["lon"],
        current_state["lat"], current_state["lon"]
    )
    implied_speed_ms = displacement_m / dt
    implied_speed_kmh = implied_speed_ms * 3.6

    # If displacement implied speed massively exceeds realistic road speeds
    if implied_speed_kmh > MAX_PLAUSIBLE_SPEED_KMH:
        return False, "DROP_TELEPORTATION_EXCESSIVE_VELOCITY"

    # 3. Acceleration / Deceleration limit check
    v1_ms = prev_state["speed_kmh"] / 3.6
    v2_ms = current_state["speed_kmh"] / 3.6
    acceleration_ms2 = abs(v2_ms - v1_ms) / dt

    if acceleration_ms2 > MAX_PLAUSIBLE_ACCEL_MS2:
        return False, "DROP_IMPLAUSIBLE_ACCELERATION"

    return True, "ACCEPT_KINEMATICS"