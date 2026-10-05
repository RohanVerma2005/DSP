"""
System-wide constants and configuration values for the V2V protocol.
"""

# Networking Configuration
BROADCAST_PORT = 5005
BROADCAST_IP = "255.255.255.255"
TA_SERVER_HOST = "127.0.0.1"
TA_SERVER_PORT = 8080

# Security and Protocol Constraints
MAX_CLOCK_SKEW_SECONDS = 2.0  # Max acceptable time difference for replay defense
MAX_SEQ_GAP = 500             # Maximum allowed sequence number jump
PSEUDONYM_VALIDITY_SECONDS = 300  # Pseudonym cert validity: 5 minutes

# Elliptic Curve Definition
CURVE_NAME = "secp256r1"

# Protocol Message Types
MSG_TYPE_BEACON = "BEACON"
MSG_TYPE_EMERGENCY_BRAKE = "EMERGENCY_BRAKE"
MSG_TYPE_ACCIDENT = "ACCIDENT_WARNING"
MSG_TYPE_ROAD_HAZARD = "ROAD_HAZARD"

# Kinematic and Spatial Filtering Limits
MAX_GEOCAST_DISTANCE_METERS = 300.0   # Beyond 300m, beacons are ignored
MAX_PLAUSIBLE_SPEED_KMH = 250.0       # Max physical vehicle velocity (~69.4 m/s)
MAX_PLAUSIBLE_ACCEL_MS2 = 12.0        # Max physical acceleration/deceleration (~1.22g)
MIN_SAMPLING_DELTA_TIME = 0.05        # Ignore delta calculations below 50ms to avoid division by zero