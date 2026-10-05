# Secure Vehicle-to-Vehicle (V2V) & Vehicle-to-Infrastructure (V2I) Communication Protocol

An automotive-grade, zero-trust cryptographic communication framework for connected and autonomous vehicles (CAVs). This protocol implements decentralized broadcast authentication, privacy-preserving rotating pseudonym certificates, kinematic plausibility validation, geocasting boundary enforcement, and ephemeral ECDH-based unicast channels protected by AES-256-GCM authenticated encryption.

---

## 1. System Architecture & Entity Model

The protocol models the standard vehicular ad-hoc network (VANET) ecosystem, establishing mutual trust across physical, network, and cryptographic layers:

┌─────────────────────────────────────┐
                      │     Trusted Authority (TA / PKI)    │
                      │   - Root Key Management (secp256r1) │
                      │   - Vehicle / RSU Enrollment        │
                      │   - CRL Management & Revocation     │
                      └──────────────────┬──────────────────┘
                                         │ Issuance & Revocation
                  ┌──────────────────────┴──────────────────────┐
                  ▼                                             ▼
      ┌───────────────────────┐                     ┌───────────────────────┐
      │  Roadside Unit (RSU)  │                     │   Vehicle Node (OBU)  │
      │ - Civil Infrastructure│                     │ - Pseudonym Keystore  │
      │ - I2V Hazard Warnings │                     │ - Multi-Stage Defense │
      │ - CRL Synchronization │                     │ - Kinematic Engine    │
      └───────────┬───────────┘                     └───────────┬───────────┘
                  │                                             │
                  │ (UDP Broadcast: 6002)                       │ (V2V Broadcast / ECDH Unicast)
                  └──────────────────────► ◄────────────────────┘

### 1.1 Core Entities

1. **Trusted Authority (TA):**
   * Serves as the central Root of Trust (Root CA).
   * Generates and secures the master elliptic curve keypair (`secp256r1`).
   * Verifies hardware identifiers (VIDs) during vehicle registration and issues batches of short-lived pseudonym certificates.
   * Manages the Certificate Revocation List (CRL) for compromised or misbehaving nodes.
2. **Onboard Unit (OBU / Vehicle Node):**
   * Embedded edge computing system operating in each connected vehicle.
   * Maintains a rotating pool of pseudonym credentials to prevent location tracking and vehicular fingerprinting.
   * Executes the 6-stage inbound message verification pipeline in real time.
3. **Roadside Unit (RSU):**
   * Stationary civil infrastructure nodes deployed along transportation corridors.
   * Disseminates authenticated Infrastructure-to-Vehicle (I2V) safety alerts (e.g., icy road alerts, accident advisories).
   * Caches and redistributes TA-signed CRL updates to passing vehicles.
4. **Adversary Node:**
   * External or insider threat model simulating packet manipulation, eavesdropping, identity forgery, kinematic spoofing, and fuzzing attacks.

---

## 2. Cryptographic Specification & Primitives

All cryptographic primitives are implemented using the automotive NIST P-256 (`secp256r1`) standard:

| Security Goal | Mechanism / Primitive | Specification | Implementation Detail |
| :--- | :--- | :--- | :--- |
| **Broadcast Authentication** | ECDSA (`secp256r1`) + SHA-256 | IEEE 1609.2 / ETSI ITS-G5 | Ephemeral pseudonym keypair signing |
| **Payload Integrity** | SHA-256 Canonical Hashing | RFC 8785 (JCS-like) | Deterministic UTF-8 serialization |
| **Unicast Confidentiality** | AES-256-GCM | NIST SP 800-38D | 256-bit symmetric key, 96-bit nonce, 128-bit tag |
| **Key Agreement** | ECDH over `secp256r1` | ANSI X9.63 | Ephemeral-Ephemeral key exchange |
| **Key Derivation** | HKDF-SHA256 | RFC 5869 | Expands raw shared secret into 32-byte key |
| **Location Privacy** | Pseudonym Certificates | C-V2X Privacy Standard | 5–10 min validity rotation; unlinked IDs |

---

## 3. Protocol Message Specification

### 3.1 Standard Canonical Broadcast Envelope (CAM / BSM)

JSON

{
  "body": {
    "header": {
      "protocol_version": "1.0",
      "message_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "seq_no": 1042,
      "timestamp": 1727181632.415,
      "message_type": "BEACON"
    },
    "payload": {
      "latitude": 37.774929,
      "longitude": -122.419416,
      "speed_kmh": 68.4,
      "heading_deg": 182.5
    }
  },
  "sender_certificate": {
    "certificate_data": {
      "serial_number": "3f8b89d4-1fbc-4cb1-807e-97ec59c84e1b",
      "pseudonym_id": "PSEUDO-A4F82910",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "valid_from": 1727181600.0,
      "valid_to": 1727181900.0
    },
    "ta_signature": "MEQCIDz..."
  },
  "signature": "MEQCIF3b1Q6l1..."
}


### 3.2 Confidential Unicast Envelope

JSON

{
  "header": {
    "message_type": "UNICAST_CONFIDENTIAL_PAYLOAD",
    "sender_pseudonym": "PSEUDO-A4F82910",
    "target_pseudonym": "PSEUDO-B180C42F",
    "timestamp": 1727181635.102
  },
  "encrypted": {
    "nonce": "a8F1k3Lm90Q=",
    "ciphertext": "Kb910vNxQ9910d..."
  }
}

## 4. Multi-Stage Inbound Verification Pipeline

Every inbound wireless frame received by an Onboard Unit is processed through a sequential, fail-fast verification pipeline:

                      Inbound UDP Packet
                              │
                              ▼
                ┌───────────────────────────┐
                │ Stage 0: Defensive Parser │ ──▶ Drop if malformed / non-dict
                └─────────────┬─────────────┘
                              ▼
                ┌───────────────────────────┐
                │ Stage 1: Freshness Check  │ ──▶ Drop if |t_recv - t_msg| > 2.0s
                │          Sequence Check   │ ──▶ Drop if seq_no <= last_seen_seq
                └─────────────┬─────────────┘
                              ▼
                ┌───────────────────────────┐
                │ Stage 2: Revocation Check │ ──▶ Drop if cert_serial in CRL cache
                └─────────────┬─────────────┘
                              ▼
                ┌───────────────────────────┐
                │ Stage 3: TA Root Check    │ ──▶ Drop if TA signature is invalid
                │          Temporal Window  │ ──▶ Drop if current_time not in [valid_from, valid_to]
                └─────────────┬─────────────┘
                              ▼
                ┌───────────────────────────┐
                │ Stage 4: ECDSA Signature  │ ──▶ Drop if payload tampered / signature mismatch
                └─────────────┬─────────────┘
                              ▼
                ┌───────────────────────────┐
                │ Stage 5: Geocasting Filter│ ──▶ Drop if Haversine distance > 300m
                └─────────────┬─────────────┘
                              ▼
                ┌───────────────────────────┐
                │ Stage 6: Kinematic Check  │ ──▶ Drop if speed > 250 km/h
                │                           │ ──▶ Drop if Δpos / Δt implies impossible velocity
                │                           │ ──▶ Drop if acceleration > 12 m/s²
                └─────────────┬─────────────┘
                              ▼
                    ACCEPT & PROCESS FRAME

## 5. Threat Model & Simulated Attack Vectors

Attack Vector
Attacker Capability
Detection Mechanism
Status Code

Replay Attack
Captures authentic packets and re-transmits them after a delay.
Clock skew boundary Δ t > 2.0 s and sequence counter tracking.
DROP_REPLAY_STALE_TIMESTAMP / DROP_REPLAY_DUPLICATE_OR_REGRESSIVE_SEQ

Payload Tampering (MITM)
Intercepts in-flight frames and alters telemetry fields (e.g., speed, alert type).
ECDSA signature verification against canonical SHA-256 payload digest.
DROP_CORRUPTED_OR_TAMPERED_PAYLOAD

Sybil Attack
Generates multiple fake vehicle identities from an unauthorized node.
Certificate legitimacy validation against Trusted Authority root public key.
DROP_INVALID_TA_SIGNATURE

Impersonation Attack	
Forges high-priority emergency broadcasts using self-signed credentials.	
Chain of trust verification against TA root key.	
DROP_INVALID_TA_SIGNATURE

Teleportation / Kinematic Spoofing	
Insider attack where a registered node transmits impossible GPS displacements.	
Great-circle Haversine displacement velocity & acceleration checks.	
DROP_TELEPORTATION_EXCESSIVE_VELOCITY / DROP_IMPLAUSIBLE_ACCELERATION

Geocast Boundary Violation	
Emits safety beacons from locations beyond spatial relevance.	
Great-circle distance computation (>300m threshold).	
DROP_OUT_OF_RANGE_GEOCAST

Denial-of-Service (DoS) Fuzzing	
Floods communication channel with malformed packet structures.	
Defensive schema enforcement and type checking prior to evaluation.	
DROP_MALFORMED_STRUCTURE / DROP_NON_DICT_PACKET

### 6. Directory Structure
V2V-Secure-Protocol/
├── requirements.txt                  # Dependency manifest
├── README.md                         # Protocol documentation
│
├── src/
│   ├── __init__.py
│   ├── trusted_authority/
│   │   ├── __init__.py
│   │   ├── ta_server.py              # Central PKI server & registry
│   │   ├── certificate_manager.py    # Pseudonym certificate batch issuer
│   │   └── crl_manager.py            # Revocation list management
│   │
│   ├── vehicle/
│   │   ├── __init__.py
│   │   ├── vehicle_node.py           # OBU engine & 6-stage inbound pipeline
│   │   ├── pseudonym_pool.py         # Autonomous certificate rotation
│   │   ├── communication.py          # Threaded UDP socket broadcaster/listener
│   │   └── unicast_session.py        # ECDH key agreement & AES-GCM unicast
│   │
│   ├── rsu/
│   │   ├── __init__.py
│   │   └── rsu_node.py               # Roadside Unit for I2V advisories & CRLs
│   │
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── constants.py              # Protocol constraints & parameters
│   │   ├── crypto_utils.py           # ECDSA, ECDH, HKDF, AES-GCM primitives
│   │   ├── message_utils.py          # Canonical deterministic serialization
│   │   └── spatial_utils.py          # Haversine distance & kinematic checks
│   │
│   └── attacks/
│       ├── __init__.py
│       ├── replay_attack.py          # Captures and delays message frames
│       ├── tampering_attack.py       # Modifies telemetry payload post-signing
│       ├── sybil_attack.py           # Forges unauthorized ghost identities
│       ├── impersonation_attack.py   # Spoofs priority emergency alerts
│       ├── kinematic_anomaly_attack.py # Emits teleporting / excessive speed frames
│       ├── geocast_spoof_attack.py   # Generates out-of-bounds telemetry
│       └── dos_flooding.py           # High-rate malformed frame generator
│
├── gui/
│   ├── __init__.py
│   ├── dashboard.py                  # Tkinter Security Operations Center
│   └── radar_canvas.py               # 2D polar/Cartesian moving-map radar
│
├── tests/
│   ├── __init__.py
│   ├── test_crypto.py                # Cryptographic primitives unit tests 
│   ├── test_ta.py                    # PKI & certificate issuance tests
│   ├── test_vehicle.py               # OBU validation & rollover tests
│   ├── test_network.py               # UDP socket & RSU communication tests
│   ├── test_attacks.py               # Attack model mitigation validation
│   ├── test_kinematics_and_geocast.py# Spatial and kinematic plausibility tests
│   ├── test_unicast_ecdh.py          # ECDH handshake & AES-GCM tests
│   └── test_integration.py          # End-to-end full system lifecycle test
│
└── demo/
    ├── __init__.py
    └── simulation_runner.py          # Multi-node interactive simulation

### 7. Installation & Setup
## 7.1 Prerequisites
Python 3.9+ (Tested through Python 3.14)

Standard C-compiler / OpenSSL runtime (packaged automatically by cryptography)

## 7.2 Installation Steps
Clone the repository:

git clone [https://github.com/your-username/V2V-Secure-Protocol.git](https://github.com/your-username/V2V-Secure-Protocol.git)
cd V2V-Secure-Protocol
Create and activate a virtual environment:

Linux / macOS:

Bash
python3 -m venv .venv
source .venv/bin/activate
Windows (PowerShell):

PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
Install dependencies:

Bash
pip install -r requirements.txt

8. Verification & Test Suite
The repository includes a comprehensive, automated test suite covering all cryptographic, network, kinematic, and attack defense layers.

Run all 32 unit and integration tests:

PowerShell
pytest tests/ -v
Expected Output Summary
Plaintext
tests/test_attacks.py .................................. [PASSED]
tests/test_crypto.py ................................... [PASSED]
tests/test_integration.py .............................. [PASSED]
tests/test_kinematics_and_geocast.py ................... [PASSED]
tests/test_network.py .................................. [PASSED]
tests/test_ta.py ....................................... [PASSED]
tests/test_unicast_ecdh.py ............................. [PASSED]
tests/test_vehicle.py .................................. [PASSED]

============================== 32 passed in 0.65s ==============================

### 9. Verification & Automated Test Suite
Run all 32 unit and integration tests across every layer of the protocol:

PowerShell
pytest tests/ -v
Test Suite Coverage

tests/test_crypto.py: Validates ECDSA signing/verification, PEM serialization, and AES-256-GCM encryption/tampering detection.
tests/test_ta.py: Tests vehicle registration, pseudonym batch issuance, temporal window validation, and CRL management.
tests/test_vehicle.py: Tests standard message synthesis, pseudonym rollover, CRL enforcement, and replay defenses.
tests/test_network.py: Tests real threaded UDP socket transmission and RSU hazard alert generation.
tests/test_attacks.py: Tests defenses against Replay, Tampering, Sybil, Impersonation, and DoS attacks.
tests/test_kinematics_and_geocast.py: Validates Haversine distance, out-of-range geocast dropping, teleportation detection, and acceleration limits.
tests/test_unicast_ecdh.py: Tests the 3-way ECDH handshake, HKDF key derivation, and confidential AES-GCM unicast transmission.
tests/test_integration.py: End-to-end integration lifecycle test.


### 10. Standards & Reference Compliance

IEEE 1609.2-2016: Standard for Wireless Access in Vehicular Environments (WAVE) — Security Services for Applications and Management Messages.
ETSI TS 102 940 / TS 103 097: Intelligent Transport Systems (ITS); Security; Trust and Privacy Management. 
NIST FIPS 186-4: Digital Signature Standard (DSS) — Elliptic Curve Digital Signature Algorithm (ECDSA).
NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM).
RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
RFC 8785: JSON Canonicalization Scheme (JCS).
































