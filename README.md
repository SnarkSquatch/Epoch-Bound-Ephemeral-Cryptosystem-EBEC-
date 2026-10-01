# Epoch Bound Ephemeral Cipher (EBEC)

A lightweight cryptographic engine for authenticated ephemeral data transmission, designed so relay and storage infrastructure does not possess the keys required to decrypt payloads.

> **Disclaimer:** EBEC is a custom cryptographic protocol. It should undergo independent security review and testing before being used for high-value or safety-critical applications.

EBEC uses an ephemeral X25519 key exchange to establish a shared session root secret, then derives rotating per-epoch symmetric encryption keys on demand. No static key rings, certificate authorities, or persistent identity keys are required.

---

## Core Features

* **Ephemeral Key Exchange:** Uses ephemeral X25519 ECDH to establish a shared session root secret without transmitting the secret itself.
* **Role-Bound Canonical Transcripts:** Explicitly requires `initiator` and `responder` roles during key exchange to construct role-independent canonical transcripts.
* **Transcript-Bound SAS:** Derives a 48-bit Short Authentication String (SAS) from the X25519 shared secret and both ephemeral public keys. Comparing the SAS through an independent trusted channel provides protection against active man-in-the-middle attacks.
* **Session ID Derivation:** Automatically derives a 128-bit unique session identifier alongside the root secret and SAS.
* **Active Security Defenses:** Built-in protection against self-reflection attacks, low-order point / weak shared secret generation, and instance reuse.
* **Automatic Epoch Key Derivation:** Encryption keys rotate every 60 seconds and are derived on demand from the session root secret using HKDF-SHA256.
* **Authenticated Encryption:** AES-256-GCM provides confidentiality and integrity for every packet.
* **Server-Blind Payloads:** Relay and storage layers do not possess the session root secret and therefore cannot decrypt payload contents.
* **Strict Replay and Freshness Defense:** Timestamp validation, future-skew enforcement, and a bounded in-memory replay cache help prevent stale and replayed packets.
* **Language-Agnostic Wire Format:** Packets use a strict binary layout and URL-safe Base64 encoding for compatibility with Python, Rust, C, Go, and other environments.
* **No Persistent Identity Keys:** Ephemeral X25519 private keys are generated in memory and enforced as single-use instances.

---

## Security Model

### EBEC is designed to provide:

* Confidentiality of encrypted payloads from intermediaries that do not possess the session root secret.
* Integrity and authentication of packet contents through AES-256-GCM.
* Ephemeral session establishment using X25519 with single-use session enforcement.
* Peer authentication through an independently verified SAS.
* Explicit reflection attack and low-order point shared-secret defenses.
* Per-epoch encryption-key separation.
* Packet freshness and replay detection within the configured acceptance window.

### EBEC does NOT currently provide:

* Forward secrecy after compromise of the session root secret. Because epoch keys are derived from the same root secret, possession of that root secret permits derivation of past and future epoch keys.
* Protection of transport metadata such as packet size, timing, routing information, or externally visible timestamps.
* Peer authentication if the SAS is not independently verified.
* Protection against a compromised endpoint whose session root secret or plaintext is exposed.
* Persistent identity authentication or identity continuity across independent sessions.
* Automatic synchronization of newly generated root secrets between peers.

*For applications requiring forward secrecy after session-root compromise, an evolving key schedule or ratcheting protocol is required.*

---

## Binary Packet Layout

All transmitted payloads adhere to the following binary layout before Base64 encoding:

| Field | Size | Type | Description |
| :--- | :--- | :--- | :--- |
| **Magic Bytes** | 2 Bytes | ASCII (`"EC"`) | Protocol identification header. |
| **Version** | 1 Byte | Unsigned Char (`1`) | Protocol version. |
| **Timestamp** | 8 Bytes | Unsigned Long (`!Q`) | Unix timestamp in seconds. |
| **Nonce** | 12 Bytes | Raw Bytes | Cryptographically secure random 96-bit GCM nonce. |
| **Ciphertext + Tag** | Variable | Raw Bytes | AES-256-GCM ciphertext followed by the 16-byte authentication tag. |

The complete packet structure:

```text
+----------+---------+-----------+-------------+-------------------+
| Magic    | Version | Timestamp | Nonce       | Ciphertext + Tag  |
| 2 bytes  | 1 byte  | 8 bytes   | 12 bytes    | variable          |
+----------+---------+-----------+-------------+-------------------+
```

The binary packet is then encoded using URL-safe Base64 for transport.

---

## Installation

Ensure you have Python 3.10+ and the core cryptographic library installed:

```bash
pip install cryptography
```

---

## Quick Start

EBEC sessions begin by establishing a shared root secret through the ephemeral X25519 key exchange, specifying connection roles.

```python
from engine import EphemeralCryptoEngine
from kex import EphemeralKeyExchange

# 1. Generate ephemeral X25519 state with explicit roles.
alice_kex = EphemeralKeyExchange(role="initiator")
bob_kex = EphemeralKeyExchange(role="responder")

# 2. Exchange ephemeral public keys over the transport.
alice_pub = alice_kex.get_public_bytes()
bob_pub = bob_kex.get_public_bytes()

# 3. Derive session outputs (root secret, session ID, SAS) on both sides.
alice_res = alice_kex.derive_session(bob_pub)
bob_res = bob_kex.derive_session(alice_pub)

# 4. Compare the SAS through an independent trusted channel.
# Example:
#   Alice SAS: 4A8F2C9B1E03
#   Bob SAS:   4A8F2C9B1E03
if alice_res.sas != bob_res.sas:
    raise RuntimeError("Key exchange authentication failed")

# Print Derived Session ID
print("Session ID:", alice_res.session_id.hex())

# 5. Initialize the encryption engines.
alice_engine = EphemeralCryptoEngine(alice_res.root_secret)
bob_engine = EphemeralCryptoEngine(bob_res.root_secret)

# 6. Encrypt on Alice's side.
packet = alice_engine.encrypt("Secure transmission payload")
print("Encoded Packet:", packet)

# 7. Decrypt on Bob's side.
timestamp, plaintext_bytes = bob_engine.decrypt(packet)
print(
    f"Decryption successful at Unix time {timestamp}: "
    f"{plaintext_bytes.decode('utf-8')}"
)
```

> **Note:** The SAS comparison is an essential part of the authenticated key-exchange process. If the public-key exchange occurs over an untrusted network, the SAS must be compared through an independent trusted channel such as an in-person comparison, voice call, or another already-authenticated channel.

---

## Architecture

EBEC consists of two primary layers:

```text
                    EBEC
                     │
          ┌──────────┴──────────┐
          │                     │
     Key Exchange          Crypto Engine
          │                     │
       X25519               AES-256-GCM
          │                     │
     HKDF-SHA256            Epoch keys
          │                     │
     Root Secret          Replay protection
          │                     │
     SAS & Session ID      Freshness checks
```

### 1. Ephemeral Key Exchange (`kex.py`)

`kex.py` establishes the shared session root secret, session ID, and SAS string.

```text
Alice ephemeral private key
              +
Bob ephemeral public key
              │
              ▼
     X25519 ECDH Exchange
              │
              ▼
   Shared DH Secret Check
  (Rejects weak / all-zero)
              │
              ▼
    Canonical Transcript
 (Initiator Pub + Responder Pub)
              │
              ▼
         HKDF-SHA256
              │
              ├──────────────► Root Secret      (ebec-kex-root-v1)
              │
              ├──────────────► Session ID       (ebec-session-id-v1)
              │
              └──────────────► SAS Key          (ebec-kex-sas-v1)
                                    │
                                    ▼
                         HMAC-SHA256 transcript
                                    │
                                    ▼
                               48-bit SAS
```

Both parties independently derive the exact same root secret, session ID, and SAS.

### 2. Transcript-Bound SAS & Session ID

The transcript is constructed strictly based on protocol role (`initiator` vs `responder`), ensuring that both peers generate identical transcript byte representations regardless of execution timing:

```text
PROTOCOL_VERSION ("EBEC-KEX-v1")
        +
Initiator Public Key (32 bytes)
        +
Responder Public Key (32 bytes)
        │
        ▼
   Transcript
```

Key material is derived from `master_secret` using explicit HKDF domain separation context labels:

* Root Secret: `ebec-kex-root-v1`
* Session ID: `ebec-session-id-v1`
* SAS Key: `ebec-kex-sas-v1`

---

## Epoch Key Derivation

After the root secret has been authenticated, `EphemeralCryptoEngine` derives an AES-256-GCM key for each timestamp epoch.

The default epoch duration is 60 seconds:

```python
EPOCH_SECONDS = 60
```

The epoch number is calculated as:

```python
epoch = timestamp // 60
```

The epoch number is public and is used as HKDF salt material:

```text
                 Root Secret
                      │
                      ▼
                 HKDF-SHA256
                      │
                 epoch number
                      │
                      ▼
                  AES-256 key
                      │
                      ▼
                   AES-GCM
```

Each epoch therefore has its own encryption key. Knowledge of one individual epoch key does not directly reveal the root secret or allow direct calculation of another epoch key.

---

## Replay & Freshness Protection

Incoming packets are checked for timestamp validity before decryption.

Default values:

```python
MAX_FUTURE_SKEW = 30
MAX_PACKET_AGE = 300
MAX_REPLAY_CACHE = 10_000
```

This means:

* Packets more than 5 minutes old are rejected.
* Packets more than 30 seconds in the future are rejected.
* Previously accepted packet bytes are tracked in an in-memory replay cache.

The replay cache is bounded to prevent unbounded memory growth. Replay detection is therefore limited to the configured freshness window and retained replay state.

---

## API Reference

### Key Exchange API (`kex.py`)

#### `KexResult` Dataclass
Immutable dataclass holding the outcome of a completed key exchange:
* `root_secret`: `bytes` (32 bytes)
* `session_id`: `bytes` (16 bytes)
* `sas`: `str` (12-character uppercase hex string)

#### `EphemeralKeyExchange(role: str)`
Initializes a single-use X25519 key exchange state.
* **Parameters:** `role` - Must be either `'initiator'` or `'responder'`.
* **`get_public_bytes() -> bytes`**
  Returns the local 32-byte raw X25519 public key.
* **`derive_session(peer_public_bytes: bytes) -> KexResult`**
  Completes key agreement given the peer's 32-byte public key. Performs reflection checks, validates shared secret strength, constructs the transcript, and returns a `KexResult`. Raises `RuntimeError` if invoked more than once.
* **`derive_root_secret(peer_public_bytes: bytes) -> tuple[bytes, str]`** *(Legacy Helper)*
  Returns `(root_secret, sas)`.

---

### Crypto Engine API (`engine.py`)

Exposes `EphemeralCryptoEngine(root_secret)`:

* **Generate a random root secret:**
  ```python
  root_secret = EphemeralCryptoEngine.generate_root_secret()
  ```
  *Returns 32 bytes of cryptographically secure random material.*

* **Encrypt:**
  ```python
  packet = engine.encrypt("Secure message")
  ```
  *Accepts either `str` or `bytes` and returns a URL-safe Base64 encoded packet.*

* **Decrypt:**
  ```python
  timestamp, plaintext = engine.decrypt(packet)
  ```
  *Returns `timestamp` (Unix timestamp) and `plaintext` (`bytes`). Malformed, expired, future-dated, unauthenticated, or replayed packets are rejected.*

---

## Threat Model

### EBEC is designed to protect against:

* Passive network interception.
* Passive observation of the X25519 public-key exchange.
* Self-reflection attacks during key exchange.
* All-zero / low-order point key agreement vulnerabilities.
* Key exchange instance reuse.
* Modification of authenticated packet contents or metadata.
* Straightforward packet replay within the configured replay window.
* Active key substitution when the SAS is correctly verified out-of-band.

### EBEC does NOT protect against:

* Compromise of an endpoint or theft of session state / plaintext.
* A compromised trusted SAS-verification channel.
* Traffic analysis (packet sizing, timing, routing).
* Root-secret compromise followed by derivation of historical epoch keys.

---

## License

This project is open source software licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for details.
