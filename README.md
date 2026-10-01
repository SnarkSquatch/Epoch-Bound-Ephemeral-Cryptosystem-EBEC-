# Epoch Bound Ephemeral Cipher (EBEC)

A lightweight cryptographic engine for authenticated ephemeral data transmission, designed so relay and storage infrastructure does not possess the keys required to decrypt payloads.

> **Disclaimer:** EBEC is a custom cryptographic protocol. It should undergo independent security review and testing before being used for high-value or safety-critical applications.

EBEC uses an ephemeral X25519 key exchange to establish a shared session root secret, then derives rotating per-epoch symmetric encryption keys on demand. No static key rings or certificate authorities are required, but note that EBEC does not provide inherent identity authentication—peer authentication relies entirely on the out-of-band SAS verification.

---

## Core Features

* **Ephemeral Key Exchange:** Uses ephemeral-ephemeral X25519 ECDH to establish a shared session root secret without transmitting the secret itself.
* **Role-Bound Canonical Transcripts:** Explicitly requires `initiator` and `responder` roles during key exchange to construct length-prefixed, role-independent canonical transcripts.
* **Transcript-Bound SAS:** Derives a 48-bit (12-character hex) Short Authentication String (SAS) using HMAC-SHA256 over the canonical transcript. Comparing the SAS through an independent trusted channel allows both parties to verify that they derived the same authenticated session material, providing protection against active man-in-the-middle attacks when the comparison channel is trusted.
* **128-Bit Session ID Derivation:** Automatically derives a 128-bit collision-resistant session identifier, deterministically derived from the session transcript alongside the root secret and SAS, to bind packets strictly to the session context.
* **Active Security Defenses:** Built-in protection against self-reflection attacks, all-zero shared-secret generation, invalid X25519 peer keys, and instance reuse.
* **Automatic Epoch & Directional Key Derivation:** AES-256-GCM encryption keys rotate every 60 seconds and are derived on demand from the session root secret using public-derived context (session ID, epoch number, and explicit direction flag) via HKDF-SHA256.
* **Authenticated Encryption:** AES-256-GCM provides confidentiality and integrity for every packet, binding header metadata (magic bytes, version, direction, session ID, timestamp) as Additional Authenticated Data (AAD).
* **Server-Blind Payloads:** Relay and storage layers do not possess the session root secret and therefore cannot decrypt payload contents.
* **Strict Replay and Freshness Defense:** Timestamp validation, future-skew enforcement (30s), maximum packet age enforcement (300s), and a bounded SHA-256 in-memory replay cache keyed by the entire packet hash prevent stale and replayed packets.
* **Language-Agnostic Wire Format:** Packets use a strict binary layout and URL-safe Base64 encoding for compatibility with Python, Rust, C, Go, and other environments.
* **No Persistent Identity Keys:** Ephemeral X25519 private keys are generated in memory and enforced as single-use instances. 

---

## Security Model

### EBEC is designed to provide:

* Confidentiality of encrypted payloads from intermediaries that do not possess the session root secret.
* Integrity and authentication of packet contents and header metadata (including session ID, direction, and timestamp) through AES-256-GCM.
* Ephemeral session establishment using X25519 with single-use session enforcement.
* Peer authentication through an independently verified SAS.
* Explicit reflection-attack protection, all-zero shared-secret rejection, and X25519 invalid-key handling.
* Key separation between transmission directions (`initiator` vs `responder`) and per-epoch key separation.
* Packet freshness and replay detection within the configured acceptance window.

### EBEC does NOT currently provide:

* Forward secrecy after compromise of the session root secret. Because epoch keys are derived from the same root secret, possession of that root secret permits derivation of all past and future epoch keys.
* Protection of transport metadata such as total packet size, timing, routing information, or externally visible timestamps.
* Peer authentication or identity continuity if the SAS is not independently verified out-of-band. (X25519 alone does not authenticate identities).
* Protection against a compromised endpoint whose session root secret or plaintext is exposed.
* Automatic synchronization of newly generated root secrets between peers.

*For applications requiring forward secrecy after session-root compromise, an evolving key schedule or ratcheting protocol is required.*

---

## Binary Packet Layout

All transmitted payloads adhere to the following binary header and payload layout before URL-safe Base64 encoding:

| Field | Size | Struct Type | Description |
| :--- | :--- | :--- | :--- |
| **Magic Bytes** | 2 Bytes | `2s` ASCII (`"EC"`) | Protocol identification header. |
| **Version** | 1 Byte | `B` Unsigned Char (`1`) | Protocol version. |
| **Direction** | 1 Byte | `B` Unsigned Char | `0x01` (Initiator $\rightarrow$ Responder) or `0x02` (Responder $\rightarrow$ Initiator). |
| **Session ID** | 16 Bytes | `16s` Raw Bytes | 128-bit derived session identifier. |
| **Timestamp** | 8 Bytes | `!Q` Unsigned Long Long | Big-endian Unix timestamp in seconds. |
| **Nonce** | 12 Bytes | Raw Bytes | Cryptographically secure random 96-bit GCM nonce. |
| **Ciphertext + Tag** | Variable | Raw Bytes | AES-256-GCM ciphertext followed by the 16-byte authentication tag. |

The complete packet structure:

```text
+----------+---------+-----------+--------------------+-------------------+--------------+-------------------+
| Magic    | Version | Direction | Session ID         | Timestamp         | Nonce        | Ciphertext + Tag  |
| 2 bytes  | 1 byte  | 1 byte    | 16 bytes           | 8 bytes           | 12 bytes     | variable          |
+----------+---------+-----------+--------------------+-------------------+--------------+-------------------+
| <----------------------- Header / AAD (28 bytes) ---------------------> |

```

The entire binary packet is encoded using URL-safe Base64 (`base64.urlsafe_b64encode`) for transport.

---

## Installation

Ensure you have Python 3.10+ and the core cryptographic library installed:

```bash
pip install cryptography

```

---

## Quick Start

EBEC sessions begin by establishing a shared root secret and session ID through the ephemeral X25519 key exchange, specifying connection roles.

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

print("Session ID:", alice_res.session_id.hex())

# 5. Initialize the encryption engines using the helper constructor.
alice_engine = EphemeralCryptoEngine.from_kex_result(alice_res, role="initiator")
bob_engine = EphemeralCryptoEngine.from_kex_result(bob_res, role="responder")

# 6. Encrypt on Alice's side (Initiator -> Responder).
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
      (kex.py)              (engine.py)
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
(Rejects all-zero / low-order points)
              │
              ▼
 Length-Prefixed Canonical Transcript
 (Protocol + Initiator Pub + Responder Pub)
              │
              ▼
         HKDF-SHA256
              │
              ├──────────────► Master Secret    (ebec-kex-master-v1)
              │                     │
              │                     ├────────► Root Secret    (ebec-kex-root-v1)
              │                     │
              │                     ├────────► Session ID     (ebec-session-id-v1)
              │                     │
              │                     └────────► SAS Key        (ebec-kex-sas-v1)
              │                                   │
              └───────────────────────────────────┴──► HMAC-SHA256
                                                            │
                                                            ▼
                                                       48-bit SAS (Hex)

```

Both parties independently derive the exact same root secret, session ID, and SAS.

### 2. Length-Prefixed Canonical Transcript

The transcript is constructed with 4-byte big-endian length prefixes (`struct.pack("!I", len(val))`) strictly based on protocol role (`initiator` vs `responder`), ensuring identical byte representations:

```text
!I len(PROTOCOL_VERSION) + PROTOCOL_VERSION ("EBEC-KEX-v1")
        +
!I len(Initiator Public Key) + Initiator Public Key (32 bytes)
        +
!I len(Responder Public Key) + Responder Public Key (32 bytes)

```

Key material derivation chain:

1. `raw_shared_secret` and `sha256(transcript)` derive `master_secret` via HKDF (`ebec-kex-master-v1`).
2. `master_secret` expands into:
* **Root Secret (32 bytes):** HKDF info `ebec-kex-root-v1`
* **Session ID (16 bytes):** HKDF info `ebec-session-id-v1`
* **SAS Key (32 bytes):** HKDF info `ebec-kex-sas-v1`


3. `sas` is the first 6 bytes (48 bits) of `HMAC-SHA256(sas_key, transcript)` formatted as uppercase hex.

---

## Epoch & Directional Key Derivation

After the root secret has been authenticated, `EphemeralCryptoEngine` derives an AES-256-GCM key on demand for each timestamp epoch and transmission direction.

The default epoch duration is 60 seconds:

```python
EPOCH_SECONDS = 60

```

The epoch number is calculated as:

```python
epoch = timestamp // 60

```

To provide strict key separation between directions and epochs, a **public-derived salt** is constructed using a SHA-256 digest:

$$\text{salt} = \text{SHA-256}(\text{session\_id} \parallel \text{direction\_byte} \parallel \text{struct.pack}("!\text{Q}", \text{epoch}))$$

The key is derived using HKDF-SHA256, where the cryptographic security relies entirely on the `root_secret` functioning as the Input Key Material (IKM):

```text
                Root Secret (IKM)
                       │
                       ▼
            HKDF-SHA256 (ebec-epoch-aead-v1)
                       │
             Public-Derived Salt
                       │
                       ▼
                 AES-256-GCM Key

```

As a property of the KDF construction, knowledge of one individual epoch key does not allow derivation of keys for other epochs or opposite transmission directions. However, compromise of the `root_secret` permits derivation of all past and future epoch keys for that session.

---

## Replay & Freshness Protection

Incoming packets undergo strict verification prior to decryption:

* **Session Validation:** Packet `session_id` must match the engine's derived `session_id`.
* **Direction Validation:** Packet direction byte must match the expected incoming direction (`0x02` for initiator, `0x01` for responder).
* **Payload Size Validation:** Decoded payload must not exceed `MAX_PAYLOAD_SIZE` (1 MiB).
* **Timestamp Checks:**
* Packets older than `MAX_PACKET_AGE` (300 seconds / 5 minutes) are rejected.
* Packets further in the future than `MAX_FUTURE_SKEW` (30 seconds) are rejected.


* **Replay Prevention:** A SHA-256 digest of the *entire decoded binary packet* is stored in a bounded `OrderedDict` (`MAX_REPLAY_CACHE = 10_000`). Because the randomly generated 96-bit nonce is included in this hash, two separate encryptions of the exact same plaintext will normally produce different nonces and therefore different packet hashes. Re-encountering an identical packet causes an immediate rejection.

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

* **Parameters:** `role` – Must be either `'initiator'` or `'responder'`.
* **`get_public_bytes() -> bytes`**
Returns the local 32-byte raw X25519 public key.
* **`derive_session(peer_public_bytes: bytes) -> KexResult`**
Completes key agreement given the peer's 32-byte public key. Performs reflection checks, validates shared secret strength against all-zero/low-order points, constructs the transcript, and returns a `KexResult`. Raises `RuntimeError` if invoked more than once.

#### Legacy Helpers

* **`derive_root_secret(peer_public_bytes: bytes) -> tuple[bytes, str]`**
*Legacy API:* Retained for backward compatibility. Completes key agreement and returns `(root_secret, sas)`. New implementations should use `derive_session()`.

---

### Crypto Engine API (`engine.py`)

#### `EphemeralCryptoEngine(session_id: bytes, root_secret: bytes, direction: int)`

Constructs an authenticated encryption engine instance.

#### Class Methods

* **`from_kex_result(kex_result, role: str) -> EphemeralCryptoEngine`**
Instantiates the engine directly from a `KexResult` object and the local peer's role (`"initiator"` or `"responder"`). Automatically configures send and receive directions.
* **`generate_root_secret() -> bytes`**
Generates a cryptographically secure random 32-byte secret (for standalone or testing uses).

#### Instance Methods

* **`encrypt(payload: str | bytes, timestamp: int | None = None) -> str`**
Encrypts a payload and returns a URL-safe Base64 encoded packet string. The header is bound as AEAD Additional Authenticated Data.
* **`decrypt(encoded_packet: str) -> tuple[int, bytes]`**
Decrypts and authenticates an incoming packet string. Returns `(timestamp, plaintext_bytes)`. Validates format, length, header values, session ID, direction, timestamp freshness, and replay cache.

---

## Threat Model

### EBEC is designed to protect against:

* Passive network interception.
* Passive observation of the X25519 public-key exchange.
* Self-reflection attacks during key exchange.
* All-zero shared-secret generation and invalid X25519 peer-key handling.
* Key exchange instance reuse (single-use enforcement).
* Modification of authenticated packet contents or header metadata (including direction, timestamp, and session ID).
* Packet replay within the configured replay window.
* Active key substitution / Man-in-the-Middle attacks when the SAS is correctly verified out-of-band.

### EBEC does NOT protect against:

* Compromise of an endpoint or theft of session state / plaintext.
* A compromised trusted SAS-verification channel.
* Traffic analysis (packet sizing, timing, routing).
* Root-secret compromise followed by derivation of historical epoch keys.

---

## License

This project is open source software licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for details.

```

```
