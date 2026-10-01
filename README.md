# Epoch Bound Ephemeral Cipher (EBEC)

A lightweight cryptographic engine for authenticated ephemeral data transmission, designed so relay and storage infrastructure does not possess the keys required to decrypt payloads.

> **Disclaimer:** EBEC is a custom cryptographic protocol. It should undergo independent security review and testing before being used for high-value or safety-critical applications.

EBEC uses an ephemeral X25519 key exchange to establish a shared session root secret, then derives rotating per-epoch symmetric encryption keys on demand. No static key rings, certificate authorities, or persistent identity keys are required.

---

## Core Features

* **Ephemeral Key Exchange:** Uses ephemeral X25519 ECDH to establish a shared session root secret without transmitting the secret itself.
* **Transcript-Bound SAS:** Derives a 48-bit Short Authentication String (SAS) from the X25519 shared secret and both ephemeral public keys. Comparing the SAS through an independent trusted channel provides protection against active man-in-the-middle attacks.
* **Automatic Epoch Key Derivation:** Encryption keys rotate every 60 seconds and are derived on demand from the session root secret using HKDF-SHA256.
* **Authenticated Encryption:** AES-256-GCM provides confidentiality and integrity for every packet.
* **Server-Blind Payloads:** Relay and storage layers do not possess the session root secret and therefore cannot decrypt payload contents.
* **Strict Replay and Freshness Defense:** Timestamp validation, future-skew enforcement, and a bounded in-memory replay cache help prevent stale and replayed packets.
* **Language-Agnostic Wire Format:** Packets use a strict binary layout and URL-safe Base64 encoding for compatibility with Python, Rust, C, Go, and other environments.
* **No Persistent Identity Keys:** Ephemeral X25519 private keys are generated in memory and are not persisted by the KEX component.

---

## Security Model

### EBEC is designed to provide:

* Confidentiality of encrypted payloads from intermediaries that do not possess the session root secret.
* Integrity and authentication of packet contents through AES-256-GCM.
* Ephemeral session establishment using X25519.
* Peer authentication through an independently verified SAS.
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

EBEC sessions should begin by establishing a shared root secret through the ephemeral X25519 key exchange.

```python
from engine import EphemeralCryptoEngine
from kex import EphemeralKeyExchange

# 1. Generate ephemeral X25519 state on both sides.
alice_kex = EphemeralKeyExchange()
bob_kex = EphemeralKeyExchange()

# 2. Exchange ephemeral public keys over the transport.
alice_pub = alice_kex.get_public_bytes()
bob_pub = bob_kex.get_public_bytes()

# 3. Derive the session root secret and SAS on both sides.
alice_root, alice_sas = alice_kex.derive_root_secret(bob_pub)
bob_root, bob_sas = bob_kex.derive_root_secret(alice_pub)

# 4. Compare the SAS through an independent trusted channel.
# Example:
#   Alice: 4A8F2C9B1E03
#   Bob:   4A8F2C9B1E03
# Do not accept the session until the SAS values have been verified.
if alice_sas != bob_sas:
    raise RuntimeError("Key exchange authentication failed")

# 5. Initialize the encryption engines.
alice_engine = EphemeralCryptoEngine(alice_root)
bob_engine = EphemeralCryptoEngine(bob_root)

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
       HKDF-SHA256          Epoch keys
          │                     │
     Root Secret          Replay protection
          │                     │
     SAS verification      Freshness checks
```

### 1. Ephemeral Key Exchange (`kex.py`)

`kex.py` establishes the shared session root secret.

```text
Alice ephemeral private key
              +
Bob ephemeral public key
              │
              ▼
          X25519 ECDH
              │
              ▼
       Shared DH secret
              │
              ▼
          HKDF-SHA256
              │
              ├──────────────► Root secret
              │
              └──────────────► SAS key
                                  │
                                  ▼
                         HMAC-SHA256 transcript
                                  │
                                  ▼
                            48-bit SAS
```

Both parties independently derive the same root secret and SAS.

### 2. Transcript-Bound SAS

The SAS is derived from:

* EBEC KEX protocol version.
* Both ephemeral X25519 public keys.
* The X25519 shared secret.

The public keys are canonically sorted and length-prefixed before being included in the transcript:

```text
EBEC-KEX-v1
    +
Public Key A
    +
Public Key B
    │
    ▼
Transcript
    │
    ▼
HMAC-SHA256 using KEX-derived SAS key
    │
    ▼
48-bit / 12-character hexadecimal SAS
```

The transcript binding prevents the authentication value from being independent of the specific key exchange.

The SAS key and encryption root secret are derived independently using different HKDF info contexts:

* `ebec-kex-root-v1`
* `ebec-kex-sas-v1`

This provides domain separation between encryption key material and SAS authentication material.

### 3. SAS Verification

X25519 by itself does not authenticate the peer and is vulnerable to an active man-in-the-middle attack. EBEC addresses this by requiring both parties to compare the derived SAS through an independent trusted channel.

For example:

* **Alice:** `4A8F2C9B1E03`
* **Bob:** `4A8F2C9B1E03`

If the values match and the comparison is performed through an independent trusted channel, the parties have authenticated their key-exchange transcript and demonstrated agreement on the derived shared secret. If they do not match, the session must be aborted.

*The SAS must not simply be accepted from the same untrusted transport used to exchange the public keys.*

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

### Important Forward-Secrecy Limitation

Epoch rotation should not be confused with full forward secrecy. All epoch keys are ultimately derived from the same session root secret:

```text
Root Secret
   ├── Epoch N-1
   ├── Epoch N
   ├── Epoch N+1
   └── ...
```

Therefore, if an attacker obtains the root secret, they can derive both historical and future epoch keys. Applications requiring forward secrecy after compromise of session state should use an evolving key schedule or ratcheting construction.

---

## AES-256-GCM Encryption

EBEC uses AES-256-GCM for authenticated encryption. Each packet receives a fresh 96-bit random nonce:

```python
nonce = secrets.token_bytes(12)
```

The packet header is supplied as AES-GCM associated authenticated data (AAD):

```python
ciphertext = aesgcm.encrypt(
    nonce,
    payload_bytes,
    header,
)
```

This means the following fields are authenticated:

* Magic
* Version
* Timestamp

An attacker cannot modify these fields without causing GCM authentication to fail. The nonce is transmitted in plaintext because GCM nonces do not need to be secret.

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

*Timestamp validation does not prove when a packet was originally created. The timestamp is authenticated as packet metadata, but a holder of the encryption key can construct a packet containing a chosen valid timestamp.*

---

## Server-Blind Payloads

EBEC is designed so that relay and storage infrastructure does not possess the session root secret. A transport server can forward or store Base64 packets without possessing the key necessary to decrypt its payload.

However, EBEC does not hide all transport metadata. Depending on the surrounding application and transport, intermediaries may still observe:

* Packet size.
* Transmission timing.
* Routing information.
* The authenticated packet timestamp.
* Connection metadata.

*EBEC provides payload confidentiality, not traffic-analysis resistance.*

---

## Application-Layer Root Secret Rotation

Applications with long-running sessions may periodically establish a new root secret. A new root secret must be securely communicated to the peer through a corresponding authenticated key-establishment mechanism.

Simply generating a new root secret locally does not synchronize it with the remote endpoint. For example:

```python
new_root_secret = EphemeralCryptoEngine.generate_root_secret()
```

This only creates local key material. The peer cannot decrypt packets using that secret until it has securely received or independently derived the same secret. Applications requiring seamless root rotation should maintain overlapping authenticated sessions during the transition.

---

## Wire Format Example

A packet consists of:

```text
EC
01
[timestamp: 8 bytes]
[nonce: 12 bytes]
[ciphertext + 16-byte GCM tag]
```

The complete binary structure is then URL-safe Base64 encoded. The format is intentionally independent of Python so that compatible implementations can be written in other languages.

---

## API Reference

### Key Exchange API (`kex.py`)

Exposes `EphemeralKeyExchange()`:

* **Generate a public key:**
  ```python
  public_key = kex.get_public_bytes()
  ```
  *Returns the 32-byte raw X25519 public key.*

* **Derive the session root and SAS:**
  ```python
  root_secret, sas = kex.derive_root_secret(peer_public_key)
  ```
  *Returns:*
  * `root_secret`: 32 bytes
  * `sas`: 12-character hexadecimal string

*The root secret should only be used after successful SAS verification.*

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
* Modification of authenticated packet contents.
* Modification of authenticated packet metadata.
* Straightforward packet replay within the configured replay window.
* Active key substitution when the SAS is correctly verified out-of-band.

### EBEC does NOT protect against:

* Compromise of an endpoint.
* Theft of the session root secret.
* Theft of plaintext before encryption or after decryption.
* A compromised trusted SAS-verification channel.
* Traffic analysis.
* Root-secret compromise followed by derivation of historical epoch keys.
* Malicious peers that legitimately possess the session encryption key.

---

## Security Considerations

EBEC relies on the security properties of:

* X25519
* HKDF-SHA256
* HMAC-SHA256
* AES-256-GCM
* Cryptographically secure random number generation provided by the Python `secrets` module and the underlying cryptographic library.

The security of the overall protocol also depends on correct key lifecycle management, secure endpoint storage, correct SAS verification, clock behavior, and safe handling of the resulting plaintext.

---

## License

This project is open source software licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for details.
