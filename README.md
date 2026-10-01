# Epoch Bound Ephemeral Cryptosystem (EBEC)

A lightweight, zero knowledge, server blind cryptographic engine designed for ephemeral data transmission. 

It eliminates static key rings, long term identity exposure, and single points of failure by deriving per epoch symmetric keys
on the fly from a shared, previously negotiated root secret. 

---

## Core Features

* **Automatic Key Rotation:** No PGP Key rings, no certificate authorities, and no long term identity keys sitting on disk.
* **Forward Secrecy via Epoch Rotation:** Keys rotate automatically every 60 seconds. Compromising a key yields zero insight
  into past or future epochs.
* **Server Blind Storage:** Intermediary transport layers (mail queues, WebSockets, or relay nodes) handle purely opaque
  cyphertext and metadata bound packets.
* **Strict Replay and Skew Defense:** Freshness checks, skew enforcement, and a bounded in memory replay cache.
* **Language Agnostic Wire Format:** Strict binary layout and URL safe Base64 encoded for safe transit across legacy network daemons.

---

## Binary Packet Layout

To ensure portability across Python, Rust, C, or Go, all transmitted payloads adhere to this strict binary layout before Base64
encoding:

| Field | Size | Type | Description |
| :--- | :--- | :--- | :--- |
| **Magic Bytes** | 2 Bytes | ASCII (`"EC"`) | Protocol identification header. |
| **Version** | 1 Byte | Unsigned Char (`1`) | Protocol version for backward-compatibility. |
| **Timestamp** | 8 Bytes | Unsigned Long (`!Q`) | Unix epoch timestamp in seconds. |
| **Nonce** | 12 Bytes | Raw Bytes | Cryptographically secure random 96-bit vector (`secrets.token_bytes`). |
| **Cyphertext + Tag** | Variable | Raw Bytes | AES-256-GCM encrypted payload concatenated with the 16-byte authentication tag. |

---

## Installation

Ensure you have Python 3.10+ and the core cryptographic library installed:

```bash
pip install cryptography
```
## Quick Start

```python

import os
from engine import EphemeralCryptoEngine

# Establish random root secret via out of band p2p handshake
root_secret = EphemeralCryptoEngine.generate_root_secret()

# Start on both sides
engine = EphemeralCryptoEngine(root_secret)

# Encrypt arbitrary payload (string or bytes)
packet = engine.encrypt("Secure transmission payload")
print("Encoded Packet:", packet)

# Decrypt and validate
timestamp, plaintext_bytes = engine.decrypt(packet)
print(f"Decryption successful at Unix time {timestamp}: {plaintext_bytes.decode('utf-8')}")
```

## Architecture

1. Key Derivation (HKDF-SHA256): Per epoch AES-256 keys derived using HKDF-SHA256 where salt is public epoch integer (timestamp // 60)
and info parameter provides strict domain separation.

2. Associated Data (AAD) Binding: Binary header (magic + version + timestamp) is bound directly to AESGCM tag. Tampering with headers
in transit instantly invalidates the authentication tag.

3. Replay Mitigation: Incoming packets are hashed via SHA-256(packet) and checked against a size capped OrderedDict replay cache,
pruned for age expiration (Max_Packet_Age = 300s).

## License

This project is open source software licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) for
details.   
