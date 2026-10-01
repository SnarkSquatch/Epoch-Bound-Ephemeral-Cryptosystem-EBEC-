import hashlib
import hmac
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class EphemeralKeyExchange:
    """
    EBEC ephemeral X25519 key exchange.

    Provides:
      - Ephemeral X25519 ECDH
      - HKDF-SHA256 root-secret derivation
      - Transcript-bound SAS derivation
      - 48-bit (12 hex character) SAS
      - Domain separation between root-key and SAS derivation

    IMPORTANT:
      The SAS must be compared through an independent/authenticated
      out-of-band channel. Matching SAS values authenticate the key
      exchange; merely displaying or transmitting the SAS over the
      same untrusted channel does not.
    """

    PROTOCOL_VERSION = b"EBEC-KEX-v1"

    ROOT_INFO = b"ebec-kex-root-v1"
    SAS_INFO = b"ebec-kex-sas-v1"

    SAS_BYTES = 6  # 48-bit SAS

    def __init__(self):
        # Fresh ephemeral X25519 key pair.
        self._private_key = x25519.X25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    def get_public_bytes(self) -> bytes:
        """Return the 32-byte raw X25519 public key."""
        from cryptography.hazmat.primitives import serialization

        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def _build_transcript(
        my_public: bytes,
        peer_public: bytes,
    ) -> bytes:
        """
        Build a canonical transcript.

        Sorting the public keys ensures Alice and Bob construct
        exactly the same transcript regardless of who generated
        which key.

        Length-prefixing prevents ambiguous concatenation.
        """
        first, second = sorted((my_public, peer_public))

        return (
            EphemeralKeyExchange.PROTOCOL_VERSION
            + struct.pack("!H", len(first))
            + first
            + struct.pack("!H", len(second))
            + second
        )

    @staticmethod
    def _derive_key(
        shared_secret: bytes,
        *,
        info: bytes,
    ) -> bytes:
        """Derive independent 256-bit key material using HKDF-SHA256."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        ).derive(shared_secret)

    def derive_root_secret(
        self,
        peer_public_bytes: bytes,
    ) -> tuple[bytes, str]:
        """
        Perform X25519 ECDH and derive:

          1. A 32-byte root secret for EBEC encryption.
          2. A 48-bit transcript-bound SAS for out-of-band verification.

        Both parties must independently compare the SAS over a trusted
        channel before accepting the resulting root secret.
        """

        if not isinstance(peer_public_bytes, bytes):
            raise TypeError("peer_public_bytes must be bytes")

        if len(peer_public_bytes) != 32:
            raise ValueError(
                "X25519 public key must be exactly 32 bytes"
            )

        peer_public_key = x25519.X25519PublicKey.from_public_bytes(
            peer_public_bytes
        )

        # X25519 ECDH.
        raw_shared_secret = self._private_key.exchange(
            peer_public_key
        )

        # Derive encryption/session root material.
        root_secret = self._derive_key(
            raw_shared_secret,
            info=self.ROOT_INFO,
        )

        # Build canonical transcript from the two ephemeral public keys.
        my_public = self.get_public_bytes()

        transcript = self._build_transcript(
            my_public,
            peer_public_bytes,
        )

        # Derive independent SAS key material from the ECDH secret.
        sas_key = self._derive_key(
            raw_shared_secret,
            info=self.SAS_INFO,
        )

        # Authenticate the complete protocol transcript.
        #
        # HMAC is used rather than an unkeyed hash so that the SAS
        # demonstrates knowledge of the X25519 shared secret as well
        # as agreement on the public-key transcript.
        sas_mac = hmac.new(
            sas_key,
            transcript,
            hashlib.sha256,
        ).digest()

        # 6 bytes = 48 bits = 12 hexadecimal characters.
        sas_fingerprint = sas_mac[:self.SAS_BYTES].hex().upper()

        return root_secret, sas_fingerprint
