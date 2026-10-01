from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class KexResult:
    """
    Immutable result of a completed EBEC X25519 key exchange.
    """

    root_secret: bytes
    session_id: bytes
    sas: str


class EphemeralKeyExchange:
    """
    Ephemeral X25519 key exchange for EBEC.

    Features:
    - Ephemeral-Ephemeral X25519 ECDH key agreement
    - Single-use session enforcement per keypair
    - Domain-separated HKDF-SHA256 key derivation
    - Role-independent canonical transcript binding
    - Short Authentication String (SAS) generation for out-of-band verification
    - 128-bit session ID derivation
    - Reflection and weak shared secret defense checks
    """

    PROTOCOL_VERSION = b"EBEC-KEX-v1"

    MASTER_INFO = b"ebec-kex-master-v1"
    ROOT_INFO = b"ebec-kex-root-v1"
    SAS_INFO = b"ebec-kex-sas-v1"
    SESSION_ID_INFO = b"ebec-session-id-v1"

    SAS_LENGTH_BYTES = 6
    SESSION_ID_LENGTH = 16
    KEY_LENGTH = 32

    def __init__(self, role: str):
        """
        Initialize a single-use X25519 key exchange state.

        Args:
            role: Must be 'initiator' or 'responder'.
        """
        if role not in ("initiator", "responder"):
            raise ValueError("role must be either 'initiator' or 'responder'")

        self.role = role
        self._private_key = x25519.X25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._session_derived = False

    def get_public_bytes(self) -> bytes:
        """
        Export local 32-byte raw X25519 public key.
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def _length_prefix(value: bytes) -> bytes:
        return struct.pack("!I", len(value)) + value

    @classmethod
    def _build_transcript(
        cls,
        initiator_public_bytes: bytes,
        responder_public_bytes: bytes,
    ) -> bytes:
        """
        Build the canonical length-prefixed protocol transcript.
        """
        return (
            cls._length_prefix(cls.PROTOCOL_VERSION)
            + cls._length_prefix(initiator_public_bytes)
            + cls._length_prefix(responder_public_bytes)
        )

    @staticmethod
    def _hkdf(
        *,
        ikm: bytes,
        info: bytes,
        length: int,
        salt: bytes | None = None,
    ) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        ).derive(ikm)

    def derive_session(self, peer_public_bytes: bytes) -> KexResult:
        """
        Complete key agreement given the peer's 32-byte public key.

        Returns:
            KexResult containing root_secret, session_id, and SAS string.
        """
        if self._session_derived:
            raise RuntimeError(
                "this ephemeral key exchange instance has already been used"
            )

        if not isinstance(peer_public_bytes, bytes):
            raise TypeError("peer_public_bytes must be bytes")

        if len(peer_public_bytes) != self.KEY_LENGTH:
            raise ValueError(
                f"X25519 public key must be exactly {self.KEY_LENGTH} bytes"
            )

        my_public_bytes = self.get_public_bytes()

        # Block self-reflection attacks
        if hmac.compare_digest(peer_public_bytes, my_public_bytes):
            raise ValueError(
                "reflection attack detected: peer public key matches local public key"
            )

        try:
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(
                peer_public_bytes
            )
            raw_shared_secret = self._private_key.exchange(peer_public_key)
        except (ValueError, InvalidKey) as exc:
            raise ValueError(f"X25519 key exchange failed: {exc}") from exc

        # Reject low-order points yielding all-zero secrets
        if hmac.compare_digest(raw_shared_secret, b"\x00" * self.KEY_LENGTH):
            raise ValueError("invalid or weak X25519 shared secret generated")

        # Canonical transcript ordering based on session roles
        if self.role == "initiator":
            initiator_public_bytes = my_public_bytes
            responder_public_bytes = peer_public_bytes
        else:
            initiator_public_bytes = peer_public_bytes
            responder_public_bytes = my_public_bytes

        transcript = self._build_transcript(
            initiator_public_bytes,
            responder_public_bytes,
        )

        transcript_hash = hashlib.sha256(transcript).digest()

        # HKDF Secret Derivation Chain
        master_secret = self._hkdf(
            ikm=raw_shared_secret,
            salt=transcript_hash,
            info=self.MASTER_INFO,
            length=self.KEY_LENGTH,
        )

        root_secret = self._hkdf(
            ikm=master_secret,
            info=self.ROOT_INFO,
            length=self.KEY_LENGTH,
        )

        session_id = self._hkdf(
            ikm=master_secret,
            info=self.SESSION_ID_INFO,
            length=self.SESSION_ID_LENGTH,
        )

        sas_key = self._hkdf(
            ikm=master_secret,
            info=self.SAS_INFO,
            length=self.KEY_LENGTH,
        )

        sas_mac = hmac.new(
            sas_key,
            transcript,
            hashlib.sha256,
        ).digest()

        sas = sas_mac[: self.SAS_LENGTH_BYTES].hex().upper()

        self._session_derived = True

        return KexResult(
            root_secret=root_secret,
            session_id=session_id,
            sas=sas,
        )

    def derive_root_secret(
        self, peer_public_bytes: bytes
    ) -> tuple[bytes, str]:
        """
        Legacy helper returning (root_secret, sas).
        """
        result = self.derive_session(peer_public_bytes)
        return result.root_secret, result.sas
