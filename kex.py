from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

@dataclass(frozen=True)
class KexResult:
    """
    Result of a completed X25519 key exchange.

    root_secret:
        32-byte session root secret.

    session_id:
        16-byte identifier derived from the authenticated KEX transcript.

    send_key:
        32-byte AES-256 key used for packets sent by this peer.

    receive_key:
        32-byte AES-256 key used for packets received by this peer.

    sas:
        12-character hexadecimal Short Authentication String.
    """

    root_secret: bytes
    session_id: bytes
    send_key: bytes
    receive_key: bytes
    sas: str


class EphemeralKeyExchange:
    """
    Ephemeral X25519 key exchange for EBEC.

    The exchange derives:

        - a 32-byte session root secret
        - a 16-byte session ID
        - independent A->B and B->A encryption keys
        - a transcript-bound 48-bit SAS

    The peer roles must be explicitly specified as either:

        "initiator"
        "responder"

    The initiator's send key is the responder's receive key, and
    the responder's send key is the initiator's receive key.
    """

    PROTOCOL_VERSION = b"EBEC-KEX-v1"

    ROOT_INFO = b"ebec-kex-root-v1"
    SAS_INFO = b"ebec-kex-sas-v1"
    SESSION_ID_INFO = b"ebec-session-id-v1"

    INITIATOR_TO_RESPONDER_INFO = b"ebec-a-to-b-v1"
    RESPONDER_TO_INITIATOR_INFO = b"ebec-b-to-a-v1"

    SAS_LENGTH_BYTES = 6
    SESSION_ID_LENGTH = 16
    KEY_LENGTH = 32

    def __init__(self, role: str):
        if role not in ("initiator", "responder"):
            raise ValueError(
                "role must be either 'initiator' or 'responder'"
            )

        self.role = role

        # Generate a fresh, ephemeral X25519 keypair.
        self._private_key = x25519.X25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    def get_public_bytes(self) -> bytes:
        """
        Return the 32-byte raw X25519 public key.

        This value is safe to transmit over an untrusted transport.
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def _length_prefix(value: bytes) -> bytes:
        """
        Encode a byte string using a 4-byte big-endian length prefix.
        """
        return struct.pack("!I", len(value)) + value

    @classmethod
    def _build_transcript(
        cls,
        initiator_public_bytes: bytes,
        responder_public_bytes: bytes,
    ) -> bytes:
        """
        Build the canonical KEX transcript.

        The role-specific ordering is intentional:

            protocol version
            initiator public key
            responder public key

        This ensures both sides construct exactly the same transcript.
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
        """
        HKDF-SHA256 helper.
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        ).derive(ikm)

    def derive_session(self, peer_public_bytes: bytes) -> KexResult:
        """
        Perform the X25519 exchange and derive the complete EBEC session.

        Returns:
            KexResult containing the root secret, session ID,
            direction-specific keys, and SAS.

        The caller must independently verify the SAS before using
        the resulting session for authenticated communication.
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

        my_public_bytes = self.get_public_bytes()

        # Determine the canonical initiator/responder public keys.
        if self.role == "initiator":
            initiator_public_bytes = my_public_bytes
            responder_public_bytes = peer_public_bytes
        else:
            initiator_public_bytes = peer_public_bytes
            responder_public_bytes = my_public_bytes

        # Build the exact same transcript on both peers.
        transcript = self._build_transcript(
            initiator_public_bytes,
            responder_public_bytes,
        )

        # Perform X25519 ECDH.
        raw_shared_secret = self._private_key.exchange(peer_public_key)

        # Extract a session master secret from the raw X25519 output.
        #
        # The transcript is used as HKDF salt/context material so that
        # the resulting session is cryptographically bound to these
        # particular ephemeral public keys.
        master_secret = self._hkdf(
            ikm=raw_shared_secret,
            salt=hashlib.sha256(transcript).digest(),
            info=b"ebec-kex-master-v1",
            length=32,
        )

        # Derive the root secret independently from the master secret.
        root_secret = self._hkdf(
            ikm=master_secret,
            info=self.ROOT_INFO,
            length=self.KEY_LENGTH,
        )

        # Derive a stable 128-bit identifier for this KEX session.
        session_id = self._hkdf(
            ikm=master_secret,
            info=self.SESSION_ID_INFO,
            length=self.SESSION_ID_LENGTH,
        )

        # Derive independent encryption keys for each direction.
        initiator_to_responder_key = self._hkdf(
            ikm=master_secret,
            info=self.INITIATOR_TO_RESPONDER_INFO,
            length=self.KEY_LENGTH,
        )

        responder_to_initiator_key = self._hkdf(
            ikm=master_secret,
            info=self.RESPONDER_TO_INITIATOR_INFO,
            length=self.KEY_LENGTH,
        )

        # Derive a separate key specifically for SAS authentication.
        sas_key = self._hkdf(
            ikm=master_secret,
            info=self.SAS_INFO,
            length=32,
        )

        # Authenticate the complete canonical transcript.
        #
        # HMAC is used here rather than directly hashing the public keys.
        # This means the SAS depends on both the transcript and the
        # authenticated shared secret.
        sas_mac = hmac.new(
            sas_key,
            transcript,
            hashlib.sha256,
        ).digest()

        # 6 bytes = 48 bits = 12 hexadecimal characters.
        sas = sas_mac[: self.SAS_LENGTH_BYTES].hex().upper()

        # Assign directional keys according to this peer's role.
        if self.role == "initiator":
            send_key = initiator_to_responder_key
            receive_key = responder_to_initiator_key
        else:
            send_key = responder_to_initiator_key
            receive_key = initiator_to_responder_key

        return KexResult(
            root_secret=root_secret,
            session_id=session_id,
            send_key=send_key,
            receive_key=receive_key,
            sas=sas,
        )

    def derive_root_secret(
        self,
        peer_public_bytes: bytes,
    ) -> tuple[bytes, str]:
        """
        Compatibility helper.

        Returns only:

            (root_secret, sas)

        New code should prefer derive_session(), which also provides
        session ID and direction-specific encryption keys.
        """
        result = self.derive_session(peer_public_bytes)

        return result.root_secret, result.sas
