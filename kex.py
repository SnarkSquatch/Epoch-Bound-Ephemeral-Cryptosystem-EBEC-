from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class KexResult:
    """
    Result of a completed EBEC X25519 key exchange.

    root_secret:
        32-byte session root secret.

    session_id:
        16-byte identifier derived from the authenticated KEX
        transcript.

    sas:
        12-character hexadecimal Short Authentication String.

    The root_secret is consumed by EphemeralCryptoEngine, which
    derives per-epoch directional AES-256-GCM keys from it.
    """

    root_secret: bytes
    session_id: bytes
    sas: str


class EphemeralKeyExchange:
    """
    Ephemeral X25519 key exchange for EBEC.

    The exchange derives:

        - a 32-byte session root secret
        - a 16-byte session ID
        - a transcript-bound 48-bit SAS

    Per-epoch encryption keys are deliberately NOT derived here.

    EphemeralCryptoEngine is responsible for deriving AES-256-GCM
    keys from:

        session root
        + session ID
        + direction
        + epoch number

    The peer roles must be explicitly specified as either:

        "initiator"
        "responder"
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
        if role not in ("initiator", "responder"):
            raise ValueError(
                "role must be either 'initiator' or 'responder'"
            )

        self.role = role

        # Generate a fresh ephemeral X25519 keypair.
        #
        # The private key exists only in memory and is never persisted
        # by this component.
        self._private_key = x25519.X25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

        # Prevent accidental reuse of the same ephemeral KEX object
        # for multiple independent sessions.
        self._session_derived = False

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

        The ordering is always:

            protocol version
            initiator public key
            responder public key

        Both peers therefore construct exactly the same transcript.
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

    def derive_session(
        self,
        peer_public_bytes: bytes,
    ) -> KexResult:
        """
        Perform the X25519 exchange and derive the complete EBEC
        session root.

        Returns:

            KexResult containing:

                root_secret
                session_id
                sas

        The caller MUST independently verify the SAS before using
        the resulting session for authenticated communication.
        """

        if self._session_derived:
            raise RuntimeError(
                "this ephemeral key exchange has already been used"
            )

        if not isinstance(peer_public_bytes, bytes):
            raise TypeError(
                "peer_public_bytes must be bytes"
            )

        if len(peer_public_bytes) != 32:
            raise ValueError(
                "X25519 public key must be exactly 32 bytes"
            )

        peer_public_key = x25519.X25519PublicKey.from_public_bytes(
            peer_public_bytes
        )

        my_public_bytes = self.get_public_bytes()

        # Determine canonical initiator/responder public keys.
        #
        # We intentionally use role-based ordering rather than sorting
        # the public keys. This makes the transcript explicitly bind
        # the identity of each ephemeral key to its protocol role.
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

        transcript_hash = hashlib.sha256(
            transcript
        ).digest()

        # Perform X25519 ECDH.
        raw_shared_secret = self._private_key.exchange(
            peer_public_key
        )

        # Reject an all-zero X25519 shared secret.
        #
        # cryptography's X25519 implementation normally handles the
        # relevant low-order-point behavior, but explicitly checking
        # the result keeps this protocol invariant visible here.
        if not any(raw_shared_secret):
            raise ValueError(
                "invalid X25519 shared secret"
            )

        # First derive a session-specific master secret.
        #
        # Binding the transcript here means the resulting session
        # material is tied to this exact pair of ephemeral public keys.
        master_secret = self._hkdf(
            ikm=raw_shared_secret,
            salt=transcript_hash,
            info=self.MASTER_INFO,
            length=self.KEY_LENGTH,
        )

        # Derive the encryption root independently from the master
        # secret. This gives the encryption layer its own domain.
        root_secret = self._hkdf(
            ikm=master_secret,
            info=self.ROOT_INFO,
            length=self.KEY_LENGTH,
        )

        # Derive a stable 128-bit session identifier from the same
        # authenticated session material.
        #
        # The session ID is public packet metadata, not a secret.
        session_id = self._hkdf(
            ikm=master_secret,
            info=self.SESSION_ID_INFO,
            length=self.SESSION_ID_LENGTH,
        )

        # Derive a completely separate key for SAS generation.
        sas_key = self._hkdf(
            ikm=master_secret,
            info=self.SAS_INFO,
            length=self.KEY_LENGTH,
        )

        # Authenticate the complete canonical transcript.
        #
        # The SAS therefore depends on:
        #
        #   - the protocol version
        #   - the initiator ephemeral public key
        #   - the responder ephemeral public key
        #   - the X25519 shared secret
        #
        # A passive observer cannot reproduce the SAS without the
        # shared secret.
        sas_mac = hmac.new(
            sas_key,
            transcript,
            hashlib.sha256,
        ).digest()

        # 6 bytes = 48 bits = 12 hexadecimal characters.
        sas = sas_mac[: self.SAS_LENGTH_BYTES].hex().upper()

        self._session_derived = True

        return KexResult(
            root_secret=root_secret,
            session_id=session_id,
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
        the session ID required by the packet layer.
        """

        result = self.derive_session(
            peer_public_bytes
        )

        return result.root_secret, result.sas
