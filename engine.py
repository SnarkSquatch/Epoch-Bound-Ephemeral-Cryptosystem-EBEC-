from __future__ import annotations

import base64
import hashlib
import secrets
import struct
import time
from collections import OrderedDict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class EphemeralCryptoEngine:
    """
    EBEC authenticated encryption engine.

    Features:

    - AES-256-GCM authenticated encryption
    - Per-epoch AES-256 key derivation
    - Independent send/receive key separation
    - 128-bit authenticated session ID
    - Explicit authenticated packet direction
    - Fresh 96-bit nonce per packet
    - Authenticated packet metadata
    - Timestamp freshness checking
    - Replay detection
    - Strict packet validation
    - Versioned packet format

    Packet format:

        [magic: 2 bytes]
        [version: 1 byte]
        [direction: 1 byte]
        [session_id: 16 bytes]
        [timestamp: 8 bytes]
        [nonce: 12 bytes]
        [ciphertext + GCM tag: variable]

    The complete binary packet is URL-safe Base64 encoded.

    Direction values:

        0x01 = initiator -> responder
        0x02 = responder -> initiator

    Epoch keys are derived on demand from the session root secret:

        session root
             |
             +-- direction
             +-- session ID
             +-- epoch number
             |
             v
          HKDF-SHA256
             |
             v
        AES-256-GCM key
    """

    MAGIC = b"EC"
    VERSION = 1

    DIRECTION_INITIATOR_TO_RESPONDER = 0x01
    DIRECTION_RESPONDER_TO_INITIATOR = 0x02

    SESSION_ID_SIZE = 16
    NONCE_SIZE = 12
    KEY_SIZE = 32
    GCM_TAG_SIZE = 16

    # Encryption keys rotate every 60 seconds.
    EPOCH_SECONDS = 60

    # Domain-separated HKDF context for packet encryption.
    EPOCH_KEY_INFO = b"ebec-epoch-aead-v1"

    MAX_FUTURE_SKEW = 30
    MAX_PACKET_AGE = 5 * 60

    MAX_REPLAY_CACHE = 10_000

    # Maximum plaintext accepted by this engine.
    MAX_PAYLOAD_SIZE = 1024 * 1024  # 1 MiB

    # Header:
    #
    # magic       2 bytes
    # version     1 byte
    # direction   1 byte
    # session_id 16 bytes
    # timestamp   8 bytes
    #
    # Total = 28 bytes
    HEADER_FORMAT = "!2sBB16sQ"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(
        self,
        *,
        session_id: bytes,
        root_secret: bytes,
        direction: int,
    ):
        """
        Create an EBEC crypto engine.

        Args:
            session_id:
                16-byte session identifier produced by the KEX.

            root_secret:
                32-byte session root secret produced by the KEX.

            direction:
                Direction used for packets sent by this instance.

                Use:

                    DIRECTION_INITIATOR_TO_RESPONDER

                or:

                    DIRECTION_RESPONDER_TO_INITIATOR

        The engine does NOT store static AES send/receive keys.

        Instead, the AES key for each packet is derived from the
        session root secret and that packet's timestamp epoch.
        """

        if not isinstance(session_id, bytes):
            raise TypeError("session_id must be bytes")

        if len(session_id) != self.SESSION_ID_SIZE:
            raise ValueError(
                f"session_id must be exactly "
                f"{self.SESSION_ID_SIZE} bytes"
            )

        if not isinstance(root_secret, bytes):
            raise TypeError("root_secret must be bytes")

        if len(root_secret) != self.KEY_SIZE:
            raise ValueError(
                f"root_secret must be exactly {self.KEY_SIZE} bytes"
            )

        if direction not in (
            self.DIRECTION_INITIATOR_TO_RESPONDER,
            self.DIRECTION_RESPONDER_TO_INITIATOR,
        ):
            raise ValueError("invalid direction")

        self.session_id = session_id
        self.root_secret = root_secret
        self.direction = direction

        # Direction expected from incoming packets.
        if direction == self.DIRECTION_INITIATOR_TO_RESPONDER:
            self.receive_direction = (
                self.DIRECTION_RESPONDER_TO_INITIATOR
            )
        else:
            self.receive_direction = (
                self.DIRECTION_INITIATOR_TO_RESPONDER
            )

        # OrderedDict gives us a bounded replay cache.
        #
        # Key:
        #     SHA-256(packet)
        #
        # Value:
        #     timestamp
        self._replay_cache: OrderedDict[bytes, int] = OrderedDict()

    @classmethod
    def from_kex_result(cls, kex_result):
        """
        Construct an engine directly from a KexResult.

        The KexResult must contain:

            root_secret
            session_id
            sas

        The role is still required because packet direction is
        intentionally separate from the session root secret.
        """

        if not hasattr(kex_result, "session_id"):
            raise TypeError("invalid KexResult")

        if not hasattr(kex_result, "root_secret"):
            raise TypeError("invalid KexResult")

        raise TypeError(
            "use from_kex_result_with_role() and provide "
            "the KEX role"
        )

    @classmethod
    def from_kex_result_with_role(
        cls,
        kex_result,
        role: str,
    ):
        """
        Construct an engine from a KexResult and its KEX role.

        role must be:

            "initiator"
            "responder"
        """

        if role == "initiator":
            direction = cls.DIRECTION_INITIATOR_TO_RESPONDER

        elif role == "responder":
            direction = cls.DIRECTION_RESPONDER_TO_INITIATOR

        else:
            raise ValueError(
                "role must be either 'initiator' or 'responder'"
            )

        return cls(
            session_id=kex_result.session_id,
            root_secret=kex_result.root_secret,
            direction=direction,
        )

    @classmethod
    def generate_root_secret(cls) -> bytes:
        """
        Generate a cryptographically secure 256-bit root secret.

        For a normal P2P session, the root secret should instead be
        established through EphemeralKeyExchange.
        """
        return secrets.token_bytes(cls.KEY_SIZE)

    def _current_time(self) -> int:
        return int(time.time())

    def _epoch_for_timestamp(self, timestamp: int) -> int:
        """
        Convert a Unix timestamp into the corresponding EBEC epoch.
        """
        return timestamp // self.EPOCH_SECONDS

    def _derive_epoch_key(
        self,
        *,
        epoch: int,
        direction: int,
    ) -> bytes:
        """
        Derive the AES-256-GCM key for a specific epoch and direction.

        The derivation is:

            root_secret
                |
                +-- session_id
                +-- direction
                +-- epoch
                |
                v
            HKDF-SHA256
                |
                v
            32-byte AES key

        Direction separation ensures that the key used for
        initiator -> responder traffic is different from the key
        used for responder -> initiator traffic.

        Session-ID binding prevents accidental key reuse across
        independent sessions even if root material were ever reused.
        """

        if direction not in (
            self.DIRECTION_INITIATOR_TO_RESPONDER,
            self.DIRECTION_RESPONDER_TO_INITIATOR,
        ):
            raise ValueError("invalid direction")

        if epoch < 0:
            raise ValueError("epoch cannot be negative")

        # Canonical binary derivation context.
        #
        # session_id: 16 bytes
        # direction:   1 byte
        # epoch:       8 bytes
        #
        # This context is supplied as HKDF salt so that each epoch and
        # direction receives independent key material.
        salt = hashlib.sha256(
            self.session_id
            + bytes([direction])
            + struct.pack("!Q", epoch)
        ).digest()

        return HKDF(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            info=self.EPOCH_KEY_INFO,
        ).derive(self.root_secret)

    def _build_header(self, timestamp: int) -> bytes:
        """
        Build the authenticated packet header.
        """

        return struct.pack(
            self.HEADER_FORMAT,
            self.MAGIC,
            self.VERSION,
            self.direction,
            self.session_id,
            timestamp,
        )

    def _cleanup_replay_cache(self, now: int) -> None:
        """
        Remove expired replay entries and enforce the cache limit.
        """

        expiration = now - self.MAX_PACKET_AGE

        expired = [
            digest
            for digest, timestamp in self._replay_cache.items()
            if timestamp < expiration
        ]

        for digest in expired:
            self._replay_cache.pop(digest, None)

        while len(self._replay_cache) > self.MAX_REPLAY_CACHE:
            self._replay_cache.popitem(last=False)

    def _validate_timestamp(
        self,
        timestamp: int,
        now: int,
    ) -> None:
        """
        Reject timestamps that are too old or too far in the future.
        """

        if timestamp < now - self.MAX_PACKET_AGE:
            raise ValueError("packet has expired")

        if timestamp > now + self.MAX_FUTURE_SKEW:
            raise ValueError(
                "packet timestamp is too far in the future"
            )

    def _validate_payload_size(self, payload: bytes) -> None:
        if len(payload) > self.MAX_PAYLOAD_SIZE:
            raise ValueError(
                f"payload exceeds maximum size of "
                f"{self.MAX_PAYLOAD_SIZE} bytes"
            )

    def encrypt(
        self,
        payload: str | bytes,
        timestamp: int | None = None,
    ) -> str:
        """
        Encrypt a payload and return a URL-safe Base64 packet.

        The AES key is derived from:

            session root
            + this engine's direction
            + timestamp epoch

        Therefore the encryption key automatically changes every
        EPOCH_SECONDS.
        """

        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")

        elif isinstance(payload, bytes):
            payload_bytes = payload

        else:
            raise TypeError(
                "payload must be str or bytes"
            )

        self._validate_payload_size(payload_bytes)

        if timestamp is None:
            timestamp = self._current_time()

        if not isinstance(timestamp, int):
            raise TypeError(
                "timestamp must be an integer"
            )

        if timestamp < 0:
            raise ValueError(
                "timestamp cannot be negative"
            )

        epoch = self._epoch_for_timestamp(timestamp)

        # Derive the key for this exact outgoing epoch and direction.
        encryption_key = self._derive_epoch_key(
            epoch=epoch,
            direction=self.direction,
        )

        header = self._build_header(timestamp)

        # AES-GCM requires a unique nonce for a given key.
        #
        # A fresh cryptographically secure random 96-bit nonce is
        # generated for every packet.
        nonce = secrets.token_bytes(self.NONCE_SIZE)

        aesgcm = AESGCM(encryption_key)

        ciphertext = aesgcm.encrypt(
            nonce,
            payload_bytes,
            header,
        )

        packet = header + nonce + ciphertext

        return base64.urlsafe_b64encode(packet).decode("ascii")

    def decrypt(
        self,
        encoded_packet: str,
    ) -> tuple[int, bytes]:
        """
        Decrypt and authenticate an incoming packet.

        The AES key is derived from:

            session root
            + packet direction
            + packet timestamp epoch

        Returns:

            (timestamp, plaintext_bytes)

        Raises ValueError for malformed, expired, future-dated,
        wrong-session, wrong-direction, unauthenticated, or replayed
        packets.
        """

        if not isinstance(encoded_packet, str):
            raise TypeError(
                "encoded_packet must be str"
            )

        if not encoded_packet:
            raise ValueError(
                "packet cannot be empty"
            )

        try:
            packet = base64.b64decode(
                encoded_packet.encode("ascii"),
                altchars=b"-_",
                validate=True,
            )

        except (ValueError, UnicodeEncodeError):
            raise ValueError(
                "invalid Base64 packet"
            )

        minimum_size = (
            self.HEADER_SIZE
            + self.NONCE_SIZE
            + self.GCM_TAG_SIZE
        )

        if len(packet) < minimum_size:
            raise ValueError(
                "packet is too short"
            )

        # Enforce a maximum packet size before performing expensive
        # cryptographic operations.
        maximum_packet_size = (
            self.HEADER_SIZE
            + self.NONCE_SIZE
            + self.MAX_PAYLOAD_SIZE
            + self.GCM_TAG_SIZE
        )

        if len(packet) > maximum_packet_size:
            raise ValueError(
                "packet exceeds maximum size"
            )

        try:
            (
                magic,
                version,
                direction,
                session_id,
                timestamp,
            ) = struct.unpack(
                self.HEADER_FORMAT,
                packet[: self.HEADER_SIZE],
            )

        except struct.error:
            raise ValueError(
                "invalid packet header"
            )

        # Validate protocol identity.
        if magic != self.MAGIC:
            raise ValueError(
                "invalid packet magic"
            )

        if version != self.VERSION:
            raise ValueError(
                "unsupported packet version"
            )

        # Ensure this packet belongs to this session.
        if not secrets.compare_digest(
            session_id,
            self.session_id,
        ):
            raise ValueError(
                "packet belongs to a different session"
            )

        # Ensure the packet came from the expected peer direction.
        if direction != self.receive_direction:
            raise ValueError(
                "invalid packet direction"
            )

        now = self._current_time()

        self._cleanup_replay_cache(now)

        self._validate_timestamp(
            timestamp,
            now,
        )

        # Hash the complete packet for replay tracking.
        packet_id = hashlib.sha256(packet).digest()

        if packet_id in self._replay_cache:
            raise ValueError(
                "replayed packet"
            )

        # Derive the receive key from the packet's authenticated
        # direction and timestamp epoch.
        epoch = self._epoch_for_timestamp(timestamp)

        decryption_key = self._derive_epoch_key(
            epoch=epoch,
            direction=direction,
        )

        nonce_start = self.HEADER_SIZE
        nonce_end = nonce_start + self.NONCE_SIZE

        nonce = packet[
            nonce_start:nonce_end
        ]

        ciphertext = packet[
            nonce_end:
        ]

        # The header is authenticated as AES-GCM AAD.
        header = packet[
            : self.HEADER_SIZE
        ]

        aesgcm = AESGCM(decryption_key)

        try:
            plaintext = aesgcm.decrypt(
                nonce,
                ciphertext,
                header,
            )

        except Exception as exc:
            raise ValueError(
                "authentication failed"
            ) from exc

        self._validate_payload_size(
            plaintext
        )

        # Only record the packet after successful authentication.
        self._replay_cache[packet_id] = timestamp

        return timestamp, plaintext
