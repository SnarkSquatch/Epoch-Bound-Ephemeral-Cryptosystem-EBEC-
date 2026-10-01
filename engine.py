from __future__ import annotations

import base64
import hashlib
import secrets
import struct
import time
from collections import OrderedDict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class EphemeralCryptoEngine:
    """
    EBEC authenticated encryption engine.

    Features:

    - AES-256-GCM authenticated encryption
    - Separate send and receive keys
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
    """

    MAGIC = b"EC"
    VERSION = 1

    DIRECTION_INITIATOR_TO_RESPONDER = 0x01
    DIRECTION_RESPONDER_TO_INITIATOR = 0x02

    SESSION_ID_SIZE = 16
    NONCE_SIZE = 12
    KEY_SIZE = 32
    GCM_TAG_SIZE = 16

    # Keys are derived by the KEX layer.
    #
    # Epoch key derivation can be added later if required. The current
    # engine uses the direction-specific AES-256 keys supplied by KEX.

    MAX_FUTURE_SKEW = 30
    MAX_PACKET_AGE = 5 * 60

    MAX_REPLAY_CACHE = 10_000

    # Maximum plaintext size accepted by this engine.
    #
    # This is deliberately bounded to prevent an attacker from causing
    # excessive memory usage through oversized packets.
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
        send_key: bytes,
        receive_key: bytes,
        direction: int,
    ):
        """
        Create an EBEC crypto engine.

        Args:
            session_id:
                16-byte session identifier produced by the KEX.

            send_key:
                32-byte AES-256 key used for outgoing packets.

            receive_key:
                32-byte AES-256 key used for incoming packets.

            direction:
                Direction used for packets sent by this instance.

                Use:

                    DIRECTION_INITIATOR_TO_RESPONDER

                or:

                    DIRECTION_RESPONDER_TO_INITIATOR
        """

        if not isinstance(session_id, bytes):
            raise TypeError("session_id must be bytes")

        if len(session_id) != self.SESSION_ID_SIZE:
            raise ValueError(
                f"session_id must be exactly "
                f"{self.SESSION_ID_SIZE} bytes"
            )

        if not isinstance(send_key, bytes):
            raise TypeError("send_key must be bytes")

        if len(send_key) != self.KEY_SIZE:
            raise ValueError(
                f"send_key must be exactly {self.KEY_SIZE} bytes"
            )

        if not isinstance(receive_key, bytes):
            raise TypeError("receive_key must be bytes")

        if len(receive_key) != self.KEY_SIZE:
            raise ValueError(
                f"receive_key must be exactly {self.KEY_SIZE} bytes"
            )

        if direction not in (
            self.DIRECTION_INITIATOR_TO_RESPONDER,
            self.DIRECTION_RESPONDER_TO_INITIATOR,
        ):
            raise ValueError("invalid direction")

        self.session_id = session_id
        self.send_key = send_key
        self.receive_key = receive_key
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

        This avoids manually copying session_id/send_key/receive_key.

        The KexResult must have been produced by EphemeralKeyExchange.
        """

        # Import lazily to avoid making engine.py depend on kex.py
        # at module import time.
        from kex import EphemeralKeyExchange

        if not hasattr(kex_result, "session_id"):
            raise TypeError("invalid KexResult")

        if not hasattr(kex_result, "send_key"):
            raise TypeError("invalid KexResult")

        if not hasattr(kex_result, "receive_key"):
            raise TypeError("invalid KexResult")

        if not isinstance(kex_result, object):
            raise TypeError("invalid KexResult")

        # KexResult does not itself expose the role, so the direction
        # must be inferred by the caller using from_kex_result_with_role().
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
            send_key=kex_result.send_key,
            receive_key=kex_result.receive_key,
            direction=direction,
        )

    @classmethod
    def generate_root_secret(cls) -> bytes:
        """
        Generate a cryptographically secure 256-bit root secret.

        This method is retained for compatibility with older EBEC
        application code.

        For a normal P2P session, the root secret should be derived
        through EphemeralKeyExchange instead.
        """
        return secrets.token_bytes(32)

    def _current_time(self) -> int:
        return int(time.time())

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

        The outgoing packet uses this engine's send_key and direction.
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

        header = self._build_header(timestamp)

        # AES-GCM requires a unique nonce for a given key.
        #
        # A fresh cryptographically secure random 96-bit nonce is
        # generated for every packet.
        nonce = secrets.token_bytes(self.NONCE_SIZE)

        aesgcm = AESGCM(self.send_key)

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

        aesgcm = AESGCM(self.receive_key)

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
