import base64
import hashlib
import secrets
import struct
import time
from collections import OrderedDict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class EphemeralCryptoEngine:
    """
    Timestamp-epoch AES-256-GCM encryption with:

    - 256-bit root secret
    - HKDF-SHA256 key derivation
    - rotating per-epoch encryption keys
    - fresh 96-bit nonce per message
    - authenticated packet metadata
    - timestamp freshness checking
    - replay detection
    - strict packet validation
    - versioned packet format

    Packet format:

        [magic: 2 bytes]
        [version: 1 byte]
        [timestamp: 8 bytes]
        [nonce: 12 bytes]
        [ciphertext + GCM tag: variable]

    timestamp is Unix time in seconds.
    """

    MAGIC = b"EC"
    VERSION = 1

    NONCE_SIZE = 12
    KEY_SIZE = 32

    # Keys change every minute.
    EPOCH_SECONDS = 60

    # Accepted clock skew into the future.
    MAX_FUTURE_SKEW = 30

    # How old a packet may be.
    MAX_PACKET_AGE = 5 * 60

    # Maximum number of replay entries retained in memory.
    MAX_REPLAY_CACHE = 10_000

    INFO = b"ephemeral-crypto-engine/v1/aes256-gcm"

    HEADER_FORMAT = "!2sBQ"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, root_secret: bytes):
        if not isinstance(root_secret, bytes):
            raise TypeError("root_secret must be bytes")

        if len(root_secret) < 32:
            raise ValueError(
                "root_secret must contain at least 32 bytes of "
                "cryptographically random material"
            )

        self.root_secret = root_secret

        # OrderedDict gives us a bounded replay cache.
        #
        # Key:
        #   SHA-256(packet)
        #
        # Value:
        #   timestamp
        self._replay_cache: OrderedDict[bytes, int] = OrderedDict()

    @classmethod
    def generate_root_secret(cls) -> bytes:
        """
        Generate a cryptographically random 256-bit root secret.
        """
        return secrets.token_bytes(32)

    def _derive_epoch_key(self, epoch: int) -> bytes:
        """
        Derive an AES-256 key for a specific epoch.

        The epoch is public and does not need to be secret.
        """

        if epoch < 0:
            raise ValueError("invalid epoch")

        # Domain separation:
        # prevents this derivation from accidentally being reused
        # for another purpose.
        salt = struct.pack("!Q", epoch)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            info=self.INFO,
        )

        return hkdf.derive(self.root_secret)

    def _current_time(self) -> int:
        return int(time.time())

    def _epoch_for_timestamp(self, timestamp: int) -> int:
        return timestamp // self.EPOCH_SECONDS

    def _build_header(self, timestamp: int) -> bytes:
        return struct.pack(
            self.HEADER_FORMAT,
            self.MAGIC,
            self.VERSION,
            timestamp,
        )

    def _cleanup_replay_cache(self, now: int) -> None:
        """
        Remove expired replay entries and enforce cache size.
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

    def _validate_timestamp(self, timestamp: int, now: int) -> None:
        """
        Reject timestamps that are too old or too far in the future.
        """

        if timestamp < now - self.MAX_PACKET_AGE:
            raise ValueError("packet has expired")

        if timestamp > now + self.MAX_FUTURE_SKEW:
            raise ValueError("packet timestamp is too far in the future")

    def encrypt(
        self,
        payload: str | bytes,
        timestamp: int | None = None,
    ) -> str:
        """
        Encrypt payload and return a URL-safe Base64 packet.

        timestamp is Unix time in seconds. If omitted, current time is used.
        """

        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        elif isinstance(payload, bytes):
            payload_bytes = payload
        else:
            raise TypeError("payload must be str or bytes")

        if timestamp is None:
            timestamp = self._current_time()

        if not isinstance(timestamp, int):
            raise TypeError("timestamp must be an integer")

        if timestamp < 0:
            raise ValueError("timestamp cannot be negative")

        epoch = self._epoch_for_timestamp(timestamp)
        key = self._derive_epoch_key(epoch)

        nonce = secrets.token_bytes(self.NONCE_SIZE)

        # The header is authenticated by AES-GCM.
        #
        # This prevents an attacker from changing the timestamp/version
        # without invalidating the authentication tag.
        header = self._build_header(timestamp)

        aesgcm = AESGCM(key)

        ciphertext = aesgcm.encrypt(
            nonce,
            payload_bytes,
            header,
        )

        packet = header + nonce + ciphertext

        return base64.urlsafe_b64encode(packet).decode("ascii")

    def decrypt(self, encoded_packet: str) -> tuple[int, bytes]:
        """
        Decrypt a packet.

        Returns:

            (timestamp, plaintext_bytes)

        Raises ValueError for malformed, expired, future-dated,
        or replayed packets.
        """

        if not isinstance(encoded_packet, str):
            raise TypeError("encoded_packet must be str")

        # Strict Base64 decoding.
        try:
            packet = base64.b64decode(
                encoded_packet.encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, UnicodeEncodeError):
            raise ValueError("invalid Base64 packet")

        minimum_size = (
            self.HEADER_SIZE
            + self.NONCE_SIZE
            + 16  # AES-GCM authentication tag
        )

        if len(packet) < minimum_size:
            raise ValueError("packet is too short")

        # Parse header.
        try:
            magic, version, timestamp = struct.unpack(
                self.HEADER_FORMAT,
                packet[:self.HEADER_SIZE],
            )
        except struct.error:
            raise ValueError("invalid packet header")

        if magic != self.MAGIC:
            raise ValueError("invalid packet magic")

        if version != self.VERSION:
            raise ValueError("unsupported packet version")

        now = self._current_time()

        self._cleanup_replay_cache(now)

        # Check freshness BEFORE expensive cryptographic work.
        self._validate_timestamp(timestamp, now)

        # Replay identity.
        #
        # Hashing the entire packet means the exact packet cannot be
        # accepted twice during the replay-cache lifetime.
        packet_id = hashlib.sha256(packet).digest()

        if packet_id in self._replay_cache:
            raise ValueError("replayed packet")

        nonce_start = self.HEADER_SIZE
        nonce_end = nonce_start + self.NONCE_SIZE

        nonce = packet[nonce_start:nonce_end]
        ciphertext = packet[nonce_end:]

        epoch = self._epoch_for_timestamp(timestamp)
        key = self._derive_epoch_key(epoch)

        aesgcm = AESGCM(key)

        header = packet[:self.HEADER_SIZE]

        try:
            plaintext = aesgcm.decrypt(
                nonce,
                ciphertext,
                header,
            )
        except Exception as exc:
            # Do not leak details about why authentication failed.
            raise ValueError("authentication failed") from exc

        # Only mark a packet as seen after successful authentication.
        self._replay_cache[packet_id] = timestamp

        return timestamp, plaintext
