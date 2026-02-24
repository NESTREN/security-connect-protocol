from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

VERSION = 1
SUITE_ID = "DH31-HMACSHA256-STREAMXOR"
COUNTER_WINDOW = 32
# Mersenne prime for lightweight demonstrational DH (not production-grade).
DH_P = 2**127 - 1
DH_G = 5


class ProtocolState(Enum):
    INIT = "INIT"
    HELLO_SENT = "HELLO_SENT"
    ESTABLISHED = "ESTABLISHED"
    REKEYING = "REKEYING"
    CLOSED = "CLOSED"


@dataclass
class ClientHello:
    version: int
    suite: str
    random: bytes
    ephemeral_pubkey: bytes

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "version": self.version,
                "suite": self.suite,
                "random": self.random.hex(),
                "ephemeral_pubkey": self.ephemeral_pubkey.hex(),
            },
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "ClientHello":
        payload = json.loads(data.decode("utf-8"))
        return cls(
            version=payload["version"],
            suite=payload["suite"],
            random=bytes.fromhex(payload["random"]),
            ephemeral_pubkey=bytes.fromhex(payload["ephemeral_pubkey"]),
        )


@dataclass
class ServerHello:
    random: bytes
    ephemeral_pubkey: bytes
    mac: bytes

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "random": self.random.hex(),
                "ephemeral_pubkey": self.ephemeral_pubkey.hex(),
                "mac": self.mac.hex(),
            },
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "ServerHello":
        payload = json.loads(data.decode("utf-8"))
        return cls(
            random=bytes.fromhex(payload["random"]),
            ephemeral_pubkey=bytes.fromhex(payload["ephemeral_pubkey"]),
            mac=bytes.fromhex(payload["mac"]),
        )


@dataclass
class EncryptedPacket:
    counter: int
    ciphertext: bytes
    tag: bytes

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "counter": self.counter,
                "ciphertext": self.ciphertext.hex(),
                "tag": self.tag.hex(),
            },
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedPacket":
        payload = json.loads(data.decode("utf-8"))
        return cls(
            counter=payload["counter"],
            ciphertext=bytes.fromhex(payload["ciphertext"]),
            tag=bytes.fromhex(payload["tag"]),
        )


class ReplayWindow:
    def __init__(self, size: int = COUNTER_WINDOW) -> None:
        self.size = size
        self.max_seen = -1
        self.bitmap = 0

    def validate_and_mark(self, counter: int) -> bool:
        if counter < 0:
            return False
        if self.max_seen == -1:
            self.max_seen = counter
            self.bitmap = 1
            return True
        if counter > self.max_seen:
            shift = counter - self.max_seen
            self.bitmap = 0 if shift >= self.size else (self.bitmap << shift) & ((1 << self.size) - 1)
            self.bitmap |= 1
            self.max_seen = counter
            return True
        delta = self.max_seen - counter
        if delta >= self.size:
            return False
        mask = 1 << delta
        if self.bitmap & mask:
            return False
        self.bitmap |= mask
        return True


class EELPPeer:
    def __init__(self, psk: bytes, role: str) -> None:
        if role not in {"client", "server"}:
            raise ValueError("role must be client or server")
        self.role = role
        self.psk = psk
        self.state = ProtocolState.INIT
        self._priv: Optional[int] = None
        self._pub_peer: Optional[int] = None
        self._client_random: Optional[bytes] = None
        self._server_random: Optional[bytes] = None
        self._send_counter = 0
        self._replay = ReplayWindow()
        self._tx_key: Optional[bytes] = None
        self._rx_key: Optional[bytes] = None

    @staticmethod
    def _int_to_bytes(x: int) -> bytes:
        return x.to_bytes(32, "big")

    @staticmethod
    def _bytes_to_int(x: bytes) -> int:
        return int.from_bytes(x, "big")

    def _new_ephemeral(self) -> bytes:
        self._priv = int.from_bytes(os.urandom(32), "big") % (DH_P - 2) + 2
        pub = pow(DH_G, self._priv, DH_P)
        return self._int_to_bytes(pub)

    @staticmethod
    def _context(version: int, suite: str) -> bytes:
        return f"{version}|{suite}".encode()

    def create_client_hello(self) -> bytes:
        if self.role != "client" or self.state != ProtocolState.INIT:
            raise RuntimeError("invalid state for ClientHello")
        self._client_random = os.urandom(16)
        self.state = ProtocolState.HELLO_SENT
        return ClientHello(VERSION, SUITE_ID, self._client_random, self._new_ephemeral()).to_bytes()

    def process_client_hello(self, payload: bytes) -> bytes:
        if self.role != "server" or self.state != ProtocolState.INIT:
            raise RuntimeError("invalid state for processing ClientHello")
        hello = ClientHello.from_bytes(payload)
        if hello.version != VERSION or hello.suite != SUITE_ID:
            raise ValueError("unsupported version/suite")

        self._client_random = hello.random
        self._server_random = os.urandom(16)
        server_pub = self._new_ephemeral()
        self._pub_peer = self._bytes_to_int(hello.ephemeral_pubkey)
        self._derive_transport_keys(hello.version, hello.suite)

        mac = hmac.new(self.psk, digestmod=hashlib.sha256)
        mac.update(self._context(hello.version, hello.suite))
        mac.update(self._client_random)
        mac.update(self._server_random)
        mac.update(hello.ephemeral_pubkey)
        mac.update(server_pub)
        self.state = ProtocolState.ESTABLISHED
        return ServerHello(self._server_random, server_pub, mac.digest()).to_bytes()

    def process_server_hello(self, payload: bytes) -> None:
        if self.role != "client" or self.state != ProtocolState.HELLO_SENT:
            raise RuntimeError("invalid state for processing ServerHello")
        hello = ServerHello.from_bytes(payload)
        self._server_random = hello.random
        self._pub_peer = self._bytes_to_int(hello.ephemeral_pubkey)
        self._derive_transport_keys(VERSION, SUITE_ID)

        local_pub = self._int_to_bytes(pow(DH_G, self._priv, DH_P))
        mac = hmac.new(self.psk, digestmod=hashlib.sha256)
        mac.update(self._context(VERSION, SUITE_ID))
        mac.update(self._client_random)
        mac.update(self._server_random)
        mac.update(local_pub)
        mac.update(hello.ephemeral_pubkey)
        if not hmac.compare_digest(mac.digest(), hello.mac):
            raise ValueError("server hello MAC validation failed")
        self.state = ProtocolState.ESTABLISHED

    def _hkdf(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        okm = b""
        t = b""
        counter = 1
        while len(okm) < length:
            t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
            okm += t
            counter += 1
        return okm[:length]

    def _derive_transport_keys(self, version: int, suite: str) -> None:
        shared = pow(self._pub_peer, self._priv, DH_P)
        shared_secret = self._int_to_bytes(shared)
        salt = self._client_random + self._server_random
        keymat = self._hkdf(shared_secret, salt, self._context(version, suite), 64)
        c2s, s2c = keymat[:32], keymat[32:]
        self._tx_key, self._rx_key = (c2s, s2c) if self.role == "client" else (s2c, c2s)

    def _keystream(self, key: bytes, counter: int, length: int, aad: bytes) -> bytes:
        out = b""
        block = 0
        while len(out) < length:
            out += hmac.new(key, counter.to_bytes(8, "big") + block.to_bytes(4, "big") + aad, hashlib.sha256).digest()
            block += 1
        return out[:length]

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        if self.state != ProtocolState.ESTABLISHED:
            raise RuntimeError("session is not established")
        counter = self._send_counter
        self._send_counter += 1
        stream = self._keystream(self._tx_key, counter, len(plaintext), aad)
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
        tag = hmac.new(self._tx_key, counter.to_bytes(8, "big") + aad + ciphertext, hashlib.sha256).digest()[:16]
        return EncryptedPacket(counter, ciphertext, tag).to_bytes()

    def decrypt(self, packet_payload: bytes, aad: bytes = b"") -> bytes:
        if self.state != ProtocolState.ESTABLISHED:
            raise RuntimeError("session is not established")
        packet = EncryptedPacket.from_bytes(packet_payload)
        if not self._replay.validate_and_mark(packet.counter):
            raise ValueError("replay detected")
        expected = hmac.new(self._rx_key, packet.counter.to_bytes(8, "big") + aad + packet.ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(expected, packet.tag):
            raise ValueError("ciphertext integrity check failed")
        stream = self._keystream(self._rx_key, packet.counter, len(packet.ciphertext), aad)
        return bytes(a ^ b for a, b in zip(packet.ciphertext, stream))

    def lightweight_rekey(self) -> None:
        if self.state != ProtocolState.ESTABLISHED:
            raise RuntimeError("session is not established")
        self.state = ProtocolState.REKEYING
        self._tx_key = self._hkdf(self._tx_key, b"", b"rekey-tx", 32)
        self._rx_key = self._hkdf(self._rx_key, b"", b"rekey-rx", 32)
        self.state = ProtocolState.ESTABLISHED

    def close(self) -> None:
        self.state = ProtocolState.CLOSED
