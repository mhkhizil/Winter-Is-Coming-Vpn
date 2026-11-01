#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Independent WireGuard client used to prove interoperability.

Every C++ test drives our own initiator against our own responder, which cannot
catch a misreading of the spec shared by both sides. This script implements the
handshake from the specification using a *different* crypto stack (Python
`cryptography` for X25519/ChaCha20-Poly1305, `hashlib` for BLAKE2s/HMAC), so a
successful handshake means our bytes on the wire match the spec.

  python scripts/interop_client.py --genkey
  python scripts/interop_client.py --connect --server-pub <hex> --client-priv <hex> \
      [--host 127.0.0.1] [--port 51820] [--packets 4]

Exit code 0 = handshake completed, keys agreed, N transport packets sent.
"""
import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys
import time

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    sys.exit("error: pip install cryptography (needed for X25519 + ChaCha20-Poly1305)")

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
ZERO_NONCE = b"\x00" * 12


def b2s(data: bytes, key: bytes = b"", size: int = 32) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=size).digest()


def hmac_b2s(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def kdf(chaining_key: bytes, data: bytes, count: int):
    """WireGuard KDF: T1 = HMAC(T0, 0x01), T2 = HMAC(T0, T1 || 0x02), ..."""
    t0 = hmac_b2s(chaining_key, data)
    out, previous = [], b""
    for i in range(1, count + 1):
        previous = hmac_b2s(t0, previous + bytes([i]))
        out.append(previous)
    return out


def tai64n() -> bytes:
    now = time.time()
    seconds = int(now)
    nanos = int((now - seconds) * 1_000_000_000)
    return struct.pack(">Q", 0x400000000000000A + seconds) + struct.pack(">I", nanos)


def genkey() -> int:
    private = X25519PrivateKey.generate()
    print(f"private_key = {private.private_bytes_raw().hex()}")
    print(f"public_key  = {private.public_key().public_bytes_raw().hex()}")
    return 0


def connect(host: str, port: int, server_pub_hex: str, client_priv_hex: str, packets: int) -> int:
    server_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(server_pub_hex))
    server_pub_raw = server_pub.public_bytes_raw()
    static_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(client_priv_hex))
    my_pub = static_priv.public_key().public_bytes_raw()

    sender_index = struct.unpack("<I", os.urandom(4))[0] or 1

    # --- message 1 ---------------------------------------------------------
    ck = b2s(CONSTRUCTION)
    h = b2s(ck + IDENTIFIER)
    h = b2s(h + server_pub_raw)

    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()
    h = b2s(h + eph_pub)
    ck = kdf(ck, eph_pub, 1)[0]

    ck, key = kdf(ck, eph_priv.exchange(server_pub), 2)
    enc_static = ChaCha20Poly1305(key).encrypt(ZERO_NONCE, my_pub, h)
    h = b2s(h + enc_static)

    ck, key = kdf(ck, static_priv.exchange(server_pub), 2)
    enc_ts = ChaCha20Poly1305(key).encrypt(ZERO_NONCE, tai64n(), h)
    h = b2s(h + enc_ts)

    msg = struct.pack("<I", 1) + struct.pack("<I", sender_index) + eph_pub + enc_static + enc_ts
    if len(msg) != 116:
        print(f"FAIL: initiation header is {len(msg)} bytes, expected 116 before the MACs")
        return 1
    mac1 = b2s(msg, key=b2s(LABEL_MAC1 + server_pub_raw), size=16)
    msg += mac1 + b"\x00" * 16

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    sock.sendto(msg, (host, port))

    try:
        response, _ = sock.recvfrom(2048)
    except socket.timeout:
        print("FAIL: no response to the handshake initiation (mac1 or transcript hash?)")
        return 1
    if len(response) != 92 or struct.unpack("<I", response[:4])[0] != 2:
        print(f"FAIL: expected a 92-byte handshake response, got {len(response)} bytes")
        return 1

    remote_index = struct.unpack("<I", response[4:8])[0]
    if struct.unpack("<I", response[8:12])[0] != sender_index:
        print("FAIL: response receiver_index does not match our sender_index")
        return 1
    resp_eph = X25519PublicKey.from_public_bytes(response[12:44])
    enc_nothing = response[44:60]

    # --- message 2 ---------------------------------------------------------
    h = b2s(h + response[12:44])
    ck = kdf(ck, response[12:44], 1)[0]
    ck = kdf(ck, eph_priv.exchange(resp_eph), 1)[0]
    ck = kdf(ck, static_priv.exchange(resp_eph), 1)[0]
    ck, tau, key = kdf(ck, b"\x00" * 32, 3)
    h = b2s(h + tau)
    try:
        ChaCha20Poly1305(key).decrypt(ZERO_NONCE, enc_nothing, h)
    except Exception:
        print("FAIL: could not authenticate the empty payload (keys diverged)")
        return 1

    send_key, _recv_key = kdf(ck, b"", 2)
    print(f"handshake ok: local index {sender_index}, remote index {remote_index}")

    # --- transport ---------------------------------------------------------
    for counter in range(packets):
        inner = bytearray(32)          # 20-byte IPv4 header, padded to a 16-byte multiple
        inner[0] = 0x45
        inner[2:4] = struct.pack(">H", len(inner))  # total length includes padding
        inner[9] = 17                  # UDP
        inner[12:16] = bytes([10, 66, 0, 2])
        inner[16:20] = bytes([10, 66, 0, 1])
        nonce = b"\x00" * 4 + struct.pack("<Q", counter)
        sealed = ChaCha20Poly1305(send_key).encrypt(nonce, bytes(inner), None)
        datagram = (struct.pack("<I", 4) + struct.pack("<I", remote_index) +
                    struct.pack("<Q", counter) + sealed)
        sock.sendto(datagram, (host, port))
    print(f"transport sent: {packets} packets")
    sock.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="independent WireGuard client (interop test)")
    parser.add_argument("--genkey", action="store_true")
    parser.add_argument("--connect", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=51820)
    parser.add_argument("--server-pub", default="")
    parser.add_argument("--client-priv", default="")
    parser.add_argument("--packets", type=int, default=4)
    args = parser.parse_args()

    if args.genkey:
        return genkey()
    if not args.connect:
        parser.print_help()
        return 2
    if not args.server_pub or not args.client_priv:
        sys.stderr.write("error: --server-pub and --client-priv are required\n")
        return 2
    return connect(args.host, args.port, args.server_pub, args.client_priv, args.packets)


if __name__ == "__main__":
    sys.exit(main())
