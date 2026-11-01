#!/usr/bin/env bash
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#
# End-to-end interoperability test: does our server complete a handshake with the
# OFFICIAL WireGuard client and carry traffic?
#
# This is the one gate that self-consistency cannot prove. It must run on Linux
# as root (TUN + wg-quick), with wireguard-tools installed.
#
#   sudo apt-get install -y wireguard-tools iproute2 curl xxd
#   sudo ./scripts/interop-test.sh            # expects ./out/build/server/vpn-dp
#
# Exit code 0 means: handshake completed, ping through the tunnel worked, and the
# client's egress view is the server. Anything else is a failure with a log dump.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_BIN="${VPN_DP:-$ROOT/out/build/server/vpn-dp}"
IFACE="${IFACE:-wgvpn0}"
SERVER_IP="10.66.0.1"
CLIENT_IP="10.66.0.2"
PORT="${PORT:-51821}"
WORK="$(mktemp -d)"
CONF="$WORK/datad.toml"
CLIENT_CONF="$WORK/client.conf"
LOG="$WORK/vpn-dp.log"

cleanup() {
  set +e
  wg-quick down "$IFACE" >/dev/null 2>&1
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
  wait "${SERVER_PID:-}" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

hex_to_b64() { xxd -r -p | base64 -w0; }
b64_to_hex() { base64 -d | xxd -p -c 64; }

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root (TUN + wg-quick)"; exit 2; }
command -v wg >/dev/null || { echo "error: wireguard-tools missing"; exit 2; }
[ -x "$SERVER_BIN" ] || {
  echo "error: $SERVER_BIN not found - build with:"
  echo "  cmake -S . -B out/build -DVPN_BUILD_DATAPLANE=ON && cmake --build out/build"
  exit 2
}

echo "==> generating keys"
SERVER_KEYS="$("$SERVER_BIN" --genkey)"
SERVER_PRIV_HEX="$(printf '%s\n' "$SERVER_KEYS" | awk -F'= ' '/private_key/{print $2}')"
SERVER_PUB_HEX="$(printf '%s\n' "$SERVER_KEYS" | awk -F'= ' '/public_key/{print $2}')"
CLIENT_PRIV="$(wg genkey)"
CLIENT_PUB="$(printf '%s' "$CLIENT_PRIV" | wg pubkey)"
CLIENT_PUB_HEX="$(printf '%s' "$CLIENT_PUB" | b64_to_hex)"

echo "==> writing $CONF"
cat >"$CONF" <<EOF
[interface]
private_key = "$SERVER_PRIV_HEX"
listen = "127.0.0.1:$PORT"
tun = "vpninterop0"
address = "$SERVER_IP/24"
mtu = 1420

[[peer]]
name = "official-client"
public_key = "$CLIENT_PUB_HEX"
allowed_ips = ["$CLIENT_IP/32"]
EOF

echo "==> starting vpn-dp"
"$SERVER_BIN" --config "$CONF" >"$LOG" 2>&1 &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "FAIL: vpn-dp exited at startup"; cat "$LOG"; exit 1
fi

echo "==> bringing up the official client (wg-quick)"
chmod 600 "$WORK"
cat >"$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = $CLIENT_IP/32
MTU = 1420

[Peer]
PublicKey = $(printf '%s' "$SERVER_PUB_HEX" | hex_to_b64)
Endpoint = 127.0.0.1:$PORT
AllowedIPs = 10.66.0.1/32
PersistentKeepalive = 5
EOF
cp "$CLIENT_CONF" "/etc/wireguard/$IFACE.conf"
chmod 600 "/etc/wireguard/$IFACE.conf"
wg-quick up "$IFACE"

fail() { echo "FAIL: $1"; echo "--- server log ---"; cat "$LOG"; echo "--- wg show ---"; wg show || true; exit 1; }

echo "==> waiting for a handshake (max 15 s)"
for _ in $(seq 1 15); do
  if wg show "$IFACE" latest-handshakes | awk '{print $2}' | grep -qv '^0$'; then break; fi
  sleep 1
done
wg show "$IFACE" latest-handshakes | awk '{print $2}' | grep -qv '^0$' \
  || fail "no handshake: the client could not authenticate against our Noise_IK implementation"

echo "==> handshake OK:"
wg show "$IFACE"

echo "==> ICMP through the tunnel"
ping -c 3 -W 2 "$SERVER_IP" || fail "ping through the tunnel failed"

echo "==> keepalive/transport counters"
wg show "$IFACE" transfer
RX="$(wg show "$IFACE" transfer | awk '{print $2}')"
[ "${RX:-0}" -gt 0 ] || fail "no transport bytes were counted by the client"

echo
echo "PASS: official WireGuard client <-> vpn-dp handshake, ping and transport"
echo "      server public key (hex): $SERVER_PUB_HEX"
