#!/usr/bin/env sh
# Bootstrap a Linux build environment for vpn (run inside WSL2/Ubuntu 24.04 or a
# plain Ubuntu 22.04+ host). Idempotent: safe to re-run.
#
#   wsl --install -d Ubuntu-24.04      # from Windows, once
#   sh scripts/bootstrap-wsl.sh
set -eu

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
fi

echo "==> apt packages"
$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
  build-essential gcc-13 g++-13 clang-18 lld-18 \
  cmake ninja-build ccache pkg-config git curl ca-certificates \
  wireguard-tools nftables iproute2 tcpdump gdb \
  postgresql-client redis-tools shellcheck

echo "==> checking versions"
cmake --version | head -n 1
g++-13 --version | head -n 1
clang-18 --version | head -n 1
ninja --version

echo "==> enabling ccache"
if ! grep -q 'CMAKE_CXX_COMPILER_LAUNCHER' "$HOME/.bashrc" 2>/dev/null; then
  cat >>"$HOME/.bashrc" <<'EOF'
export CMAKE_CXX_COMPILER_LAUNCHER=ccache
export CCACHE_DIR="$HOME/.cache/ccache"
export CCACHE_MAXSIZE=5G
EOF
fi

cat <<'EOF'

==> done. Next:

    # keep the clone on the Linux filesystem, never /mnt/c
    mkdir -p ~/src && cd ~/src && git clone <remote> vpn && cd vpn
    cmake --preset default
    cmake --build --preset default --parallel "$(nproc)"
    ctest --preset default

Verify the data-plane prerequisites (needed from M2):

    ls -l /dev/net/tun && sudo sysctl net.ipv4.ip_forward
EOF
