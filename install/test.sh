#!/bin/sh
# Headless suite for this wallet. GitHub Actions runs this same script.
#
# The suite does not open a window. It also does not read or write this
# user's wallet files, language choice, trust anchors, desktop key store, or YubiKeys.
# A temporary home is used for the whole run. The Secret Service and KWallet
# live-bus checks skip, because this script does not connect to the session bus.
#
#   ./install/test.sh
#   ./install/test.sh --offline
#   ./install/test.sh wallet::present
#   ./install/test.sh --offline wallet::present
set -eu
cd "$(dirname "$0")/.."

# rustup keeps the toolchain under the real home. Point at it before HOME changes.
real_home=${HOME:-}
if [ -n "$real_home" ]; then
  if [ -z "${CARGO_HOME:-}" ]; then
    CARGO_HOME="$real_home/.cargo"
    export CARGO_HOME
  fi
  if [ -z "${RUSTUP_HOME:-}" ]; then
    RUSTUP_HOME="$real_home/.rustup"
    export RUSTUP_HOME
  fi
fi
if [ -n "${CARGO_HOME:-}" ] && [ -d "$CARGO_HOME/bin" ]; then
  PATH="$CARGO_HOME/bin:$PATH"
  export PATH
fi

offline=
if [ "${1:-}" = "--offline" ]; then
  offline=--offline
  shift
fi

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT INT TERM
mkdir -p "$root/home" "$root/config" "$root/data" "$root/cache" "$root/runtime"
chmod 700 "$root/home" "$root/config" "$root/data" "$root/cache" "$root/runtime"
export HOME="$root/home"
export XDG_CONFIG_HOME="$root/config"
export XDG_DATA_HOME="$root/data"
export XDG_CACHE_HOME="$root/cache"
export XDG_RUNTIME_DIR="$root/runtime"
unset DBUS_SESSION_BUS_ADDRESS
unset DISPLAY
unset WAYLAND_DISPLAY

# shellcheck disable=SC2086
cargo test $offline --all-targets -- "$@"
# shellcheck disable=SC2086
cargo clippy $offline --all-targets -- -D warnings
