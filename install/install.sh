#!/bin/sh
# Build the wallet and register its protocol handlers with this user.
# Pass --system to install for every user (needs root). Pass --haip to also
# register haip-vci:// and haip-vp://.
set -eu
cd "$(dirname "$0")/.."
cargo build --release
exec ./target/release/oid4vc-wallet install "$@"
