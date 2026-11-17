# syntax=docker/dockerfile:1
#
# The wallet's command line in a container, for test suites that drive it
# headlessly (id-proto-debugger's OpenID4VP Verifier job, rcbj/id-proto-
# debugger#364). The window (`--ui`) is not used in a container: it needs a
# display. `accept`, `present`, `self-issued` and `credential` run without
# one, without a session bus and without a desktop key ring, when
# OID4VC_WALLET_KEY_FILE names the storage key file (README, "Without a
# window").
#
#   docker build --build-arg GIT_COMMIT=$(git rev-parse HEAD) \
#                -t oid4vc-wallet .
#   docker run --rm oid4vc-wallet --version --json
#
# Both FROM lines are images a mirror can carry: id-proto-debugger builds
# this from a release tag into its private image mirror and resolves each
# FROM against its own copy.

FROM rust:1.95-bookworm AS build

# What CI installs (.github/workflows/ci.yml): the window's libraries are
# linked even by a headless build, and udev and PC/SC by the security-key
# code.
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libudev-dev \
      libpcsclite-dev libgl1-mesa-dev libx11-dev libxcursor-dev \
      libxrandr-dev libxi-dev libxkbcommon-dev libfontconfig1-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# rust-toolchain.toml says `stable`, which rustup would resolve by
# downloading whatever stable is today. The image's own toolchain is the
# one this Dockerfile pins, so the file is set aside for the build.
RUN rm -f rust-toolchain.toml

ARG GIT_COMMIT=""
ARG BUILD_NUMBER=""
ENV GIT_COMMIT=${GIT_COMMIT} BUILD_NUMBER=${BUILD_NUMBER}
RUN cargo build --release --locked --bin oid4vc-wallet \
 && strip target/release/oid4vc-wallet

FROM debian:bookworm-slim

# The shared libraries the binary links, and the CA store rustls-native-certs
# reads. A suite that adds its own root points SSL_CERT_FILE at a bundle
# holding it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libudev1 \
      libpcsclite1 libgl1 libx11-6 libxcursor1 libxrandr2 libxi6 \
      libxkbcommon0 libfontconfig1 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/oid4vc-wallet /usr/local/bin/oid4vc-wallet

# Not root. HOME holds the XDG directories the wallet writes (mode 0700).
RUN useradd --uid 10001 --create-home --home-dir /home/wallet wallet
USER 10001
ENV HOME=/home/wallet \
    OID4VC_WALLET_KEY_FILE=/home/wallet/.local/share/oid4vc-wallet/storage.key

ENTRYPOINT ["/usr/local/bin/oid4vc-wallet"]
CMD ["--help"]
