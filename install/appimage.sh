#!/bin/sh
# Build a self-contained x86_64 AppImage of oid4vc-wallet.
#
# The image contains the wallet and every library it needs besides the
# system C library. The result uses the glibc of the machine that builds it.
# GitHub Actions builds on Ubuntu 22.04, so that artifact runs on Ubuntu 22.04
# and newer.
set -eu

cd "$(dirname "$0")/.."

if [ "$(uname -m)" != "x86_64" ]; then
    echo "oid4vc-wallet AppImage builds are x86_64" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    echo "cargo and curl are required" >&2
    exit 1
fi

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
if [ -z "$version" ]; then
    echo "could not read the version from Cargo.toml" >&2
    exit 1
fi

cargo build --release

binary="target/release/oid4vc-wallet"
if ldd "$binary" | grep -q "not found"; then
    echo "the release binary is missing a shared library" >&2
    ldd "$binary" >&2
    exit 1
fi

appdir="target/appimage/OID4VC_Wallet.AppDir"
rm -rf "$appdir"
mkdir -p "$appdir/usr/bin" "$appdir/usr/lib" \
    "$appdir/usr/share/applications" \
    "$appdir/usr/share/icons/hicolor/256x256/apps"

cp "$binary" "$appdir/usr/bin/oid4vc-wallet"
if command -v strip >/dev/null 2>&1; then
    strip --strip-unneeded "$appdir/usr/bin/oid4vc-wallet"
fi
chmod 755 "$appdir/usr/bin/oid4vc-wallet"

# Keep libraries other than the C library next to the binary. glibc stays
# on the system; it has to match the kernel's dynamic linker.
ldd "$binary" | while IFS= read -r line; do
    case $line in
        *linux-vdso* | *ld-linux*) continue ;;
    esac
    lib=$(printf "%s\n" "$line" | sed -n "s/.* => \\([^ ]*\\) (.*/\\1/p")
    if [ -z "$lib" ] || [ ! -f "$lib" ]; then
        continue
    fi
    base=$(basename "$lib")
    case $base in
        libc.so* | libm.so* | libpthread.so* | libdl.so* | librt.so* | libresolv.so*)
            continue
            ;;
    esac
    cp -L "$lib" "$appdir/usr/lib/$base"
done

cat > "$appdir/AppRun" <<'EOF'
#!/bin/sh
set -eu
here=$(dirname "$(readlink -f "$0")")
if [ -n "${LD_LIBRARY_PATH:-}" ]; then
    LD_LIBRARY_PATH="$here/usr/lib:$LD_LIBRARY_PATH"
else
    LD_LIBRARY_PATH="$here/usr/lib"
fi
export LD_LIBRARY_PATH
exec "$here/usr/bin/oid4vc-wallet" "$@"
EOF
chmod 755 "$appdir/AppRun"

cp install/org.rcbj.oid4vc-wallet.png "$appdir/org.rcbj.oid4vc-wallet.png"
cp install/org.rcbj.oid4vc-wallet.png "$appdir/.DirIcon"
cp install/org.rcbj.oid4vc-wallet.png \
    "$appdir/usr/share/icons/hicolor/256x256/apps/org.rcbj.oid4vc-wallet.png"

cat > "$appdir/org.rcbj.oid4vc-wallet.desktop" <<'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=OID4VC Wallet
GenericName=Verifiable Credential Wallet
Comment=Accept OpenID4VCI credential offers and OpenID4VP and SIOPv2 requests
Exec=oid4vc-wallet %u
Icon=org.rcbj.oid4vc-wallet
Terminal=true
Categories=Network;Security;System;
MimeType=x-scheme-handler/openid-credential-offer;x-scheme-handler/siopv2;x-scheme-handler/openid4vp;
StartupNotify=true
EOF
cp "$appdir/org.rcbj.oid4vc-wallet.desktop" \
    "$appdir/usr/share/applications/org.rcbj.oid4vc-wallet.desktop"

tool_dir="target/appimage/tools"
mkdir -p "$tool_dir"
fetch() {
    dest=$1
    url=$2
    sum=$3
    if [ -f "$dest" ] && echo "$sum  $dest" | sha256sum -c - >/dev/null 2>&1; then
        return 0
    fi
    curl -fsSL -o "$dest.partial" "$url"
    echo "$sum  $dest.partial" | sha256sum -c -
    mv "$dest.partial" "$dest"
    chmod 755 "$dest"
}
# AppImage/appimagetool 1.9.1, the static x86_64 binary.
fetch "$tool_dir/appimagetool" \
    "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage" \
    "ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
# AppImage/type2-runtime 20251108. appimagetool would otherwise download
# whatever "continuous" points at.
fetch "$tool_dir/runtime-x86_64" \
    "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64" \
    "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"

mkdir -p dist
out="dist/OID4VC_Wallet-${version}-x86_64.AppImage"
rm -f "$out"
ARCH=x86_64 VERSION="$version" "$tool_dir/appimagetool" \
    --runtime-file "$tool_dir/runtime-x86_64" \
    --no-appstream \
    "$appdir" "$out"
chmod 755 "$out"

# The runtime can extract the image when FUSE is not available.
help_text=$(APPIMAGE_EXTRACT_AND_RUN=1 "$out" --lang en help)
printf "%s\n" "$help_text" | grep -q "OpenID4VCI"
echo "wrote $out"
