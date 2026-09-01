#!/usr/bin/env bash
# Package the PyInstaller --onedir bundle (dist/PreScan) as a .deb.
#
# Choice: .deb over AppImage — it is the native Debian/Ubuntu format, so apt/dpkg
# install the launcher and hicolor icons into the system and Qt libraries stay as
# separate replaceable files under /opt/prescan (LGPL §4d), no squashfs to unpack.
#
# Usage: packaging/build-deb.sh [dist/PreScan] [output_dir]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
bundle="${1:-$root/dist/PreScan}"
outdir="${2:-$root/dist}"
# Single source of truth: __version__ in src/prescan/__init__.py (pyproject is dynamic).
version="$(python3 -c 'import re,pathlib; print(re.search(r"__version__ = \"([^\"]+)\"", pathlib.Path("'"$root"'/src/prescan/__init__.py").read_text()).group(1))')"

[ -x "$bundle/prescan" ] || { echo "bundle not found: $bundle (run pyinstaller first)"; exit 1; }

pkg="$(mktemp -d)"
trap 'rm -rf "$pkg"' EXIT

# App payload under /opt/prescan, launcher symlinked onto PATH.
install -d "$pkg/opt/prescan" "$pkg/usr/bin" "$pkg/usr/share/applications"
cp -a "$bundle/." "$pkg/opt/prescan/"
# licenses/ next to the executable (§11.5); PyInstaller can't place it there itself.
cp -r "$root/licenses" "$pkg/opt/prescan/licenses"
ln -s /opt/prescan/prescan "$pkg/usr/bin/prescan"
install -m 0644 "$here/prescan.desktop" "$pkg/usr/share/applications/prescan.desktop"

# Icons into the system hicolor theme.
for size in 16 24 32 48 64 128 256 512; do
    d="$pkg/usr/share/icons/hicolor/${size}x${size}/apps"
    install -d "$d"
    install -m 0644 "$root/src/prescan/resources/icons/prescan_${size}.png" "$d/prescan.png"
done
install -d "$pkg/usr/share/icons/hicolor/scalable/apps"
install -m 0644 "$root/src/prescan/resources/icons/prescan.svg" \
    "$pkg/usr/share/icons/hicolor/scalable/apps/prescan.svg"

# Control metadata. Depends only on glibc; Qt libs ship inside the bundle.
install -d "$pkg/DEBIAN"
size_kb="$(du -sk "$pkg" | cut -f1)"
cat > "$pkg/DEBIAN/control" <<EOF
Package: prescan
Version: ${version}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: PreScan
Installed-Size: ${size_kb}
Depends: libc6, libgl1, libglib2.0-0t64, libegl1, libxkbcommon0, libdbus-1-3
Description: Pre-execution file & link malware scanner
 PreScan checks a file for malware before you run it and inspects a link before
 you download it. Not an antivirus; verdicts are informational.
EOF

mkdir -p "$outdir"
deb="$outdir/prescan_${version}_amd64.deb"
dpkg-deb --root-owner-group --build "$pkg" "$deb"
echo "built $deb"
