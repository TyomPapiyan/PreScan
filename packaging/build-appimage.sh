#!/usr/bin/env bash
# Package the PyInstaller --onedir bundle (dist/PreScan) as an AppImage.
#
# The AppImage mounts a squashfs at run time -- it does NOT unpack into a single
# executable, so §11.3's --onefile ban is not violated and the Qt libraries stay
# separate replaceable files inside the image. Build only in CI (glibc comes from
# the build host); local runs are for debugging.
#
# Usage: packaging/build-appimage.sh [dist/PreScan] [output_dir]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
bundle="${1:-$root/dist/PreScan}"
outdir="${2:-$root/dist}"
version="$(python3 -c 'import re,pathlib; print(re.search(r"__version__ = \"([^\"]+)\"", pathlib.Path("'"$root"'/src/prescan/__init__.py").read_text()).group(1))')"

[ -x "$bundle/prescan" ] || { echo "bundle not found: $bundle (run pyinstaller first)"; exit 1; }

appdir="$(mktemp -d)/PreScan.AppDir"
trap 'rm -rf "$(dirname "$appdir")"' EXIT
mkdir -p "$appdir/usr/bin" "$appdir/usr/share/applications" \
         "$appdir/usr/share/icons/hicolor/256x256/apps"

# The whole onedir bundle under usr/bin; AppRun launches it.
cp -a "$bundle" "$appdir/usr/bin/PreScan"
# licenses/ ship inside the image (§11.5); done here, not in the workflow, so a
# distribution without licenses cannot be built.
cp -r "$root/licenses" "$appdir/usr/bin/PreScan/licenses"
cat > "$appdir/AppRun" <<'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/PreScan/prescan" "$@"
EOF
chmod +x "$appdir/AppRun"

# appimagetool wants the .desktop and icon at the AppDir root (mirrored under usr/share).
install -m 0644 "$here/prescan.desktop" "$appdir/prescan.desktop"
install -m 0644 "$here/prescan.desktop" "$appdir/usr/share/applications/prescan.desktop"
install -m 0644 "$root/src/prescan/resources/icons/prescan_256.png" "$appdir/prescan.png"
install -m 0644 "$root/src/prescan/resources/icons/prescan_256.png" \
    "$appdir/usr/share/icons/hicolor/256x256/apps/prescan.png"

# Fetch the (static) appimagetool once.
tool="${APPIMAGETOOL:-/tmp/appimagetool-x86_64.AppImage}"
if [ ! -x "$tool" ]; then
    curl -fsSL -o "$tool" \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
    chmod +x "$tool"
fi

mkdir -p "$outdir"
out="$outdir/PreScan-${version}-x86_64.AppImage"
# --appimage-extract-and-run: no FUSE needed on CI runners.
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$tool" --appimage-extract-and-run \
    --no-appstream "$appdir" "$out"
echo "built $out"
