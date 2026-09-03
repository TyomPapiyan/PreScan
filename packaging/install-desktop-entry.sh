#!/usr/bin/env bash
# Install the PreScan launcher and icons for the current user (no sudo).
#
# Puts prescan.desktop in ~/.local/share/applications and the shield icon into the
# hicolor theme so GNOME/KDE show "PreScan" with the shield instead of "python3"
# with a gear. Run once after `pip install .` (or a source checkout). Uninstall by
# deleting the files it prints.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
icons_src="$here/../src/prescan/resources/icons"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
apps_dir="$data_home/applications"
hicolor="$data_home/icons/hicolor"

mkdir -p "$apps_dir"

# The installed entry must launch with an absolute command that the system can
# resolve. Two reasons the bare "Exec=prescan" fails on a source/venv install:
#   1. the venv's bin is only on PATH while the venv is active, so GLib/GNOME cannot
#      resolve the entry -- Gio.DesktopAppInfo.new returns NULL, gtk-launch says "no
#      such application", the window is never matched to this .desktop, and the shell
#      shows the raw app-id with a generic gear;
#   2. the "prescan" console script is the CLI (shows --help on no args); the GUI is
#      "python -m prescan".
# So bake in the absolute venv python and launch the module. The file in packaging/
# keeps Exec=prescan for the .deb, where /usr/bin/prescan is the GUI-dispatching
# bundle and is a real command on PATH.
py="$(python3 -c 'import sys, importlib.util as u; print(sys.executable if u.find_spec("prescan") else "")' 2>/dev/null || true)"
if [ -z "${py:-}" ] || [ ! -x "$py" ]; then
    echo "error: could not find a python with 'prescan' importable." >&2
    echo "  Activate the venv and run 'pip install -e .' first, then re-run this." >&2
    exit 1
fi
sed "s|^Exec=prescan\$|Exec=$py -m prescan|" "$here/prescan.desktop" > "$apps_dir/prescan.desktop"
chmod 0644 "$apps_dir/prescan.desktop"
echo "installed $apps_dir/prescan.desktop (Exec=$py -m prescan)"

for size in 16 24 32 48 64 128 256 512; do
    dest="$hicolor/${size}x${size}/apps"
    mkdir -p "$dest"
    install -m 0644 "$icons_src/prescan_${size}.png" "$dest/prescan.png"
done
scalable="$hicolor/scalable/apps"
mkdir -p "$scalable"
install -m 0644 "$icons_src/prescan.svg" "$scalable/prescan.svg"
echo "installed hicolor icons (16-512 + scalable) under $hicolor"

# Refresh the caches so the shell picks the entry/icon up immediately (best effort).
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$apps_dir" || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$hicolor" || true

echo "done — PreScan should now appear in the application menu / dock."
