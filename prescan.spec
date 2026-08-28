# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for PreScan.

Placeholder for M0. The real --onedir build is defined on M7 (spec §11, §12).
--onefile is forbidden: Qt shared libraries must remain separate files so the
user can replace them (LGPLv3 §4d).
"""

# TODO(M7): Analysis / PYZ / EXE / COLLECT for a --onedir build, bundling
# ui/vendor/RinUI, resources/, qml/, i18n .qm catalogs and the licenses/ folder.
