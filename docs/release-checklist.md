# Release checklist

How to cut the next PreScan release. The tag build (`.github/workflows/build.yml`)
does the heavy lifting — it builds both platforms and publishes the release itself.
Your job is the four steps below, in order.

Assume the new version is `X.Y.Z` (e.g. `0.2.0`). The tag is always `vX.Y.Z`.

## 1. Bump the version

Edit the single source of truth:

- `src/prescan/__init__.py` → `__version__ = "X.Y.Z"`

Everything (artifact names, installer version, `prescan version`) derives from this.
The `guard` job fails the tag build early if the tag ≠ `v` + `__version__`, so a
forgotten bump is caught before the ~15 min build — but bump it here first.

## 2. Write the release notes

Create `docs/release-notes/vX.Y.Z.md`. The publish job passes it verbatim to
`gh release create --notes-file`, so the filename **must** match the tag exactly
(`v${tag#v}.md`). Copy the previous version's file and update it; keep the required
parts: one-line description, the §11.4 "not an antivirus" disclaimer, supported
platforms, per-OS install (including the AppImage GL/GLib dependency note), the
separate `prescan update-model` step, optional ClamAV, the non-commercial API-key
caveat, MIT + bundled `licenses/`, and the `SHA256SUMS` verification line.

Commit steps 1 and 2 to `main` and push.

## 3. Tag and push

```bash
git tag -a vX.Y.Z -m "PreScan X.Y.Z"
git push origin vX.Y.Z
```

The tag push triggers `build.yml`. Wait for **all four jobs** green:

- `tag/version guard`
- `build (ubuntu-24.04)`
- `build (windows-2022)`
- `publish release`

## 4. Verify the published release

- Exactly **four** assets: `prescan_X.Y.Z_amd64.deb`, `PreScan-X.Y.Z-x86_64.AppImage`,
  `PreScan-Setup-X.Y.Z.exe`, `SHA256SUMS`.
- `SHA256SUMS` lists **bare filenames** (no paths), so `sha256sum -c SHA256SUMS`
  works for a user who downloaded the three files into one folder.
- `gh release list`: `vX.Y.Z` is `latest`; the model release (`model-ember2024-v1`)
  stays **not** latest — publishing must not hijack the pinned model download.
- Fact-check the model path: in a clean `ubuntu:24.04`, install the released `.deb`,
  run `prescan update-model`, and confirm `prescan engines` shows `ml  ready  model available`.

## Non-negotiable

- **Published assets are never replaced.** The build is not reproducible (PyInstaller),
  and `SHA256SUMS` is frozen from the first build; overwriting an asset would break
  every downloader's checksum. A re-run of the same tag is a safe no-op by design.
- **A tag is never re-pointed once its release is published.** `vX.Y.Z` is immutable.
  If a published build is broken, cut the next version (`vX.Y.Z+1`) — do not retag.
- The model (`model.onnx`) ships as its own pinned release, never in the app release
  and never committed to the repo.
