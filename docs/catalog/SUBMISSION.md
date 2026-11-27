# Apps Catalog preparation — not submitted

Checked **2026-11-26** against catalog revision `8d91e3cbec94cb9ee451552318b1fc56e265bbca`:
[contribution guide](https://github.com/flipperdevices/flipper-application-catalog/blob/8d91e3cbec94cb9ee451552318b1fc56e265bbca/documentation/Contributing.md), [manifest schema and validator](https://github.com/flipperdevices/flipper-application-catalog/blob/8d91e3cbec94cb9ee451552318b1fc56e265bbca/documentation/Manifest.md). Recheck these before submitting.

## Prepared

- Public GPL-3.0 source and stable app ID `lockfin`, category `Tools`, version `0.26`; no tracked `lockfin` entry was found in the current catalog tree. This does not reserve the ID.
- `application.fam` includes author, source URL, description and icon. Terminal inspection confirms the existing icon is a 10×10, 1-bit grayscale PNG.
- Official 1.5.1 / API 88.2 and Momentum 012 / API 87.1 builds passed. The official firmware index lists 1.5.1 as its current release; verify again at submission time.
- A short catalog description without the main README's tables/videos, a device-only version changelog, and `manifest.yml.in` are prepared here. The template deliberately cannot be submitted as-is.

## Still missing

1. **A real, unmodified qFlipper screenshot** of a dummy vault. Do not use personal credentials. Keep its original PNG dimensions/format. None was captured or inspected during this task. Once supplied, add that exact public file explicitly to Git with an equally narrow ignore exception; personal screenshot directories remain excluded.
2. **Remaining physical checks:** Official-firmware screen behavior and interactive Back behavior; repeat runs if median timing statistics are desired. The maintainer already reports 43 s master unlock plus 3 s to a usable list at 350 entries on Momentum, effectively instant Quick PIN, and a successful manual 0.25-to-0.26 vault open with its migration notice. These are observations, not three-run medians.
3. **A final source commit** containing the approved screenshot and completed checks. Replace the two template placeholders, preserving a full 40-character source SHA. Commit the source assets first; the catalog manifest must point to that commit, not a moving branch or an invented release tag.
4. **Upstream validation:** in an isolated checkout of the catalog, install its tooling in a separate environment, set `UFBT_HOME` to that environment, put the completed manifest at `applications/Tools/lockfin/manifest.yml`, then run `python tools/bundle.py --nolint applications/Tools/lockfin/manifest.yml bundle.zip`. No validation success is claimed while required assets/placeholders are missing. Review formatting separately; `--nolint` skips linting.
5. **Final policy and app review:** confirm the current firmware release/RC still builds, preserve third-party notices, check catalog content/trademark rules, and make sure author notifications will be monitored. The catalog may contact the author and requires timely responses.

The manifest is the only file intended for a future catalog PR; application assets stay in this source repository. No fork, catalog PR, submission, main-branch merge or release publication has been performed. Sending the catalog PR is a separate future action.
