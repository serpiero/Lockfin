# Changelog

## Companion 0.6.9 / Flipper 0.26 — unreleased

### Security and migration

- New vaults and master-password changes use 600,000 PBKDF2-HMAC-SHA256 iterations; readers accept up to 2,000,000. The LMV1/LMV2 layout and authenticated 40-byte header are unchanged.
- Existing vaults keep opening because their iteration count is read from the header. To migrate, update both applications and run `python vault.py passwd <vault.lmv>` or choose **Manage → Change vault password** on the updated Flipper. An ordinary device save **preserves the old cost**; it does not re-encrypt at 600,000 iterations. Older app binaries reject costs above 500,000.
- The device shows an older-KDF notice after successful master-password or Quick PIN unlock. Master derivation requests percentage progress; Quick PIN requests a loading state while unwrapping the device-bound key. It does not repeat PBKDF2.
- Momentum 012 physical unlock medians: master password **<X> s**, Quick PIN **<Y> s**, three runs each. These are **unmeasured placeholders**. Physical progress visibility on Momentum 012 and Official 1.5.1, and opening a dummy vault actually created by 0.25, are still pending.
- Runtime and PyInstaller dependencies are pinned with SHA256 hashes; uFBT is installed separately for FAP builds.
- Vault and backup directories are restricted to mode 0700 on POSIX, including existing directories. Locking drops the Companion's references to decrypted records and the master password; Python immutable strings are not securely erased.
- Added a private reporting policy, explicit security limitations, and CI self-tests, compilation checks and history-wide secret scanning.

### Packaging

- Rebuilt Flipper 0.26 for Momentum 012 / API 87.1 and Official 1.5.1 / API 88.2 from the updated source.
- Companion 0.6.9 Linux AppImage and hash-locked Python source ZIPs were prepared locally. Windows and macOS native builds and device timing remain release gates.
