# Lockfin

Lockfin is a standalone encrypted password manager for Flipper Zero. Install the build matching your firmware (Momentum 012 API 87.1 or official 1.5.1 API 88.2) at `/ext/apps/Tools/lockfin.fap`. At first launch choose **Create vault** and set your password on the device. On subsequent launches unlock to see your accounts. Select an account for username, password, Shift+Tab, Enter or Tab. Hold OK for management, password changes and controls.

The English desktop companion imports Bitwarden JSON (including Password protected PBKDF2 or Argon2id exports), common CSV/TSV, KeePass XML, legacy TXT, 1PUX, Dashlane ZIP and existing LMV vaults. Account restricted Bitwarden exports require the originating account. Drop a file or double-click the plus, select accounts, and save an encrypted vault. Open an existing vault and choose **Change vault password** to re-encrypt that local file.

Start the Linux x86_64 AppImage or use Python 3.10+ and the launcher in a platform ZIP. Run `python start.py --test` for host tests from the source project. Linux has been tested locally. Windows and macOS packages include Python source and launchers and require validation on those platforms.

## Quick PIN (Momentum)

Unlock with the vault password and hold OK, then choose **Set quick PIN**. Enter and confirm six digits on the Flipper. On later launches Back at the PIN prompt uses the vault password. Three failed PIN attempts disable quick unlock until you enroll again. The PIN is visible while entered on the device. The cached key is authenticated and encrypted using the PIN and a secret derived from the device-unique key. The internal record is separate from the SD vault. Re-enroll after replacing or re-encrypting the vault with a different salt. **Remove quick PIN** disables it.

Renaming a file preserves its encrypted content. The device opens exactly `/ext/apps_data/lockfin/vault.lmv`. New manual PC saves default to Documents/Lockfin.

## Accounts and second factors (Momentum)

The list shows the account name and username together. Inside an account, hold Right to open U2F or hold Down to open Flipper Authenticator (install the catalog app at `/ext/apps/Tools/totp.fap`). Register the Flipper with the website for U2F, or enroll the matching token in Authenticator. When you exit the second-factor app, Momentum returns to the same login and action using a one-time authenticated ticket. A normal launch, reboot, or changed vault requires a fresh unlock. These shortcuts do not send usernames, passwords or token seeds between apps.

Use a generated master password, for example 21 random printable characters including letters, digits and symbols. Keep it in a recoverable location. The six-digit PIN is a device-bound convenience credential with a three-attempt limit. Back from the master password screen offers Quick PIN or Exit when PIN unlock is still available.

## USB and Bluetooth keyboards

Connection defaults to **Auto (USB first)**. A ready USB keyboard takes priority over a paired BLE host. Each action stays on one connection and stops if that connection drops. For a fixed destination, hold OK and choose **Connection → USB** or **BLE**. Pair the Lockfin keyboard on your host and confirm the pairing code to use BLE. The login header shows the current keyboard route. Passkeys and U2F use their own USB apps. Vault backups use USB. Locking or exiting restores the original profiles.

## Device backups

With qFlipper and the device app closed, connect one Flipper via USB. The Companion checks for Lockfin on Momentum 012 and offers installation only if the app is missing. **Not now** remembers that decision for this device and FAP release. Existing installations and vaults are preserved. With a supported device connected, creating a new vault offers **Save to Flipper** and **Save to computer…**. Replacing a device vault requires confirmation. The encrypted upload is verified before replacement. **Sync from Flipper** retries detection and saves an encrypted snapshot. Editing a snapshot creates a separate working copy. Switching accounts inside a vault keeps the quick PIN. Replacing or re-encrypting a vault on the PC requires unlocking with its master password and enrolling a PIN again.

## Vault limits

Hold OK on a login and choose **Add favorite** or **Remove favorite**. Starred logins stay at the top and travel inside the encrypted backup. Use Companion 0.6.4 and Lockfin 0.24 or newer to open a vault containing favorites. Both also open existing LMV1 vaults.

Tap Left in the account list to jump to a letter. The index uses the displayed site name, so www.google.com appears under G.

LMV1 uses AES-256-GCM and PBKDF2-HMAC-SHA256 (100,000 iterations). The device allocates space as accounts are added, up to 500 accounts. Each field holds up to 99 bytes. The plaintext payload limit is 32 KiB. The master password accepts 8–63 printable ASCII characters. USB and BLE default to US English. In Manage → Keyboard layout, choose the active host layout for Spanish (Spain) or Spanish (Latin America). The selection is saved on the SD card. Typing supports printable ASCII. Flipper text entry shows characters while editing.

## Attribution

Unofficial third-party tool, not affiliated with Flipper Devices Inc.

The grid animation is adapted from qFlipper. The upstream component, notices and license are in `third_party/qflipper`. Bundled fonts and their notices are in `assets/fonts`. The project license is in `LICENSE`.

### USB passkeys
Install Lockfin in `/ext/apps/Tools/lockfin.fap` and FIDO2 Security Key in
`/ext/apps/USB/fido2_security_key.fap`. Tap Right for **Passkeys** in the unlocked account list or on page 2/2 inside a login. Holding Right inside an account still opens U2F.
Connect USB and follow the site's security-key registration or sign-in prompt.
The FIDO2 client PIN is managed by the authenticator and is separate from the vault PIN.
Passkeys are registered per site and are stored by the provider, separately from the LMV vault.
Keep the firmware's existing `/ext/u2f` data. For a replacement authenticator, keep another sign-in method.
The experimental provider supports up to eight resident credentials.
Provider by Ege Guray Ertan, GPL-3.0, built with the Momentum SDK from
[Dospacite/flipperzero-fido2](https://github.com/Dospacite/flipperzero-fido2/tree/a9e7638ba8e8dca0a596d7182d5d2ed77654e7ff).
The TOTP shortcut opens [Flipper Authenticator by akopachov and contributors](https://github.com/akopachov/flipper-zero_authenticator).
