# Lockfin

**Your all-in-one login and password manager for Flipper Zero.**

Passwords · Authenticator · U2F · Passkeys (FIDO2)

Keep your logins on your Flipper Zero. Add an account, generate a password, and mark it as a favorite right on the device. When you need to sign in, pick the account and let your Flipper type the username and password over USB or Bluetooth.

**Watch Lockfin on the Flipper · 1:11**

https://github.com/user-attachments/assets/071d6a79-2f23-46e4-b461-c0cb41be5e99

Manage passwords on the device, type over USB or Bluetooth, and open Authenticator, U2F or **Passkeys (FIDO2)** from Lockfin when you need another sign-in step. Passwords and authentication shortcuts come together in one sign-in workflow; authentication credentials remain with their own apps. See [Authentication integrations](#authentication-integrations) for setup.

Already have your passwords somewhere else? **Lockfin Companion** helps you install Lockfin, bring in the accounts you choose, and save them to your Flipper. You can add them to an existing vault and keep your other logins and favorites.

[Download Lockfin and Companion](https://github.com/serpiero/Lockfin/releases/tag/v0.6.8)

## Support Lockfin

Lockfin is my first app for Flipper Zero. If it’s earned a place on your Flipper, I’d really appreciate a star on GitHub. And if you know someone who would enjoy using their Flipper this way, sharing the project with them helps more people find it. [Star Lockfin on GitHub](https://github.com/serpiero/Lockfin)

## Get started

**Watch the Companion workflow · 1:05**

https://github.com/user-attachments/assets/fe3b1efd-c46f-46c8-9492-eb344eb8e397

**With Companion.** Close qFlipper if it’s open, connect your Flipper to your computer over USB, and launch Lockfin Companion. If Companion offers to install Lockfin, follow the prompt. For a new vault, drop an export into Companion, select the logins you want, and choose **Save encrypted vault**. Set its master password, then choose **Save to Flipper**. To keep the accounts already on your Flipper, follow [Add accounts to your existing Flipper vault](#add-accounts-to-your-existing-flipper-vault) below.

**On the Flipper.** Once Lockfin is installed, open **Apps → Tools → Lockfin**. Choose **Create vault**, set your own master password, and add your first login. If you saved a vault from Companion, unlock it with its existing master password. After unlocking, hold **OK** and choose **Set quick PIN** to set a six-digit PIN, so you do not have to enter the master password every time you open Lockfin on that device. Your master password remains the fallback.

**Try your first login.** Connect the Flipper to your computer and click the username field on a sign-in page. Open the account on your Flipper, select **Username**, and press **OK**. Choose **Tab** to move to the next field, then **Password** to type your password. You decide when to press **Enter**.

## What you can do

| On your Flipper | With Companion |
|---|---|
| Add and edit logins wherever you are. | Import selected accounts from a password-manager export. |
| Generate a password, adjust its options, or generate another before saving. | Open your Flipper vault and add accounts while keeping existing entries and favorites. |
| Pin favorites to the top or jump to a login by its first letter. | Save an encrypted vault to your Flipper or computer. |
| Type usernames and passwords over USB or a paired Bluetooth connection. | Back up your device vault over USB and edit a separate working copy. |
| Unlock with your master password or set up a six-digit Quick PIN where supported. | Keep multiple vault files and change the master password for an individual file. |

### Your vaults

One vault can hold up to **500 logins**, within the storage limit described below. You can also create separate encrypted vault files, each with its own master password. *Personal* and *Work* are two examples. Keeping everything in one vault works too.

The Flipper currently opens **one active vault**. To switch, back up the current vault and use Companion to save the other one to the device. Companion asks before replacing the active vault and verifies the encrypted upload. Quick PIN belongs to the device and its active vault. After Companion replaces or re-encrypts the device vault, unlock it with its master password and set up Quick PIN again if you use it.

**In the works:** choose between vaults directly on the Flipper and use the same Quick PIN for all enrolled vaults. Each vault would require verification with its own master password at least the first time you open it, before it could be unlocked with the shared PIN. This is planned functionality, not part of the current release.

### Imports and backups

Companion reads **Bitwarden JSON, KeePass XML, 1Password 1PUX, Dashlane ZIP, CSV/TSV, legacy TXT, and existing Lockfin LMV vaults**. For encrypted Bitwarden exports, choose the *password-protected* export option. Account-restricted Bitwarden exports cannot be opened directly in Companion. Use the originating Bitwarden account to create a new *password-protected* export first.

To make a backup, close qFlipper and the Lockfin device app, connect one Flipper over USB, and choose **Sync from Flipper**. Companion saves an encrypted snapshot. Editing that snapshot creates a separate working copy, so you can return to the original backup.

### Add accounts to your existing Flipper vault

1. Close qFlipper and Lockfin on the device, connect one Flipper over USB, and choose **Sync from Flipper** in Companion.
2. Choose **Open device vault** and enter its existing master password.
3. Click **Add more passwords** to select an export, or drop the export onto that button.
4. Select the new accounts you want, then choose **Save additions to Flipper**.

Companion preserves your existing accounts and favorites while saving the additions with the same master password. The downloaded encrypted snapshot remains a separate backup. Unlock the updated vault on the Flipper with its master password; if you use Quick PIN, set it up again after this save.

## Flipper controls

| Where you are | Button or action | What happens |
|---|---|---|
| Account list | **Up / Down** | Move through your logins. Favorites appear first. |
| Account list | **OK** | Open the selected login. |
| Account list | **Left** | Jump to a letter in the index. |
| Inside a login, page **1/2** | **Directional buttons** | Move between **Username**, **Password**, **Tab**, **Shift+Tab**, **Space**, and **Enter**. Navigation alone does not type anything. |
| Inside a login | **OK** | Type the selected field or send the selected key to the connected computer. |
| Account list or inside a login | **Hold OK** | Open management options, including adding or editing a login and adding or removing a favorite. |
| Password generator | **Use password / Generate again / View / edit / Options** | Keep the result, try another, edit it, or adjust the generator. |
| Inside a login, bottom row of page **1/2** | **Down** | Open shortcut page **2/2**. **Up** or **Back** returns to page **1/2**. |
| Unlocked account list or shortcut page **2/2** | **Tap Right** | Open the external passkey provider. |
| Inside a login | **Hold Right** | Open U2F. |
| Inside a login | **Hold Down** | Open Flipper Authenticator. |
| Quick PIN prompt | **Back** | Switch to the master password. |

**Keyboard connection.** Lockfin defaults to **Auto**, which uses USB first when it is ready. To choose a destination yourself, hold **OK** and select **Connection → USB** or **BLE**. For Bluetooth, pair the Lockfin keyboard with your computer and confirm the pairing code. The login screen shows which connection will receive your keystrokes.

## Authentication integrations

Both the Momentum and official-firmware Lockfin builds include shortcuts to Authenticator, U2F and FIDO2. Lockfin types your login; each authentication app handles its own credentials. Use the firmware’s built-in U2F app, install Flipper Authenticator at `/ext/apps/Tools/totp.fap`, and install FIDO2 Security Key at `/ext/apps/USB/fido2_security_key.fap`. External FAPs must match the firmware and API installed on your Flipper; the presence of a shortcut does not establish compatibility with every provider build. These apps and their credentials are separate from the Lockfin vault.

- **One-time codes.** The shortcut opens **Flipper Authenticator**, by **akopachov and contributors**. Enroll the account’s token in Authenticator to see its code there. [Flipper Authenticator](https://github.com/akopachov/flipper-zero_authenticator)
- **U2F.** The shortcut opens the firmware’s **U2F app**. Register your Flipper as a security key with the website, then connect it over USB when the site asks for it.
- **Passkeys.** The shortcut opens **FIDO2 Security Key**, by **Ege Guray Ertan**. This experimental provider handles passkey registration and sign-in over USB, with support for up to eight resident credentials. It stores its credentials separately from the Lockfin vault and manages its own client PIN. Register it with each site before using it to sign in. [FIDO2 Security Key · GPL-3.0](https://github.com/Dospacite/flipperzero-fido2/tree/a9e7638ba8e8dca0a596d7182d5d2ed77654e7ff)

## Roadmap

- **Switch vaults on the Flipper with a shared Quick PIN.** Choose which vault to unlock directly on the device, so you can move between vaults such as *Personal* and *Work* while away from your computer. The plan is to reuse one Quick PIN across enrolled vaults, requiring each vault’s own master password at least on its first unlock before authorizing PIN access.
- **Install from the official Flipper mobile app.** Prepare Lockfin for submission to the Flipper Apps Catalog.
- **Bring Companion to mobile.** Explore importing accounts and managing vaults from a phone.
- **Test more desktop systems.** Validate the Windows package and test the macOS build on an M1 Mac. Reports from M2, M3, and later Apple Silicon Macs are welcome.
- **Expand firmware compatibility.** Explore support for RogueMaster and Unleashed.

**Want to help test?** A useful report can be one sentence: “On my M2 Mac running [macOS version], Companion opened and detected the Flipper, but saving a test vault failed.” Include your Companion and firmware versions and use dummy logins when reproducing an issue. [Report a test result](https://github.com/serpiero/Lockfin/issues)

## Compatibility and manual installation

**Lockfin 0.25 for Flipper Zero**

| Firmware | API | Release file |
|---|---|---|
| Momentum 012 | 87.1 | `Lockfin-0.25-Momentum-012-API-87.1.fap` |
| Official 1.5.1 | 88.2 | `Lockfin-0.25-Official-1.5.1-API-88.2.fap` |

Companion detects Momentum 012 and Official 1.5.1 and offers the matching Lockfin build when the app is missing. Existing installations are preserved. For manual installation on either firmware, download the matching `.fap` and copy it to the SD card as `/ext/apps/Tools/lockfin.fap`. Both Lockfin builds include the authentication shortcuts described above. Authenticator and FIDO2 require separate provider builds compatible with the selected firmware and API.

**Lockfin Companion 0.6.8**

| Platform | Release file | Status |
|---|---|---|
| Linux x86_64 | `Lockfin-0.6.8-x86_64.AppImage` | Tested locally |
| Windows | `Lockfin-0.6.8-Windows-Python.zip` | Published for testing. Windows validation pending. |
| macOS Apple Silicon | `Lockfin-0.6.8-macOS-Apple-Silicon.app.zip` | Published for testing. macOS validation pending. |

**Launch Companion.** On Linux, make the AppImage executable and run it. On Windows, extract the ZIP and launch `Iniciar.cmd`; Python 3.10 or newer is required, and the launcher prepares a local environment and installs dependencies on first launch. On macOS Apple Silicon, extract the ZIP and open `Lockfin.app`. Windows and macOS launch instructions still need validation on those systems.

The release includes `SHA256SUMS` for checking downloaded files. [Release files](https://github.com/serpiero/Lockfin/releases/tag/v0.6.8)

## Vault and keyboard details

| Setting | Details |
|---|---|
| Active vault on the Flipper | `/ext/apps_data/lockfin/vault.lmv` |
| Vault format | LMV1, or LMV2 when favorites are present; AES-256-GCM and PBKDF2-HMAC-SHA256 with 100,000 iterations |
| Capacity | Up to 500 accounts, 99 bytes per field, and 32 KiB of plaintext payload per vault |
| Master password | 8–63 printable ASCII characters |
| Quick PIN | Six digits. Three failed attempts disable quick unlock until you enroll again. The PIN is visible during entry. |
| Keyboard layouts | US English, Spanish (Spain), and Spanish (Latin America). Choose the layout matching your computer under **Manage → Keyboard layout**. |
| Typed characters | Printable ASCII |

## License and credits

Lockfin is licensed under [GPL-3.0](https://github.com/serpiero/Lockfin/blob/main/LICENSE).

**qFlipper** inspired the Companion’s grid, typography, and button styling. The animated grid is adapted from qFlipper. The repository includes the [qFlipper component and license notices](https://github.com/serpiero/Lockfin/tree/main/third_party/qflipper) and the [bundled font licenses](https://github.com/serpiero/Lockfin/tree/main/assets/fonts).

Unofficial third-party tool, not affiliated with Flipper Devices Inc.
