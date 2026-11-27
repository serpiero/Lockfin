# Lockfin

An encrypted login vault for Flipper Zero. Choose an account on the device and explicitly type its username or password over USB or BLE. Add and edit entries, generate passwords and mark favorites on the Flipper. Companion can import selected logins and transfer an encrypted vault.

## Using the app

Open Apps → Tools → Lockfin. Create a vault with your own master password or open one saved from Companion. Quick PIN is optional and device-bound. Keep an independent encrypted backup. Select the destination field on your computer before typing; use Tab, Shift+Tab and Enter only when you choose them.

## Security and integrations

New vaults use AES-256-GCM with PBKDF2-HMAC-SHA256 at 600,000 iterations. The SD filesystem itself is unencrypted. Flipper has no dedicated tamper-resistant secure element, and an unlocked host or modified firmware can expose credentials. Quick PIN is six digits, visible during entry, with three failed attempts per enrollment.

Authenticator, U2F and experimental FIDO2 are separate apps with separate credentials. Their shortcuts are conveniences, not additional hardened authentication. Do not use Lockfin as your only vault for banking, primary email or a domain registrar.

[Full documentation](https://github.com/serpiero/Lockfin/tree/hardening) · [Private security reports](https://github.com/serpiero/Lockfin/blob/hardening/SECURITY.md)

Unofficial third-party tool, not affiliated with Flipper Devices Inc. GPL-3.0.
