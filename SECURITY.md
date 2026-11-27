# Security policy

## Supported versions

Security fixes target the current `hardening` branch, preparing Companion **0.6.9** and Flipper app **0.26**. These versions are unreleased and have not completed physical-device or native Windows/macOS validation. This policy is not a security certification.

| Version | Security maintenance |
|---|---|
| Companion 0.6.9 / Flipper 0.26, current hardening branch | Active security work; validation pending |
| Companion 0.6.8 / Flipper 0.25 and earlier | Migration assistance only; fixes target the current branch |

Older vaults remain readable using the iteration count in their authenticated header. Upgrade both applications before re-encrypting: older Flipper binaries reject the new 600,000-iteration cost. Re-encrypt using `python vault.py passwd <vault.lmv>` or **Manage → Change vault password** on the updated device app. An ordinary device save preserves the stored cost.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/serpiero/Lockfin/security/advisories/new). If that form is unavailable, email **serpieromusic@gmail.com**. Do not open a public issue containing exploit details, real vaults, master passwords, PINs, keys, personal exports or account data.

Include the affected commit/version, firmware and API, host platform, impact and a minimal reproduction using dummy credentials. Share only the minimum information needed to reproduce the problem. The maintainer aims to acknowledge reports within **7 calendar days**; this is an acknowledgment target, not a guaranteed fix deadline. If no acknowledgment arrives, follow up using the other reporting channel. Disclosure timing will be coordinated with the reporter when possible.

## In scope

- Vault encryption integration, KDF parameters, header authentication and LMV parsing.
- Companion import/export parsing and local handling of untrusted input.
- Lockfin USB/BLE typing and transfer behavior.
- Lockfin behavior that exposes plaintext, credentials or cryptographic keys.

## Out of scope

- Bugs in Flipper firmware or independent authentication providers; report these upstream.
- Access already available through an unlocked device or an already unlocked vault.
- A compromised desktop host or modified firmware.
- The absence of a dedicated tamper-resistant secure element.
- Unimplemented roadmap features.

These exclusions do not exclude a new Lockfin vulnerability that adds exposure beyond the documented limitations. Please report uncertain cases privately.

## Credit, rewards and safe harbor

With the reporter's permission, release notes and advisories will credit the name or handle they choose. Anonymous reporting is welcome. There is **no bounty program or promised financial reward**.

Good-faith research on your own devices, accounts and dummy vaults, or systems whose owners explicitly authorized testing, is welcome. Avoid privacy violations, disruption, persistence and access to other people's data; stop if unexpected sensitive data appears and report the issue privately. The maintainer will not initiate legal action for research conducted within these conditions. This commitment covers only the maintainer's own actions and cannot authorize testing of third-party services or bind other parties.
