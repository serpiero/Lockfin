v0.26:
- New vaults and master-password changes use 600,000 PBKDF2 iterations; maximum accepted cost is 2,000,000.
- Older vaults remain readable using their authenticated header cost. Change the vault password to upgrade; an ordinary save keeps the old cost.
- Added an authenticated older-KDF notice and explicit unlock progress requests.
- Momentum physical medians remain unmeasured: master password <X> s; Quick PIN <Y> s, three runs each. Quick PIN does not repeat PBKDF2.
- Physical screen verification and opening a dummy vault created by 0.25 are pending before submission.
