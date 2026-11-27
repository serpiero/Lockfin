v0.26:
- New vaults and master-password changes use 600,000 PBKDF2 iterations; maximum accepted cost is 2,000,000.
- Older vaults remain readable using their authenticated header cost. Change the vault password to upgrade; an ordinary save keeps the old cost.
- Added an authenticated older-KDF notice and explicit unlock progress requests.
- Momentum 012, 350 entries: maintainer-reported master unlock about 43 seconds plus about 3 seconds to a usable list; Quick PIN effectively instant and does not repeat PBKDF2.
- The maintainer manually confirmed that a dummy 0.25 vault opens in 0.26 with the older-KDF notice. Official screen checks remain pending before catalog submission.
