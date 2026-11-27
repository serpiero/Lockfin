# Device validation: Lockfin 0.26 / Companion 0.6.9

## Timing and profiling

The maintainer reports Momentum 012 with 350 entries: 43 s master-password unlock plus 3 s to a usable list; Quick PIN effectively instant. These observations are not a claimed three-run median.

A separate probe ran the real current C loader and list-index functions on physical Momentum 012, using isolated synthetic 600,000-iteration vaults and a supplied fixture key to exclude PBKDF2. The tick frequency was 1,000 Hz. No personal vault, PIN file, keyboard pairing or firmware was modified.

| Entries | SD/header read ms | GCM ms | Parse/load completion ms | Display index ms |
|---|---:|---:|---:|---:|
| 1 | 15 | 0 | 1 | 0 |
| 350 | 28 | 14 | 59 | 305 |
| 500 | 36 | 20 | 96 | 458 |

A single Shell sort builds the alphabetical display index; comparisons repeatedly derive site labels. Necessary first-open indexing is not a duplicate sort. The synthetic measurements account for about 0.4 s at 350 entries, so they do not establish the cause of the full reported 3 s gap. Keyboard startup and the full interactive transition were excluded. Optimization is deferred rather than changing ordering, memory use or account selection without adequate evidence.

## Feedback checks

| Firmware/path | Result and evidence |
|---|---|
| Momentum 012, master password | Animation reported working by the maintainer; independent immediate/terminal-frame screen verification pending. Source inspection found no explicit 100% update; 0.26 now submits a terminal 100% frame with a 50 ms display interval. |
| Momentum 012, Quick PIN | Effectively instant per maintainer. No PBKDF2 or percentage animation is involved; a brief loading view is requested. Independent screen verification pending. |
| Official 1.5.1, master password | Builds successfully; physical screen test not performed on this Momentum device. |
| Official 1.5.1, Quick PIN | Builds successfully; physical screen test not performed. The PIN route does not derive a PBKDF2 key. |

No unperformed physical check is marked PASS. Back cancellation: the derivation has no input callback or cancellation poll, so Back does not cancel PBKDF2. This is a code-level finding; a separate interactive physical Back test remains manual. Do not flash firmware or overwrite a personal vault to obtain these results.

## Legacy check

**PASS, manually confirmed by the maintainer on 2026-11-26:** a dummy vault created by Lockfin 0.25 opens in 0.26 and displays the older-KDF notice. This is a human-reported physical-device result; it is separate from the synthetic desktop tests and the earlier incomplete USB probe. No claim is made here about typing credentials or physical screen validation on Official firmware.
