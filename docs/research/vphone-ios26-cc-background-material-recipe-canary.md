# iOS 26 Control Center background material-recipe canary

Status: VM redirect and rollback proved on 2026-10-11; visible tint rejected.

This experiment tested the narrow first-stage Lemin/PureKFD color route on the
visible `cyanide-ios26-base` vPhone running iOS 26.0 (`23A341`). It targeted
only:

```text
/System/Library/PrivateFrameworks/CoreMaterial.framework/modulesBackground.materialrecipe
```

No physical device was used. The canary is build-locked to `23A341`, checks
for the vPhone model, requires the Cyanide process identity, and consumes a
nonce-bound host request. It does not modify the sealed system file. It pins a
device-native payload vnode, redirects the target name-cache entry in memory,
verifies exact readback, and journals enough identity to restore the original
entry and release both vnode pins.

## Result

The plumbing worked, but this legacy recipe did not tint iOS 26 Control
Center.

- Stock target: 343 bytes, SHA-256
  `0df75fb8a3483414ba3423cff08a949039b2558bf07501f20ceba36aed659d56`.
- Purple payload: 343 bytes, SHA-256
  `00144e2ca64311c63c666b1f6dbe1f2f8064ab7d380516baa144f86519d5b0df`.
- Apply changed the live path from the stock vnode to the payload vnode and
  read back the payload hash exactly.
- SpringBoard restarted from PID 1038 to PID 1080.
- Restore changed the live path back to the exact stock vnode and read back the
  stock hash exactly.
- SpringBoard restarted from PID 1080 to PID 1120.
- `targetFileWrites` remained zero during both operations.

The tinted and restored Favorites screenshots are visually identical. A raw
RGB comparison found mean absolute channel differences of
`0.346635, 0.150243, 0.006478` on a 0–255 scale, with only `0.421532%` of
pixels differing. Those small differences are transient animation/status
pixels, not the requested purple background.

The current Lara source independently marks both `CC Module Background` and
`CC Background Blur` with its default maximum supported version of 18.9. Its
`moduleBG` mapping still names `modulesBackground.materialrecipe`, which
explains why file-name presence alone was a false compatibility signal on iOS
26. The source comparison used local Lara commit `fb2d8640cf78`.

## Artifacts

- `build/lab-cc-material-recipe-canary/full-visual-run.json`
- `build/lab-cc-material-recipe-canary/tinted.png`
- `build/lab-cc-material-recipe-canary/stock-restored.png`
- `scripts/lab/cnd_cc_material_recipe_canary.py`
- `scripts/lab/cnd_cc_material_recipe_canary.m`

The initial `stock-before.png` captured Control Center's remembered
Connectivity page, while the post-restart captures showed Favorites. The host
harness now explicitly selects Favorites for future three-way comparisons.
This mismatch does not affect the tinted-versus-restored negative result,
because those two captures show the same page.

## Consequence

Do not expose this route as an iOS 26 feature and do not infer compatibility
from the continued presence of the legacy CoreMaterial resource. A viable iOS
26 port needs to identify the current Liquid Glass material provider or apply
a bounded live SpringBoard adapter to the actual Control Center background and
module views. The proven name-cache redirect remains useful for other
resources only after their current iOS 26 consumers are demonstrated.
