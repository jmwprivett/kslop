# User-supplied Pulsar supplemental artwork

Imported from the user's October 5, 2026 `CC-pulsar.zip`. Original images are
preserved byte-for-byte; `source-manifest.json` records the archive and image
SHA-256 digests. This supplements the full original Pulsar set.
The separately attached October 6 `nightshift.png` and `truetone.png` are also
preserved byte-for-byte and recorded as additional sources in that manifest.

Regenerate:

```sh
python3 scripts/import_pulsar_supplemental_artwork.py /path/to/CC-pulsar.zip
python3 scripts/generate_pulsar_controlcenter_artwork.py
```

The generator normalizes derived exports to 220×220 before packaging. The
supplied Sleep-active, Personal-active and Satellite-connected images are
100×100; normalization keeps each control's logical size consistent. Derived
resized images use canonical sRGB metadata so repeated generation is identical.

Confirmed assignments:

| Files | Route |
| --- | --- |
| `vpn_stock.png` | `network.connected.to.line.below.fill` |
| `icons8-satellite-220.png` | Unavailable / `satellite.slash.fill` |
| `icons8-satellite-220 (1).png` | Available / `satellite.wave.2` |
| `icons8-satellite-signal-100.png` | Connected / `satellite.wave.2.fill` |
| Sleep pair | `FocusUI.framework/sleep_cg_02.ca` |
| Personal pair | `FocusUI.framework/personal_cg_02.ca` |
| Work pair | `FocusUI.framework/work_cg_02.ca` |
| Reduce Interruptions pair | Staged; focused row raster adapter pending |
| Custom Focus pair | Staged; focused row raster adapter pending |
| Driving inactive | Retained only; active artwork not supplied |
| `nightshift.png` | `DisplayModule.bundle/Assets.car` / `NightShift` |
| `truetone.png` | `DisplayModule.bundle/Assets.car` / `TrueTone` |

Satellite assignments were confirmed explicitly in the implementation task.
The unqualified `focus_reduce_interruptions.png` is its inactive state.
The generic custom Focus pair is not keyed to the user's “Stop scrolling” title.

The package-source and symbol-source adapters are verified in the local mock
runtime. The physical VPN controller redirect is implemented; the remaining
supplemental physical routes are marked pending in the generated bundle's
`SupplementalRoutes.json`. Physical-device validation remains necessary:
packaging artwork does not establish that a physical surface has been replaced.
Reduce Interruptions and
custom Focus do not globally redirect inferred `apple.intelligence`/`star.fill`
symbols. Driving, Fitness, Gaming, Mindful, Reading and AirPods artwork gaps stay
deferred. Timer keeps the existing Stopwatch compatibility artwork.

Night Shift and True Tone use a complete, build-pinned DisplayModule catalog
replacement. Their single supplied white template is used across states;
native tint, background, labels and actions continue to express enablement.
The square artwork is aspect-fitted and centered in each native 30×40-point
canvas. Generation retains both bitmap scales, both PDF vectors and the packed
atlas contracts, and pads the catalog to its original 32,296-byte length.
These new display routes still require the next physical-device apply/respring
test; a differing device catalog digest is exported and rejected before writes.
