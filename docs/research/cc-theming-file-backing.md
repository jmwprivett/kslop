# Pulsar Control Center file-backed installation

The production Apply/Restore buttons now call `CNDCCThemingFileBackingApply`
and `CNDCCThemingFileBackingRestore`. They do not call the old live-view seed or
per-instance persistence installers and do not open a SpringBoard RemoteCall
session. Runtime, Persistent, Delivery and executable Payload painters have been
removed from the project.

## Resource coverage

`PulsarControlCenter.bundle/FileBacking.json` inventories 29 exact CAML package
routes on build `23A341`: Brightness, StyleMode, all five known Volume variants,
PlayPauseStop, ForwardBackward, three Mirroring variants, Timer/Timer_IC,
LowPower/LowPower_IC, Mute/Mute_IC, OrientationLock/OrientationLock_IC, four
ReplayKit variants, and the DND/Sleep/Personal/Work Focus packages.

The generator records 19 available exported native package baselines. The other
ten routes require device preflight: the exact allowlisted path must contain a
readable nonempty regular CAML file and a valid sibling `index.xml` selecting
`main.caml`. Its root geometry, state names, and capacity are checked before
the device original is backed up and hashed. A present but incompatible package
blocks the transaction. Absent layout variants are separately reported.

The native package index is preserved. Pulsar's layer graph, animations, and
state definitions are inserted beneath the native document root; the native
root bounds/position and all native state names remain. Unused generic state
aliases are pruned to fit smaller Focus resources. Timer continues using the
Pulsar Stopwatch artwork but is centered by its native 48-point document.

Every referenced Pulsar PNG is hash checked, copied to the app's durable
`Application Support/CCThemingFileBacking/Assets` directory, and referenced by
an absolute file URL. Source-package filenames cannot be copied unchanged
into native package directories because the corresponding PNGs do not exist
there. The replacement CAML is padded with legal XML whitespace to the exact
existing file length; no NUL tail or target truncation is required.

`CatalogFileBacking.json` now supplies four native CoreUI 970/storage 17 file
replacements: CoreGlyphs, CoreGlyphsPrivate, ConnectivityModule and DisplayModule.
The installed iOS 26.0 `23A343` simulator runtime provides the actual authoring
stack through actool's `--simulator-environment=DYLD_ROOT_PATH=...` option.
The compiler verifies its output version before accepting it. No header version
is rewritten to disguise a newer catalog. Target baselines remain the exact
physical/IPSW `23A341` resources.

The two symbol catalogs preserve the native CAR header, named variables, lookup
keys and trees, and every unrelated raw BOM block. Donors use
`CoreUI_PACKING=0:0`, producing standalone bitmap CSI values alongside vector
glyphs. All existing target vector weight/size slots and cached Medium/Regular
15/17/20-point image slots are replaced. The original packed atlas remains byte
identical for unrelated consumers; targeted cache keys now resolve standalone
Pulsar images. Base catalog block offsets are repacked within the original file
capacity, preserving all block IDs. Private catalog targets fit existing slots.

The base catalog covers Wi-Fi, cellular, hotspot, flashlight, QR, Camera, media AirPlay
and the four media-volume identities (15 symbol names, 210 vector/cache values). Bluetooth, AirDrop, VPN,
satellite, and Calculator resolve from the private catalog (eight names, 88 values). The base
replacement remains exactly 150,914,088 bytes with 313,467 unrelated live blocks
preserved; the private replacement remains 24,963,464 bytes with 44,751 unrelated
blocks preserved. Their preservation proofs are hashed in the installation
manifest. Template 6 interpolation preserves native size/weight fallback,
including Large requests despite the native catalogs having no explicit Large
keys. All 920 size/weight combinations are compared against native lookups.

CoreGlyphsPriority is no longer an installation route. Apply retires its old
journaled replacement by restoring the exact backed-up native bytes, while
preserving CAML recovery entries. All retired backups remain available. A
conflicting target stops preflight, and interrupted retirement uses a separate
journal state. Same-version native authoring permits the file replacement trial;
`deviceConsumptionVerified` remains false until physical rendering is observed.

Connectivity now uses the pulled physical catalog, SHA-256
`2e1f4b5aa95cbee1257707ab4926a3e9c10151d57a06621bb5f425ad776aca44`,
with CoreUI thinning subtype `2688`. The equal-length VM catalog uses subtype
`2340` and remains rejected by the production stock-digest check. Regenerate
the physical payload with
`python3 scripts/generate_pulsar_cc_catalog_payloads.py --connectivity-only`;
`--connectivity-stock` accepts another export path only when its bytes match
that exact physical pin.

`FileBacking/ConnectivityPreservation-23A341.json` records the stock and payload
contracts for all 11 renditions: each of AirplaneGlyph, CellularDataGlyph, and
HotspotGlyph retains its 1x bitmap, 3x bitmap, and preserved PDF vector at the
native geometry, and both packed atlases retain their scales and dimensions.
Those three identities are the physical catalog's entire named artwork set;
there are no unrelated named assets to replace. The themed PDFs retain every
alpha byte from Pulsar's original native 3x canvases in a PDF soft mask.
Airplane remains 84×120 pixels, Cellular 84×120, and Hotspot 78×120; their
lower-opacity backing and opaque line art are no longer flattened or reduced
to a 40-pixel mask. The complete alpha footprint is centered within those
unchanged native canvases. Airplane now uses a smaller 0.90× optical
scale. Secondary CellularDataGlyph and HotspotGlyph remain at their previous
requested 1.12× scale, capped before any line-art/backing clipping: Cellular is
83/76 (1.0921×), and Hotspot is 77/76 (1.0132×). Every edge retains at least half a source
pixel of margin. The offset/scale is recorded for each rendition, and native 3x
CoreUI retrieval is compared with the source under that exact affine map.
The generated CAR's four tree pages retain every declared lookup
entry, every nonzero page byte, and every indexed value block; only verified
zero-filled trailing page allocation is compacted. This reduces the authored
catalog to its verified existing-file capacity before padding.
The compiled catalog is padded to the native 39,304 bytes.
The research manifest pins both the payload and preservation proof digests;
The replacement is authored by native CoreUI 970 and is admitted by the
build/version/preservation preflight.

### Per-control Connectivity optical sizing

The October 6 device-feedback pass uses explicit per-control constants in
`generate_pulsar_cc_catalog_payloads.py`, rather than one Connectivity multiplier:

| Control | Active file-backed identities | Scale relative to original authored footprint |
| --- | --- | --- |
| Wi-Fi | Public CoreGlyphs `wifi`, `wifi.slash`, `wifi.badge.lock` | 1.60× |
| AirDrop | Private CoreGlyphs `airdrop` | 1.60× |
| Bluetooth | Private CoreGlyphs `bluetooth`, `bluetooth.slash` | 1.60× |
| Cellular | Public CoreGlyphs `cellularbars` | 2.00× |
| Personal Hotspot | Public CoreGlyphs `personalhotspot`, `personalhotspot.slash` | 2.15× |
| Satellite | Private CoreGlyphs `satellite.slash.fill`, `satellite.wave.2`, `satellite.wave.2.fill` | 2.15× |
| Airplane | ConnectivityModule `AirplaneGlyph` | 0.90× |
| Flashlight | Public CoreGlyphs `flashlight.off.fill`, `flashlight.on.fill` | 1.50× |
| VPN | Private CoreGlyphs `network.connected.to.line.below.fill` | 1.27× |

Compact and expanded Connectivity share these resources. Native disassembly
shows Wi-Fi/AirDrop/Bluetooth/Satellite delivering the same UIImage object to
their collapsed and expanded glyph views; Cellular/Hotspot use the same symbol
factory/configuration on separate controllers. Airplane uses the same catalog
identity. Therefore these are intentionally **global optical adjustments**,
not submenu-only overrides: the compact page and other users of the affected
symbol identities change too. No runtime adapter, painter, hook, or recursive
view walk is introduced. Native button/canvas geometry, symbol capline/baseline
guides, state identities, alpha planes, and all unrelated CAR blocks remain
unchanged.

Both CoreGlyph preservation proofs record the per-control/identity scales and
host-render every native Connectivity vector/cache key plus both Flashlight states. Cached keys retain their
native 15/17/20-point and 1x/2x/3x combinations; vectors retain native size/weight
keys. The complete authored line-art/backing bounds must fit the unchanged
symbol template's margins and size guide regions. Host rendering then verifies
the complete source aspect footprint and normalized silhouette, allowing only
pixel rounding and expected low-resolution antialiasing. CoreUI returns
ink-cropped symbol images, so nonzero pixels at the returned CGImage edge are
not incorrectly treated as clipping. The focused lookup test additionally checks
all native size/weight fallback combinations. This is host validation, not a
claim that the new optical sizes have already been physically accepted.

The supplied October 6 Night Shift and True Tone PNGs map to the exact
`NightShift` and `TrueTone` names in
`/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car`.
Neither control has a CAML package in the exported DisplayModule bundle.
The IPSW baseline is pinned to SHA-256
`f3572be5c4a84fb0703eccfd206d7e91e1fa5278183a8770ffaacb7510d0ad93`,
32,296 bytes and thinning subtype `2688`. The generated catalog is authored by
native CoreUI 970 and padded to that exact length. Its complete eight-rendition contract retains
30×40-point PDF vectors, 30×40/90×120 bitmaps and the original packed atlas
dimensions at both scales. The source canvases are aspect-fitted and centered;
80-pixel contours yield smooth template silhouettes within the vnode capacity.
Native button tint and background distinguish enabled states. Regenerate with
`python3 scripts/generate_pulsar_cc_catalog_payloads.py --display-only`.
Host CoreUI retrieval, visible bounds, submitted-mask correspondence,
byte-identical regeneration and local transaction restore/rollback are verified.
Physical consumption is recorded separately from authoring and readback.

## Pulsar visual fidelity

The symbol donors retain the original line-art/backing alpha planes through
CoreUI's native monochrome, multicolor, and hierarchical SVG CSS annotations.
Plain SVG `fill-opacity` was experimentally ignored by the symbol compiler;
the [Apple annotation format](https://developer.apple.com/documentation/technologyoverviews/annotating-sf-symbols)
is used instead. Source masks now allow up to 160 pixels, preserving the full
144-pixel Flashlight and QR sources. Subpixel contour compaction removes raster
stair-step vertices within 0.75 source pixels. Local lookups verify authored
backing opacity at the native 15/17/20-point cache sizes and a 40-point vector
request. QR's tested symbol render contains the supplied Pulsar artwork only;
no unproved global `qrcode`/`viewfinder` assets are blanked.

Flashlight uses a denser 4× bilinear subpixel trace with a 0.20-source-pixel
contour tolerance. This retains both authored 122/255 opacity planes and the
1.75× optical size while avoiding the visibly faceted straight-line reduction
used by the general symbol path.

ReplayKit's native `recording-static` and `on` aliases now receive both the
upstream Pulsar recording pulse and its exit transitions, rather than inheriting
only the static state values. The original animated three-number countdown and
the opacity/scale keyframes remain in the package resource. Animation execution
and state selection remain owned by the system package consumer.

## Volume and expanded-slider providers

The saved VM/physical trace separates the standalone `MRUContinuousSliderView`
package consumer from `MediaControls.NowPlayingVolumeControlsView.slider`, which
is a `MediaControls.Slider`/UIKit slider and has no volume CAPackage. The former
loads `VolumeSemibold.ca`; all five exact MediaControls Volume/RTL/Semibold/
SemiboldRTL/Bold CAML variants remain replaced. The framework's Swift volume
symbol constants resolve through native SFSymbols aliases:

| Native alias | Canonical CoreGlyphs identity |
| --- | --- |
| `volume.fill` | `speaker.fill` |
| `volume.1.fill` | `speaker.wave.1.fill` |
| `volume.2.fill` | `speaker.wave.2.fill` |
| `volume.3.fill` | `speaker.wave.3.fill` |

Those four canonical symbols now receive the host-rendered, full-extent Pulsar
Volume vector artwork (`MediaVolume.png`) in all 56 native vector/cache values.
Native volume levels/actions are untouched; the visual level variants all use
the supplied Pulsar earbuds. This closes a file-provider coverage gap that can
show stock artwork when the consumer selects generated symbols instead of its
CAML path. It is not evidence that a disk file had been restored or that the
reported timed physical reversion has already been reproduced and verified.

Brightness/Volume source drawing colors are normalized during CAML preflight to
the exact native white/template contract, rather than preserving upstream black
vectors that disappear on the dark expanded slider background. Authored 30%
Brightness and 50% Volume backing opacity, paths, geometry, and native consumer
tint/colorization remain. Each native brightness/volume state explicitly restores
the same Pulsar artwork root to visible/opaque; none is an empty placeholder.
Host tests deliberately hide the drawing and then verify every native LKState
binds and restores that exact source root. This is a parsed-resource operation,
not a runtime layer/view traversal.

Connectivity CoreGlyphs artwork is enlarged 12% for all native size/weight
variants. Only artwork coordinates and symbol margins change; native capline,
baseline, template guides and Control Center button geometry are unchanged.
These providers are shared with compact controls, so their artwork enlargement
also applies to compact consumers of the same symbol identities.

Camera and Calculator are now file-backed through their live hosted-control
image routes. The focused VM capture proves `camera.fill` in CoreGlyphs and
`calculator.fill` in CoreGlyphsPrivate by walking each exact control identity
to `CHUISControlButtonViewModel.icon`, `CUINamedVectorGlyph`, and the catalog
bundle. The legacy Camera/Calculator module catalogs remain intentionally
unused. Reduce Interruptions/custom Focus without proven source packages remain
excluded.

## Transaction and lifetime

The installer uses the existing `overwrite_system_file` primitive without
changing its implementation. It requires build `23A341`, validates all reachable
resources before target writes, stages original/payload copies with verified
digests, saves a durable journal before each write, and verifies the full
target readback. Failed writes roll back in reverse order. An interrupted-write
journal permits recovery only when the remaining target bytes match original
or staged bytes; unrelated external target changes are preserved.

Restore works from the durable journal across app sessions and does not depend
on saved object addresses or the current artwork bundle. Backups and staged PNGs
are retained. The journal has a process lock and rejects invalid paths, duplicate
entries, corrupt backups, incompatible builds, and unexpected target changes.

One respring is required after installation/restoration to reload existing
native resource caches. Modified CAML files are intended as the source for
subsequent native loads and reconstruction. Byte readback is reported separately
from native provider consumption. Physical-device reconstruction persistence
and reboot persistence are not claimed as verified by the host fixtures.

The file journal is intentionally not a live SpringBoard cleanup entry: a
respring must not restore these resources before the native providers can load
them. Explicit Restore Stock CC Icons owns restoration.

## Verification

`python3 -m unittest scripts.tests.test_cc_theming_file_backing -v` runs against
local fixture directories only. It verifies exported native geometry/state
contracts, actual `CAPackage` loading of the patched stateful resources and
their PNG URLs, the production catalog compatibility policy, native catalog
fixture transactions, exact readbacks, idempotent apply, durable
restore, a partial-write rollback, build rejection, and preservation of a
conflicting external edit. No fixture contacts a VM or device.

`python3 -m unittest scripts.tests.test_pulsar_cc_catalog_payloads scripts.tests.test_coreui_car_graft -v` validates
stock and generated catalogs with `assetutil`, compares every recorded
type/scale/geometry contract, rejects equal-length VM and tampered baselines,
and regenerates all four payloads and proofs byte for byte in independent directories.
The raw graft test compares every unrelated BOM block, native CAR headers,
lookup keys, trees and legal freed-index entries, and rejects a CoreUI 975 donor.
The transaction fixture also rejects the VM baseline before any target write.

The experimental in-process Runtime, Persistent, Delivery, and executable
payload painters were removed. Production Apply and Restore invoke only the
native file transaction. Exact-route and offscreen materialization code remains
available to the read-only probes, but it is not called by the production
installer.
