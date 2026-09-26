# iOS 26 application icon descriptor matrix

## Result

The original SnowBoard Remix producer published one `68×68@3` IconServices
response per application. That record was sufficient for a normal Home Screen
icon, an App Library large tile, and a Spotlight Top Hit. It could not theme
the other observed consumers because each one asks IconServices for a
different descriptor and receives a different response UUID. The production
profile now includes the empirically required core records listed below.

The minimum empirically observed point-size set for the tested iPhone-class
iOS 26 UI is:

```text
13, 20, 27, 28, 38, 48, 64, and 68 points, all at 3x
```

The named `Spotlight` descriptor defaults to `40×40@3`, but no tested iOS 26
SpringBoard or Spotlight surface requested 40 points. It must not be treated as
the operative Spotlight size merely because of its name.

## Test environment and method

- Date: 2026-09-19
- VM: `cyanide-ios26-base`
- UI layout: iPhone 14 Pro Max class (`D74`), 3x display scale
- SpringBoard trace PID: 673
- Spotlight trace PID: 748
- Trace source: `scripts/lab/cnd_icon_descriptor_trace.m`
- Trace driver: `scripts/lab/cnd_icon_descriptor_trace.py`

The read-only trace was injected into the VM copies of SpringBoard and
Spotlight. It observed the existing `ISBundleIdentifierIcon` boundary by
interposing:

- `imageForDescriptor:`
- `generateImageWithDescriptor:`

It did not publish responses, write the IconServices store, call a descriptor
setter on a consumer-owned descriptor, or issue generation requests of its own.
For each normal consumer request it recorded:

- bundle identifier;
- point size and scale;
- descriptor digest, appearance, icon variant, and options;
- returned `IFImage` class and UUID;
- returned data length and decoded CGImage dimensions;
- the call stack identifying the consumer framework.

The exercised surfaces were the Home Screen, a Home Screen folder preview,
App Library category tiles, the app switcher, a lock-screen notification, and
a live Spotlight search for eBay.

## Observed matrix

| Surface | Host | Descriptor | Returned pixels | Evidence and consequence |
|---|---|---:|---:|---|
| Normal Home Screen icon | SpringBoard | 68×68@3 | 204×204 | The existing record. |
| App Library large tile | SpringBoard | 68×68@3 | 204×204 | Reuses the same bundle UUID as Home. No additional producer record is needed; this surface still needs its consumer refresh. |
| Home Screen folder preview child | SpringBoard | 13×13@3 | 60×60 final cache image | A separate UUID. The Utilities folder requested this for Measure, Magnifier, Calculator, Shortcuts, Passwords, and other children. |
| App Library category mini-icon | SpringBoard | 27×27@3, appearances 0 and 1 | 87×87 final cache image | Separate UUIDs. This is the small four-up content in category tiles. |
| App Library alphabetical/search-list row | SpringBoard | 48×48@3 | 180×180 final cache image | A separate UUID. `SBHIconLibraryTableViewController` configures `SBHIconTableViewCell`, whose `SBIconImageView` reads this record. |
| App switcher title icon | SpringBoard | 28×28@3 | 87×87 final cache image | A separate UUID. The stack reaches `SBFluidSwitcherSpaceTitleItemController`. |
| Lock-screen/notification icon | SpringBoard | 38×38@3 | 114×114 | A separate UUID. The stack reaches `NCIconImageForApplicationIdentifierWithFormat` in UserNotificationsUIKit. Both appearance 0 and appearance 1 were requested. |
| Spotlight Top Hit application | Spotlight | 68×68@3 | 204×204 | Reuses the normal 68-point store response. |
| Spotlight/SearchUI small result icon | Spotlight | 28×28@3 | 87×87 | A separate UUID. This covers the small app icon beside a SearchUI suggestion/result. |
| Spotlight vertical Apps result | Spotlight | 64×64@3 | 192×192 | `SearchUIHomeScreenAppIconView` variant 4 uses its own `SearchUIIconImageCache`. This is distinct from variant-5/68-point Top Hit rows and is required for every application. |
| Spotlight/SnippetUI leading app icon | Spotlight | 64×64@3 | 192×192 | Reuses the 64-point descriptor now required by ordinary Apps results. In the eBay query, SnippetUI also requested it for Safari-backed website cards. |
| Spotlight/SnippetUI tiny app badge | Spotlight | 20×20@3 | 60×60 | A separate UUID. In the eBay query, SnippetUI requested this for the small Safari badge over a website result. |

## App switcher presentation boundary

The descriptor trace and a focused, read-only live view inventory establish
which of the switcher's two SpringBoardHome results reaches the screen. Opening
the switcher caused both of these helpers to request the same 28-point
IconServices response:

```text
SBHGetApplicationIconLayerWithImageAppearance
  -> SBHGetIconLayerWithImageAppearance
  -> SBHIconServicesImageForDescriptor

SBHGetApplicationIconImageWithImageAppearance
  -> SBHGetIconImageWithImageAppearance
  -> SBHIconServicesImageForDescriptor
```

The visible `SBFluidSwitcherIconImageContainerView` does **not** display the
flat image result. Its `_imageView` exists, but `_imageView.image` and the
container's `_image` ivar are both nil. The populated, visible child is:

```text
_customImageView = SBHIconLayerView (28x28, hidden=NO, alpha=1)
  CALayer (cornerRadius=7.28)
    ICRIconLayer (cornerRadius=7.28)
      ICRIconRenderingLayer
        RBSurfaceContentsLayer
```

Therefore the app-switcher title displays the
`SBHGetApplicationIconLayerWithImageAppearance` branch. The normal
`SBIconImageView` flat-layer preference mapping does not govern this container.
Publishing the 28-point themed store response supplies the correct pixels, but
preserving their alpha in the switcher requires a switcher-specific consumer
mapping that chooses the existing flat image result or replaces the marked
custom `SBHIconLayerView`; changing only the descriptor matrix cannot remove
the `ICRIconLayer` chiclet.

### Production switcher route

The physical-device implementation selects SpringBoard's existing flat branch
without mapping custom executable code. In the same single SpringBoard
RemoteCall session already used for the process-wide flat-image preference, it
installs and reads back this matched pair of Apple-signed IMP redirects:

```text
SBFluidSwitcherSpaceTitleItemController
  _iconViewForDisplayItem:  ->  _iconImageForDisplayItem:
  ABI: @24@0:8@16

SBFluidSwitcherSpaceTitleItem
  setImageView:             ->  setImage:
  ABI: v24@0:8@16
```

The provider redirect changes the produced object from `SBHIconLayerView` to
the controller's native `UIImage`. The setter redirect stores that object in
the title item's native image slot, allowing
`SBFluidSwitcherIconImageContainerView` to use its ordinary flat image view.
Neither redirect is safe by itself because it would temporarily pair the wrong
object type with the wrong storage path. Production therefore resolves and
validates every class, selector, class-owned method, and exact type encoding
before mutating anything; it installs both in one transaction and reverses only
the changes made by that transaction if any readback fails.

This physical route is process-wide for app-switcher title icons while the
transparency presentation is enabled. It is not per icon and adds no additional
RemoteCall. Stock icons continue through SpringBoard's own flat provider; the
themed/stock distinction remains in the persistent IconServices responses.

The decoded pixel dimensions of a structured IconServices response are not
always exactly `point size × scale`. For example, the 13-point folder child
returned a 60-pixel cache image, and the 27/28-point consumers normally
returned 87-pixel cache images. Placeholder responses can differ again. The
descriptor's point size, scale, appearance, variant, and options are the
authoritative store key. The producer must not infer the key from the returned
CGImage dimensions.

## Concrete UUID proof

Different sizes for the same application resolve to different UUIDs. Examples
from the trace include:

| Bundle and use | Descriptor | UUID |
|---|---:|---|
| eBay Home/App Library large/Spotlight Top Hit | 68×68@3 | `A84088C0-2441-3D5A-803A-053B2B541090` |
| Cyanide app-switcher title | 28×28@3 | `E297FA7D-2543-3DED-A683-4BAFDBA9C16C` |
| Shortcuts Home-folder child | 13×13@3 | `1F258612-1322-3B7E-BE15-705A5D52104F` |
| Shortcuts App Library mini-icon | 27×27@3 | `4961B198-9102-3F35-8B79-0A89A43BA14D` |
| Shortcuts App Library mini-icon, appearance 1 | 27×27@3 | `F3B738AB-EECA-3B86-B542-844F8312955D` |
| Shortcuts App Library alphabetical/search-list row | 48×48@3 | `50A21A92-9338-3928-9E79-DF157402ECE4` |
| Shortcuts notification, appearance 0 | 38×38@3 | `C98A992E-64F8-3D32-8F7B-373D079E2D99` |
| Shortcuts notification, appearance 1 | 38×38@3 | `DB10B688-A9BB-33BF-926D-C83B947E41D5` |
| Safari SearchUI result | 28×28@3 | `330FB6BD-5A30-3263-93F7-5F057238207E` |
| Safari SnippetUI leading icon | 64×64@3 | `00BB9CC4-960B-310D-9ACF-7F42F432B1E8` |
| Safari SnippetUI badge | 20×20@3 | `BD98E781-81AE-3AB5-9FC2-4360B67A243C` |
| Files Spotlight Top Hit | 68×68@3 | `FB9E8D5D-E3FC-3F6F-8401-1170B4ABEFCF` |
| Files Spotlight vertical Apps result | 64×64@3 | `0FFE3EA4-D7CE-3B60-82BA-28F0CD195F14` |

The focused SearchUI inspection found separate live caches for these two row
variants. Variant 5 (Top Hit) used the 68-point cache at `0x8e0f05040`, while
variant 4 (the vertical Apps list) used the 64-point cache at `0x8df6064e0`.
For Files, the 68-point response was already themed while the independent
64-point response remained stock. Its 64-point structured-data SHA-256 was
`7f976a61b957610fb81e6721b9a1a74ea9afee755dded242b7779d3e9565ea1e`
and decoded RGBA SHA-256 was
`2af813c974316ade31bf167e898a1258154a2b8169698d6a0fd5ed88531254dd`;
the themed 68-point decoded RGBA SHA-256 was
`c2277e89ab24dbcf38f6912291957b6f98a84f4d348fbe364d14f854e283fbe1`.
A separate Find My observation matched
the live variant-4 cache pixels exactly to its stock 64-point persistent
record. Together, these observations locate the missing Apps-list skin at the
producer record, rather than at the existing 68-point Top Hit record.

This is why a SpringBoard cache purge alone cannot fix the unthemed folder,
App Library miniature, or notification icon. A purge only makes those
consumers ask again; without the corresponding themed store UUID, they receive
the stock response again.

## Appearance and variant findings

The subsequent Files launch/return trace adds one required core descriptor:
68x68@3, appearance 0, variant `0x20000`, options 0. Apple's description
prints the variant as hexadecimal (`v:%lx`), so captured `v:20000` means
131072 decimal. Its recorded digest is
`E0F23702-19F0-35BF-B6A3-67328315366B`. The production profile now includes
this descriptor alongside normal 68pt and 28pt variant 0 records.

The follow-up constructor proof corrected an important producer mistake. The
first argument of `+imageDescriptorWithIconVariant:options:` is a descriptor
preset enum; it is not the `v:` value printed in the description. Passing
`0x20000` there silently produced an ordinary `v:0` descriptor and digest
`9E1D8C88-D314-329D-BE0F-1D262142B74B`. `ISImageDescriptor` instead exposes
the exact `setVariantOptions:` / `variantOptions` pair (`v24@0:8Q16` and
`Q16@0:8`). Starting with factory preset 0, setting size 68x68, scale 3,
appearance 0, and `variantOptions=0x20000` produced the exact measured digest
`E0F23702-19F0-35BF-B6A3-67328315366B`.

A disposable Files publication then proved the corrected identity end to end:
the unhooked persistent lookup returned themed UUID
`C2796BDB-32FF-3376-9A6A-9F2343A131DB`, structured-data SHA-256
`66d4ece524a3390044acef073526f5b7f8682b0d1872284796f7426084864ad1`,
and pixel SHA-256
`c2277e4250cdbc8d9daa0b871f7d5dca5c7990c7f350f3f32a5e2e215cb0a8f9`.
During a controlled Files launch/return, `SBHIconImageCache` requested that
exact `v:20000` descriptor with options 6 and passed the same themed pixel
hash unchanged to `SBIconImageView setDisplayedImage:`. This closes the VM
publication and animation-path proof; a physical-device run remains the final
platform validation.

All ordinary application requests in the earlier capture used icon variant 0 and
options 0. Appearance was not uniformly zero:

- the lock-screen notification path requested both appearance 0 and 1;
- SpringBoard also made some 68-point appearance-1 requests;
- the normal folder, app-switcher, sampled Spotlight requests, and App
  Library alphabetical/search-list row used appearance 0;
- the App Library category mini-grid requested both appearances 0 and 1.

The multi-record producer should preserve the exact descriptor properties
used by stock generation. For any `(size, scale, appearance, variant, options)`
combination that resolves to a distinct stock UUID, it should publish the
themed response under that exact UUID. The themed pixels may be shared, but the
IconServices records may not.

The common digest value is not a sufficient discriminator. Multiple standard
descriptors with different geometries reported the same digest
`9E1D8C88-D314-329D-BE0F-1D262142B74B`, while their complete descriptors and
returned UUIDs remained distinct.

## Named descriptor defaults are only templates

For reference, the VM's named defaults included:

| Named descriptor | Default geometry |
|---|---:|
| Notification | 20×20@3 |
| Spotlight | 40×40@3 |
| TableUIName | 28×28@3 |
| HomeScreen / LargeHomeScreen | 64×64@3 |
| Activity / CarLauncher | 60×60@3 |
| WidgetAddGallery | 24×24@3 |

The live consumers override these templates. SpringBoard's normal icon cache
uses 68 points, UserNotificationsUIKit used 38 points, the App Library category
mini-grid used 27 points, and its alphabetical list used 48 points. Future code
should copy a stock template and then set the exact observed properties; it
should not equate a template's name with the final surface.

## Required producer changes

The producer should be changed from one descriptor per bundle to a descriptor
matrix per bundle:

1. Represent each required request as a descriptor specification containing
   point width, point height, scale, appearance, icon variant, and options.
2. Keep one `iconservicesagent` batch session open for the entire apply or
   restore operation.
3. Prepare and retain one descriptor template per distinct specification, not
   one global 68-point template.
4. Decode each source theme PNG once, then render/cache the necessary payload
   sizes. The structured-payload cache key must include source hash, geometry,
   scale, appearance, and payload/presentation version.
5. For every bundle and descriptor specification, run the stock generation
   boundary to discover the exact response UUID and existing `.isdata` record.
6. Journal every original record before replacement. Recovery identity is
   `(bundle, descriptor properties, UUID, path, original hash)`, not just the
   bundle identifier.
7. Publish or restore all records in the same batch, then perform the bounded
   SpringBoard cache purge and reload every canonical and live leaf icon object
   belonging to the active journal set once at the end.
8. Keep Spotlight presentation mapping separate from IconServices store
   publication. The persistent store supplies the pixels; the marker-aware
   consumer mapping controls transparency/chiclet presentation.

The production core includes `64a0` for every application because the live
Spotlight vertical Apps section uses SearchUI variant 4 at 64 points. Only the
SnippetUI tiny badge remains conditional: `20a0` is still a Safari-only
profile extra. The ordinary iPhone/iOS 26 matrix is therefore
`13a0, 27a0, 27a1, 28a0, 38a0, 38a1, 48a0, 64a0, 68a0,
68a0/v0x20000, 68a1`.

## SpringBoard refresh boundary

The persistent store write is silent to SpringBoard. The VM trace established
that the bounded per-object refresh is `SBApplicationIcon -reloadIconImage`
after the store batch is complete. That call increments `imageGeneration`,
refills each attached `SBHIconLayerView`, and notifies flat-image observers.

`SBIconModel -applicationIconForBundleIdentifier:` is not sufficient by
itself. SpringBoard may mount Home on a distinct object from
`leafIconsUniquedByApplicationBundleIdentifier`. This was exposed by an app
being themed in the switcher while its Home icon remained stock: the shared
persistent record was correct, but Home retained a different live icon object.
Production therefore snapshots the model leaf set once, filters it to the
active journal identifiers, deduplicates it with the canonical lookup results,
and calls `reloadIconImage` on every matching object. It does not reload the
entire installed-application model.

Resetting the manager cache has a separate binding consequence. On PID 2772,
`SBHIconManager.iconImageCache` moved from `0xb88380a00` to `0xb87bc1720`,
while `SBRootFolderController`, the root view, both Home pages, the dock, and
their mounted image views all remained attached to `0xb88380a00`. Production
now purges the retained old source and calls the exact
`SBFolderController.setIconImageCache:` implementation on the root controller.
Apple's setter propagates through the fixed root/list/icon-view ownership
graph and reattaches observers to the replacement cache before the targeted
generation reload. This is a bounded controller operation, not a view walk.

The app-switcher title has one additional retained layer. Purging
`appSwitcherHeaderIconImageCache` controls future 28-point reads, but each
materialized `SBFluidSwitcherSpaceTitleItemController` retains its current
image. Production follows SpringBoard's stock hierarchy through
`_appLayoutToTitleItemController` and calls `_updateDisplayItemIcons`.
Disassembly then exposed a second retention boundary:
`SBFluidSwitcherItemContainerHeaderView.setTitleItems:animated:` reuses its
existing `SBFluidSwitcherIconImageContainerView` when the display-item key is
unchanged and jumps past both image setters. Production therefore resolves
only `_visibleItemContainers`, `_visibleOverlayAccessoryViews`, and
`_visibleUnderlayAccessoryViews`, clears `titleItems` on the exact map-reachable
consumers, and then calls `_performUpdateHandler`. This forces the stock
rebuild path to install the newly fetched pixels. The operation is capped at
128 title controllers and 384 deduplicated consumers and runs after the cache
purge and icon generation reload. Both Home/leaf reload and title rebuilding
execute inside the already-open SpringBoard session; neither opens a per-icon
RemoteCall. Restore uses the same path after stock persistence is verified.

Calling `SBHIconImageCache -updateImageForIcon:` is not a suitable fallback.
The VM showed that one such call broadcasts a cache-change callback to the
cache's full observer set rather than only the target application's consumers,
while the target image remains lazily materialized. Repeating it for a batch
would create an O(apps × visible consumers) update storm and risks a
SpringBoard watchdog termination.

If an individual Home icon remains stock while Spotlight or the app switcher
is themed and a SpringBoard restart fixes it, the persistent record is present.
First verify that both the canonical and live leaf objects were found and
reloaded. Only after that should the application's exact alternate-icon
identity or descriptor be treated as an unresolved producer variant.

The complete empirical superset from this round is
`{13, 20, 27, 28, 38, 48, 64, 68}@3x`; 64 points belongs to the ordinary core,
while the SnippetUI profile contributes only Safari's 20-point badge. The 40-point
named Spotlight default should remain out until a real iOS 26 consumer is
observed requesting it. Additional environments should be discovered rather
than hardcoded: a 2x device, iPad layout, CarPlay, Messages extensions, or the
widget gallery can legitimately add descriptor specifications.

## Dynamic Clock and Calendar exception

Clock and Calendar were visibly present during the wildcard SpringBoard trace,
but did not travel through the normal `ISBundleIdentifierIcon` 68-point path in
the same way as ordinary application icons. SpringBoard owns specialized
dynamic image views, including the `SBHClockApplicationIconImageView` and
calendar icon view family.

Publishing more IconServices sizes therefore does not by itself solve the
Clock and Calendar Home Screen behavior. They require a separate presentation
decision: either preserve their live dynamic face over a themed background or
replace/disable the specialized dynamic content. That work should not be mixed
into the descriptor-matrix publisher.

## Reproduction

With the visible VM running and root SSH available:

```sh
CND_VPHONE_ROOT_PASSWORD=alpine \
python3 scripts/lab/cnd_icon_descriptor_trace.py \
  inject SpringBoard --host <VM_HOST> --bundle '*'

CND_VPHONE_ROOT_PASSWORD=alpine \
python3 scripts/lab/cnd_icon_descriptor_trace.py \
  inject Spotlight --host <VM_HOST> --bundle '*'

CND_VPHONE_ROOT_PASSWORD=alpine \
python3 scripts/lab/cnd_icon_descriptor_trace.py \
  read SpringBoard --host <VM_HOST>

CND_VPHONE_ROOT_PASSWORD=alpine \
python3 scripts/lab/cnd_icon_descriptor_trace.py \
  read Spotlight --host <VM_HOST>
```

The VM address is incidental. The trace driver still validates that the guest
is vPhone, verifies the target PID and executable identity before injection,
and refuses non-root/non-lab usage.
