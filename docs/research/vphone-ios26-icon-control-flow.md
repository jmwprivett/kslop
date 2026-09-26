# iOS 26 Spotlight canonical icon control flow

This report closes the source-resolution gap left by Phase 5 for Cyanide on
the jailbroken vphone running iOS 26.0 (23A341). The primary source is no
longer inferred from `Info.plist` or the contents of the IPA: it was observed
while the real Cyanide request traversed `iconservicesagent`.

No theme, installed application file, LaunchServices record, or cache was
manually changed during this trace. A verified identity-preserving cold VM
checkpoint was created first. The request described below had
`ignoreCache == NO`, but both cache layers missed naturally after the IPA was
reinstalled, so the agent executed a fresh canonical render.

## Exact baseline

| Item | Observed value |
| --- | --- |
| VM UDID | `<VM_UDID>` |
| OS | iOS `26.0`, build `23A341` |
| Cyanide bundle ID | `com.zeroxjf.ios-cyanide1` |
| Installed bundle | `/private/var/containers/Bundle/Application/51B1E6EA-9F69-48DC-940B-0237B30AF6FE/Cyanide.app` |
| Installed `Info.plist` SHA-256 | `7b1e3c79a99935be72d596a1764044addf7af8a6973502c9d08804b78ca359d7` |
| Installed `Assets.car` SHA-256 | `f6faa09532716f9fbf92c634886af408062302718cf5bbb1cc7904ae930b12d1` |
| Diagnostic IPA SHA-256 | `43ba8531512d485fffe5ce1a824c48ddfefd493e1182c871ccc26440fffc5d45` |

The installed plist and catalog hashes exactly match their corresponding IPA
entries. The installed primary icon dictionary is:

```text
CFBundleIconName  = AppIcon
CFBundleIconFiles = [AppIcon60x60]
```

The matching catalog has 49 reported entries, including `AppIcon` phone and
pad icon renditions, 2x and 3x renditions, a 1024x1024 rendition, and
`MultiSized Image` records. This inventory is candidate evidence; the runtime
trace below is what determines which branch actually won.

## Observed canonical render

The agent accepted an XPC generation request from SpringBoard PID 39 on queue
`com.apple.NSXPCConnection.user.com.apple.iconservices.39`:

```text
ISBundleIdentifierIcon: com.zeroxjf.ios-cyanide1
ISImageDescriptor:      (68.00, 68.00) @3x
descriptor digest:      E0F23702-19F0-35BF-B6A3-67328315366B
ignoreCache:            NO
```

That one request followed this exact path:

```text
IconCacheService generateImageWithRequest:reply:
  -> generateStoreUnitWithRequest:validationToken:
  -> ISGenerationRequest generateImageReturningRecordIdentifiers:
  -> ISBundleIdentifierIcon _makeResourceProviderAllowIconResourceFallback:
  -> ISRecordResourceProvider resolveResources
  -> ISResourceProvider resourceWithBundleURL:iconDictionary:options:
       bundle URL: Cyanide.app/
       dictionary: CFBundleIconName=AppIcon,
                   CFBundleIconFiles=[AppIcon60x60]
       options: 0xc
  -> ISAssetCatalogResource
       assetCatalogResourceWithURL:imageName:platform:isAppLike:error:
       URL:       Cyanide.app/Assets.car
       imageName: AppIcon
       platform:  4
       isAppLike: YES
  <- ISMultisizedAppAssetCatalogResource
  -> ISRecordResourceProvider configureProviderFromDescriptor:
  -> ISRecipeFactory recipe
  <- ISGenericRecipe
  -> ISCompositor imageForSize:(68, 68) scale:3
  <- IFConcreteImage, 204x204
  <- IFCacheImage, 204x204, layer data size 42296
```

After resolution, the same `ISMultisizedAppAssetCatalogResource` object was
present under both `kISPrimaryResourceKey` and `kISBadgeResourceKey` in the
record provider. The provider also exposed a nonempty validation token and a
LaunchServices source record identifier.

The decisive return value was observed immediately after the catalog factory
returned:

```text
object_getClassName(result) = ISMultisizedAppAssetCatalogResource
```

Therefore Cyanide's canonical primary icon source on this build is:

```text
Cyanide.app/Assets.car -> AppIcon -> multisized app catalog resource
```

It is not `AppIcon60x60@2x.png` while the current primary dictionary and
catalog remain valid.

## Asset and legacy selection order

The exact 23A341 implementation of
`+[ISResourceProvider(Convenience)
resourceWithBundleURL:iconDictionary:options:]` was disassembled at unslid
address `0x1a723fc88`. Its source selection order is:

1. `kISGraphicIconConfiguration`, if present, creates an
   `ISGraphicSymbolResource`.
2. The first nonempty string found under `CFBundleIconName`,
   `UTTypeIconName`, `UTTypeGlyphName`, or `CFBundleGlyphName` is resolved
   against the bundle's asset catalog.
3. Only if catalog resolution returns nil does the implementation consider
   `CFBundleIconFile` or `UTTypeIconFile`.
4. It then considers PDF resources, image bags built from
   `CFBundleIconFiles` or `UTTypeIconFiles`, direct image files, and finally
   `legacyResourceNames`.

For Cyanide, step 2 sees `CFBundleIconName = AppIcon`, opens `Assets.car`, and
returns a valid resource. That ends source selection. `AppIcon60x60` remains a
real fallback declaration, but it is not consulted for the successful
request.

The catalog factory at unslid `0x1a720eacc` opens a `CUICatalog` and selects a
resource subclass in this order:

1. icon stack;
2. layer stack;
3. multisized image with `isAppLike == YES`;
4. multisized non-app image;
5. ordinary asset-catalog image.

Cyanide took step 3, matching its `MultiSized Image` records.

## Generation, cache, and response path

The exact IconServices client and agent implementations establish the cache
boundary:

```text
ISConcreteIcon imageForDescriptor:
  -> in-process image cache
  -> persistent icon store
  -> generateImageWithDescriptor: on a miss
  -> ISGenerationRequest over the IconServices XPC connection

IconCacheService generateImageWithRequest:reply:
  -> agent persistent-store lookup when ignoreCache is false
  -> generateStoreUnitWithRequest:validationToken: on a miss
  -> resource provider + recipe + compositor
  -> write store unit and index record
  -> ISGenerationResponse(data, UUID, validationToken)
```

The request in this report reached `generateStoreUnitWithRequest:` even with
`ignoreCache == NO`, proving that this observation came from a normal cache
miss rather than a debugger-forced bypass.

## Canonical response to visible Spotlight icon

Phase 5 directly observed the consumer side in Spotlight:

```text
SearchUIHomeScreenAppIconView updateWithRowModel:
  -> SearchUIHomeScreenModel sharedInstance
  -> appIconForApplicationBundleIdentifier:
  -> private SBHIconModel
  -> applicationIconForBundleIdentifier:
  -> SBHApplicationIcon
  -> SBHSimpleApplication activeDataSource
  -> applicationBundleIdentifierForImageForIcon:
  -> com.zeroxjf.ios-cyanide1
```

`SBLeafIcon iconServicesIconForImage` was nil for this data source. The live
bundle identifier is instead placed in the image load context, and
SpringBoardHome follows this exact bridge:

```text
SBLeafIcon prepareImageLoadContext:
  -> stores applicationBundleIdentifierForImage
SBLeafIcon makeIconLayerWithInfo:...
  -> _SBHGetApplicationIconLayerWithTraitCollection
  -> _SBHGetApplicationIconLayerWithImageAppearance
  -> ISBundleIdentifierIcon initWithBundleIdentifier:
  -> _SBHGetIconLayerWithImageAppearance
  -> _SBHIconServicesImageForDescriptor
       -> prepareImageForDescriptor: (normal path)
       -> imageForDescriptor: (option-dependent synchronous path)
       -> reject placeholder responses
  -> _SBHGetIconLayerFromIconServicesImage
       -> use IFImage.ICRIconLayer when present
       -> otherwise create a CALayer from IFImage.CGImage
```

The resulting IconServices layer is then installed through:

```text
SBIcon loadRealIconContentLayerWithInfo:...
  -> SBIcon updateIconLayerView:...
  -> SBIconImageView updateExistingIconLayerAnimated:
  -> SearchUIHomeScreenAppIconView iconImageViewDidChangeContents:forIcon:
  -> placeholder removed
```

This joins the visible SearchUI object graph from Phase 5 to the freshly
observed canonical resource and compositor path from Phase 6. A full-color
post-render capture shows the resulting icon as Spotlight's Top Hit:

`${HOME}/Library/CyanideVPhoneLab/evidence/phase6/spotlight-cyanide-after-live-render.png`

The corresponding Home Screen capture is:

`${HOME}/Library/CyanideVPhoneLab/evidence/phase6/home-after-live-render.png`

## Consequence for the theming experiment

Replacing only `AppIcon60x60@2x.png` cannot test the active canonical path;
that file is behind a successful asset-catalog branch. The controlled
experiment must use one of two explicitly different methodologies:

1. Build a complete replacement `Assets.car` which preserves every unrelated
   catalog asset while replacing the `AppIcon` rendition family; or
2. Perform a canonical declaration redirect by removing the primary
   `CFBundleIconName` and naming a staged legacy PNG, followed by measured
   LaunchServices re-registration and fresh runtime proof that the legacy
   resource resolved.

Method 1 tests replacement of the currently active source. Method 2 tests a
new canonical-source declaration. They must not be reported as equivalent.

## Declaration redirect verified

The second methodology was subsequently exercised with the supplied theme.
Only the phone primary `CFBundleIconName=AppIcon` key was removed; the existing
`CFBundleIconFiles=[AppIcon60x60]` declaration was retained, and the existing
`AppIcon60x60@2x.png` was atomically replaced with a 120x120 rendition derived
from the exact theme entry (source SHA-256
`74122c8aa948fc4e2d9d02148f62b88b8e4c77b1727cd34cf5632f9c6bbdca8b`).

After targeted registration, a live resolver breakpoint observed:

```text
bundle URL: Cyanide.app/
dictionary: CFBundleIconFiles=[AppIcon60x60]
options:    0xc
result:     ISIconStackCompositeResource
```

`CFBundleIconName` was absent and the asset-catalog resource was not selected.
The themed icon appeared on the Home Screen and in Spotlight, remained themed
after Spotlight PID 483 was replaced by PID 978, and Cyanide launched as new
PID 970 after its prior process was terminated. Evidence captures are stored
under
`${HOME}/Library/CyanideVPhoneLab/evidence/phase6/redirect-20260908-cyanide/`.

The two source files were then restored atomically, the same targeted
registration was performed, and both surfaces returned to the original icon.
The durable journal reached `verified-restored` after original hashes and
metadata were rechecked.

## In-transaction canonical verification

SnowBoard Remix now records a bounded diagnostic version of that proof after
the icon and
`Info.plist` mutations have survived exact readback, installd has accepted the
targeted registration, a fresh LaunchServices capture exposes the expected
fallback declaration, the retained registration session has closed, and
`_ISInvalidateCacheEntriesForBundleIdentifier` has been issued.

It then creates a new `ISBundleIdentifierIcon` for the target, calls the
observed iOS 26 `_makeResourceProviderAllowIconResourceFallback:` route, and
requires the observed `ISResourceProvider` facade or its record-backed
subclass. If that concrete provider exposes `resolveResources`, a bounded
read-only inspection records whether its immediate object graph contains the
resource class observed in the live redirect trace:
`ISIconStackCompositeResource`. The base iOS 26 provider does not expose that
private selector, so this inspection is diagnostic rather than an activation
gate. The same new icon then requests the
named Spotlight descriptor. Placeholder or nil responses are rejected, and
the returned CGImage must have bounded nonzero geometry and produce a complete
RGBA pixel SHA-256.

This diagnostic is deliberately a chained observation rather than a perceptual pixel guess:
the preceding vnode/hash readback proves the bytes at the only declared
fallback, the LaunchServices readback proves the canonical declaration, the
provider class proves the legacy resolver branch, and the concrete CGImage
geometry/hash proves that canonical rendering returned pixels. It does not
claim that a resampled/composited IconServices image has the same byte hash as
the source PNG.

Every private selector and invoked signature is runtime-checked before use,
provider inspection is capped at 64 object ivars/items,
and rendered storage is capped at 4096x4096/64 MiB. A missing ABI, unexpected
provider/resource class, exception, placeholder, or unreadable image is
recorded diagnostically; it does not override the deterministic vnode,
LaunchServices, invalidation, and teardown checks. The verifier does not write IconServices caches directly,
graft Objective-C objects, or contact SpringBoard or SearchUI.

## Debug cleanup

All trace breakpoints were disabled, LLDB detached normally, the SSH tunnel
closed, and SpringBoard, Spotlight, and `iconservicesagent` remained alive.
The theme archive and installed app bundle were unchanged by the trace.
