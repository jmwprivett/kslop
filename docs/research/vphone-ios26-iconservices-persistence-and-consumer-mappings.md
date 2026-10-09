# iOS 26 IconServices persistence and consumer mappings

This document is the implementation contract for the non-bundle icon-theming
route proven on the iOS 26.0 vPhone. It records the complete successful path,
the two independent mechanisms involved, their lifetimes, and the conditions a
Cyanide port must verify before it may report success.

The central distinction is:

1. **Publication** changes the canonical IconServices response stored on disk.
2. **Presentation** changes how SpringBoard and Spotlight deserialize and
   display only Cyanide-marked structured responses.

Publication can remain after `iconservicesagent` exits. Presentation cannot:
SpringBoard and Spotlight each own an independent address space, so their
process-local mappings disappear when that particular process exits. Neither
mechanism requires editing an application's `Info.plist`, `Assets.car`, legacy
PNG files, LaunchServices registration, or code signature.

## Proven environment

The successful control used:

| Field | Value |
| --- | --- |
| Device | jailbroken vPhone |
| OS | iOS 26.0 (`23A341`) |
| Test bundle | `com.ebay.iphone` |
| Icon descriptor | `com.apple.IconServices.ImageDescriptor.Spotlight` |
| Geometry | 68 by 68 points at 3x (204 by 204 pixels) |
| Structured marker | `CNDThemeIcon.v1` |
| IconRendering UUID | `81cb5be9-b5da-3551-90fd-90d6e18d569a` |

The hard-coded IconRendering instruction address and object offsets below are
valid only after all pinned identity, UUID, ABI, and byte checks pass. They are
not portable constants for another iOS build.

## End-to-end control flow

### Canonical generation and persistence

The observed service-side path is:

```text
ISBundleIdentifierIcon generateImageWithDescriptor:
  -> IconServices XPC request
  -> IconCacheService generateImageWithRequest:reply:
  -> persistent-store lookup
  -> IconCacheService generateStoreUnitWithRequest:validationToken: on miss
  -> ISGenerationRequest generateImageReturningRecordIdentifiers:
  -> resource-provider resolution
       Assets.car / app-icon stack / legacy files
  -> ISRecipeFactory
  -> ISCompositor imageForSize:scale:
  -> IFCacheImage(data, UUID, validationToken)
  -> IconServices writes the response into its indexed store
  -> ISGenerationResponse(data, UUID, validationToken)
```

The durable data unit is a UUID-named file beneath the `ISImageStore` URL:

```text
<ISImageStore.storeURL>/<IFCacheImage.uuid>.isdata
```

The persisted response's UUID is also the identity used by the store index.
At the inner `generateImageReturningRecordIdentifiers:` boundary the stock
object may still have a nil UUID; the unmodified outer IconServices transaction
then assigns the canonical UUID while installing the returned response. The
validation token must be retained. A port must pass through the inner UUID
(including nil), then discover and verify the resulting canonical UUID from
the exact data/token-matched cache and store entry rather than inventing one.

### Home Screen consumption

SpringBoard consumes the response approximately as follows:

```text
SBLeafIcon prepares an application bundle identifier
  -> ISBundleIdentifierIcon
  -> _SBHIconServicesImageForDescriptor
  -> in-process ISImageCache
  -> persistent IconServices store / service generation on a miss
  -> _SBHGetIconLayerFromIconServicesImage
       IFImage.ICRIconLayer when structured layer data exists
       otherwise CALayer backed by IFImage.CGImage
  -> SBIconImageView updateExistingIconLayerAnimated:
```

### Spotlight consumption

Spotlight owns its own SpringBoardHome icon model and its own IconRendering
objects. The observed visible-row path is:

```text
SearchUIHomeScreenAppIconView updateWithRowModel:
  -> SearchUIHomeScreenModel
  -> private SBHIconModel
  -> SBHApplicationIcon / SBLeafIcon
  -> ISBundleIdentifierIcon
  -> _SBHIconServicesImageForDescriptor
  -> _SBHGetIconLayerFromIconServicesImage
  -> ICRIconLayer
  -> SBIconImageView updateExistingIconLayerAnimated:
  -> SearchUI removes the placeholder
```

SpringBoard's cache or mapped code does not control Spotlight's copy. The two
consumers must be treated as independent process identities.

## How persistent publication was achieved

The successful vPhone control is implemented by
`scripts/lab/cnd_iconservices_cache_theme.m` and orchestrated by
`scripts/lab/cnd_iconservices_cache_theme.py`.

### 1. Build a genuine structured image

The source PNG is decoded and rendered as a 204 by 204 RGBA image. The lab
constructs a `CUIMutableNamedIconLayerStack` containing:

- a transparent chiclet color required by the serializer;
- a full-size image layer containing the themed RGBA pixels;
- a destination-out inverse-alpha layer;
- rendering properties with `knocksOutBorder=true`;
- color rendering mode, 68-point size, and 3x scale.

The resulting `ICRFinalizedIcon` is serialized while its verified
`chicletIsVisible` byte is zero. The byte is restored on the temporary local
object immediately after serialization. The serialized layer data contains
the marker `CNDThemeIcon.v1`.

That layer data and the RGBA image are passed to the exact iOS 26 initializer:

```objc
-[IFImage initWithCGImage:scale:layerData:]
```

The resulting `IFImage.data` is the complete structured response payload; it
is not merely the PNG and not merely `ICRFinalizedIcon` layer data.

### 2. Interpose at the service generation boundary

The lab temporarily replaces:

```objc
-[ISGenerationRequest generateImageReturningRecordIdentifiers:]
```

The replacement always calls the stock implementation first. It accepts a
request only when all of these match:

- bundle identifier `com.ebay.iphone`;
- descriptor size exactly 68 by 68 points;
- descriptor scale exactly 3x;
- the stock return object exposes `data`, `uuid`, and `validationToken`.

For the single matching request it constructs:

```objc
[[IFCacheImage alloc] initWithData:themedIFImageData
                              uuid:stock.uuid
                   validationToken:stock.validationToken]
```

The validation token and the normal UUID-assignment transaction are essential.
The hook substitutes only the response bytes. If `stock.uuid` is already set,
it is passed through; if it is nil at this inner boundary, `IFCacheImage`
receives nil and the unmodified outer transaction assigns the genuine UUID.
The final UUID must be recovered from the exact data/token-matched cache/store
response and verified—never synthesized by Cyanide.

### 3. Trigger through the real client boundary

The matching request is triggered with:

```objc
-[ISBundleIdentifierIcon generateImageWithDescriptor:]
```

using a copied named Spotlight descriptor configured to 68 by 68 points, 3x,
and `ignoreCache=YES`.

`prepareImageForDescriptor:` is not interchangeable with this call. In a
normal application process it can continue into a private client compositor;
the failed Cyanide port consequently sent `initWithCGImage:scale:` to an
`__NSArrayM`. Direct generation is the boundary used by the successful
control and returns the encoded IconServices response without asking Cyanide
to materialize the consumer layer.

The original VM harness used a separate root trigger executable because that
was its convenient orchestration boundary. The Cyanide port does not need to
reproduce the SSH process or grant its application sandbox Mach lookup access.
It constructs the same icon and copied descriptor through the already-open
`iconservicesagent` session and calls `generateImageWithDescriptor:` there.
Returning the one-shot replacement from the matching generation call causes
IconServices to perform publication automatically; this is the recent path
that produced the consumer-visible themed icon.

The inner stock response can still have a nil UUID. Verification therefore
retains and inspects the outer response returned by the automatic generation
call before falling back to the request icon's `imageCache`. The observer must
not equate a failed lookup through that request-local cache instance with a
failed publication.

### 4. Let IconServices perform its normal store write

The replacement is returned to `IconCacheService` as the result of the normal
generation transaction. The unmodified outer service logic writes that
response and its index entry. The lab does not manually edit an application
bundle, LaunchServices record, or IconServices index.

The original generation IMP is restored after the one matching call. The
publication hook is therefore a one-shot producer, not a resident repair
loop.

### 5. Prove persistence across service replacement

The lab's proof did more than read the same process's `ISImageCache`:

1. force the matching themed generation;
2. capture the response UUID, data length, and SHA-256;
3. terminate the injected `iconservicesagent`;
4. stop the hold process so the injected address space is gone;
5. issue a normal, unhooked request to a newly launched agent;
6. require the new response's UUID, length, and SHA-256 to match exactly.

The success line was `THEMED_CACHE_PERSISTED`. Because the second response
came from a new, unhooked service process, neither a retained object nor an
in-process dictionary can explain it.

### Physical-device port: stock indexed-store replacement

The VM's publication result is portable, but its copied executable callback is
not. The vPhone root harness can execute the anonymous copied publisher body in
`iconservicesagent`. A physical Apple platform daemon enforces a different
code-signing/PAC boundary; attempting to reproduce the callback with a forged
cross-task executable remap caused a kernel PAC panic. A physical build must
therefore never execute Cyanide's publisher code in `iconservicesagent` and
must never replace `generateImageReturningRecordIdentifiers:`.

The physical transport in
`CNDIconServicesPublisherRemoteTransport.m` reproduces the durable result with
only stock signed methods:

```text
copied Spotlight descriptor (68 pt, 3x, ignoreCache=YES)
  -> ISIconManager findOrRegisterIcon:
  -> ISBundleIdentifierIcon generateImageWithDescriptor:
  -> stock outer transaction assigns/indexes UUID and validation token
  -> wait until a normal index lookup returns that exact UUID/token
  -> ISIconManager.iconCache.store
  -> existing ISStoreUnit for the returned UUID is verified
  -> IFCacheImage(themedData, same UUID, NSData._is_validToken)
  -> ISStoreUnit(themedData, same UUID)
  -> ISStore writeStoreUnit:
  -> exact unitForUUID: data/UUID readback
  -> map and validate the existing persistent ISStoreIndex
  -> find the exact 0x74-byte value by icon digest, descriptor digest,
     scale, store UUID, and old validation token
  -> replace only its 40-byte validation-token field with _is_validToken
  -> msync(MS_SYNC), invalidate the daemon read mapping, and require a
     normal index lookup to return the same UUID plus _is_validToken
  -> canonical ISImageCache setImage:forDescriptor:
  -> exact cache data/UUID/token readback
```

The UUID is not invented and no new unindexed unit is added. Stock generation
first guarantees that the UUID already belongs to the requested bundle and
descriptor in the normal IconServices index. The themed write changes the data
unit behind that identity and the validation token stored in that descriptor's
index value. The token must be changed in both places: changing only the
process-local `IFCacheImage` leaves the persistent entry tied to the current
LaunchServices epoch, so an unrelated install can later classify it as stale
and regenerate stock pixels.

The 23A341 index value is exactly `0x74` bytes. Its store UUID begins at
`+0x3c`, and its 40-byte validation token begins at `+0x4c`. Publication does
not append a duplicate entry: `ISMutableStoreIndex addValue:` always allocates
a new chained node, so a duplicate could leave lookup order ambiguous. The
transport instead opens Apple's existing `MAP_SHARED` mapping, validates the
entire record identity, mutates only the non-key token field, flushes it, and
then verifies the result through the ordinary
`findStoreUnitForIcon:descriptor:UUID:validationToken:` path. If any write,
flush, or lookup proof fails, it restores the original token and stock store
bytes and reports publication failure.

Restore uses the same descriptor with `ignoreCache=YES`, but performs no themed
store write. The normal stock generation replaces the unit behind the indexed
UUID, after which Cyanide requires the store unit and canonical cache to equal
the returned stock data, UUID, and token before clearing recovery state. It
also waits until the fresh stock UUID/token pair is observable through the
normal persistent-index lookup before accepting restoration.

The physical path uses an anonymous **RW data** staging buffer consumed by
`-[NSData initWithBytes:length:]` and Apple's file-backed **RW shared-data**
mapping for the existing index. Neither mapping is executable. The older
publisher payload remains reachable only when the authenticated vPhone lab
backend is selected.

## Why publication alone rendered a grey plate

The stored structured payload was valid and did reach both consumers, but the
serialized `chicletIsVisible=0` state was not sufficient by itself on this
build. During consumer-side deserialization/rendering, IconRendering rebuilt
or retained a chiclet/background presentation. Transparent pixels then
revealed that grey plate; replacing transparent pixels with black only hid it
visually and did not remove it.

The border and grey plate were therefore consumer presentation effects, not a
failure to persist the themed response.

## Earlier themed-only VM consumer mapping

The successful themed-only control is
`scripts/lab/cnd_spotlight_chiclet_patch.m` compiled with
`CND_CHICLET_THEMED_ONLY=1`. The same code was loaded independently into
SpringBoard and Spotlight.

This was not a single static byte patch. The themed-only mode first verified
that the global IconRendering instruction remained stock, then installed four
process-resident method replacements:

| Class | Method | Purpose |
| --- | --- | --- |
| `ICRFinalizedIcon` | `initFromSerializedData:device:error:` | Find `CNDThemeIcon.v1`, mark only that object, and change the verified byte at `+0xb8` from 1 to 0. |
| `ICRIconLayer` | `initWithData:error:` | Propagate the themed identity from serialized data. |
| `ICRIconLayer` | `initWithFinalizedIcon:` | Propagate the themed identity and prepared full-bleed image to the layer. |
| `ICRIconLayer` | `layoutSublayers` | After stock layout, replace the themed layer tree with the transparent flat surface. |

For a marked finalized icon, the mapping calls:

```objc
-[ICRFinalizedIcon
    renderedFullBleedIconWithConfiguration:
    excludeChicletSpecularHighlights:]
```

with `excludeChicletSpecularHighlights=YES`. It retains that `CGImage` through
an Objective-C association. After the stock `ICRIconLayer` layout completes,
the mapping performs one disabled-actions transaction:

- remove the layer's children;
- set the prepared full-bleed image as `contents`;
- set `contentsGravity` to resize and derive `contentsScale` from pixels;
- set `opaque=NO` and `masksToBounds=NO`;
- set corner radius and border width to zero;
- clear background color;
- set shadow opacity to zero.

The marker gate is what made this themed-only: stock IconServices responses
never take the flattening path.

### The separate global instruction experiment

The same lab file also has a different mode,
`CND_CHICLET_THEMED_ONLY=0`. That mode privately COWs the IconRendering page
and changes the instruction at unslid VM address `0x1b0d5065c`:

```text
0x52800028  mov w8, #1
0x52800008  mov w8, #0
```

It verifies the IconRendering UUID, stock instruction, executable mapping,
page size, private `VM_PROT_COPY` transition, instruction readback, instruction
cache invalidation, and restored RX protection.

That instruction patch suppresses the chiclet globally in that process. It is
useful as a control but is not the themed-only solution, and it must not be
described as if it were the four-hook marker-aware mapping.

## Flat persistent `IFImage.data` control (negative result)

On 2026-09-27, the 23A341 VM tested whether publication itself could select
the flat presentation path and eliminate the Spotlight PID redirect. This was
not the earlier failed `prepareImageForDescriptor:` experiment. The lab
publisher successfully constructed the replacement with the exact runtime ABI

```objc
-[IFImage initWithCGImage:scale:] // @32@0:8^{CGImage=}16d24
```

and returned its `data` from the normal one-shot
`generateImageReturningRecordIdentifiers:` transaction. No synthetic
`layerData` was supplied.

The control first regenerated and verified the stock 68-point eBay record:

- UUID `7621092D-4DC3-3721-B0DE-4A761F9C6A69`;
- 204 by 204 RGBA SHA-256
  `47ab4a73026bf9ccec41c2209851f4f1bf17aa76f9ccc19acc0c45e5492ecf4f`.

The flat replacement then survived an `iconservicesagent` replacement and an
unhooked persistent readback:

- UUID `1A1EA239-E714-3BB2-8B51-C39E5CCCFB43`;
- 166,512-byte response SHA-256
  `68baef076582ad5816da9287bc351f7141a8988858181a617b48e5707dd42cbb`;
- 204 by 204 RGBA SHA-256
  `c2277e4250cdbc8d9daa0b871f7d5dca5c7990c7f350f3f32a5e2e215cb0a8f9`;
- `layerData.length == 0` and `ICRIconLayer == nil` after reconstructing the
  stored response as `IFCacheImage`.

Spotlight PID 431 was terminated and the first target row was created in fresh
PID 596. The experiment installed no flat-preference or chiclet redirect; the
signed-IMP probe reported `mutation=none` and only set the visible query text.
The 68-point Top Hit displayed an empty rounded plate rather than the themed
pixels.

The read-only live-object inspection proved this was not a persistent-store or
`SearchUIIconImageCache` miss:

- the visible row was `SearchUIHomeScreenAppIconView` variant 5 at 68 points;
- `cachedImageForIcon:` contained the exact themed RGBA hash `c2277e42...`;
- its `SBIconImageView` had `displayedImage == nil` and layer opacity `0`;
- `contentsLayerView` was `SBHIconLayerView`, but both its `ICRIconLayer`
  getter and the carrier's `ICRIconLayer` getter were nil.

Thus the consumer had accepted and cached the flat bitmap, but the normal
Spotlight icon-view path did not materialize it as a visible image. Plain flat
persistent bytes do **not** replace the process-local presentation redirect.
The structured persistent payload remains necessary for the other consumers,
and Spotlight still needs its stock flat-image branch selected before the row
is built.

Stock was regenerated afterward. A clean readback restored the original stock
RGBA hash, and fresh Spotlight PID 694 displayed the normal eBay Top Hit. The
visual controls are retained under
`~/Library/CyanideVPhoneLab/evidence/spotlight-flat-payload-20260927/`.

## Final transparent presentation route

The four-hook mapping proved that consumer presentation, rather than store
publication, caused the plate. A later, narrower control found that
`SBIconImageView` already contains the correct transparent presentation path.
Before a row or icon view is constructed, force:

```objc
-[SBIconImageView effectivelyPrefersFlatImageLayers]
```

to return true. The consumer then chooses a plain `CALayer` backed by the
themed `IFImage.CGImage` instead of constructing an `ICRIconLayer`. The exact
stored RGBA alpha is preserved, and neither the grey chiclet nor its border is
created. A clean Spotlight PID with the redirect installed before its first
eBay row showed the themed transparent icon while unrelated Top Hit, Search,
Camera, and Barcode UI remained stock.

The VM proof in `scripts/lab/cnd_spotlight_signed_imp_probe.m` redirects that
method to:

```objc
-[NSObject isNSObject__]
```

Both methods have the exact encoding `B16@0:8`, and the source implementation
is an existing Apple-signed always-true IMP. The tracing dylib present during
the final control only logged calls and invoked originals; it did not mutate
presentation. Restarting Spotlight removed prior broad prominence and opaque
experiments, so the single flat-preference redirect explains the result.

### Stock Low Power Mode branch and caller trace

A later control proved that the redirect selects an existing stock policy
branch rather than providing a renderer that Spotlight otherwise lacks. With
the structured eBay record still installed, Low Power Mode was enabled and a
fresh Spotlight PID was allowed to construct the row without a presentation
redirect. The row displayed the transparent themed pixels without the grey
plate. Its live state was:

```text
prefersFlat=0 effectivelyFlat=1 square=0
appearance=SBHLightIconImageAppearance hasGlass=0
lowPower=1 thermal=0
```

The persistent response remained UUID
`841834B2-4176-3FB4-A4BA-E5752207BD41`, data SHA-256
`80b73f23ed6e9902dd1dad2ee90712b80f4c1caf1e06a4d64a3a0618a7450d6b`,
and RGBA SHA-256
`c2277e4250cdbc8d9daa0b871f7d5dca5c7990c7f350f3f32a5e2e215cb0a8f9`.
The same RGBA hash reached the visible alternate `CALayer`. This distinguishes
the stock flat-presentation policy from publication and cache lookup.

`scripts/lab/cnd_spotlight_transition_trace.m` was then injected into fresh
Spotlight PID 1293 before setting the eBay query. It interposed the exact
Objective-C ABIs for these methods while always invoking their original IMPs:

```text
-[SBIconView setPrefersFlatImageLayers:]               v20@0:8B16
-[SBIconImageView setPrefersFlatImageLayers:]          v20@0:8B16
-[SBIconView setShowsSquareCorners:]                   v20@0:8B16
-[SBIconImageView setShowsSquareCorners:]              v20@0:8B16
-[SBIconImageView effectivelyPrefersFlatImageLayers]   B16@0:8
```

The first eBay row construction produced no positive flat-policy setter. Its
actual configuration chain was:

```text
SearchUIHomeScreenAppIconView updateWithRowModel:
  -> SBIconView setIcon:animated:
  -> SBIconView _updateIconImageViewAnimated:
  -> SBIconView _makeIconImageView
  -> SBIconView _configureIconImageView:
       -> SBIconImageView setShowsSquareCorners:0
       -> SBIconImageView setPrefersFlatImageLayers:0
  -> SBIconView _updateIconImageViewAnimated:
       -> SBIconImageView setPrefersFlatImageLayers:0
```

Thus SearchUI does not configure this result as a flat icon. It creates an
ordinary `SBIconImageView` with both stored flags false. The observed calls to
`effectivelyPrefersFlatImageLayers` came from the stock SpringBoardHome image
update machinery:

```text
SBIconImageView iconImageOptions
  <- SBIconImageView needsContentsLayerUpdate
  <- SBIconImageView updateImageSublayerAnimated:
  <- SBIconImageView updateImageAnimated:
  <- SBIconImageView setIcon:location:animated:

SBIconImageView iconImageOptions
  <- SBIconImageView updateImageSublayerAnimated:
  <- SBIconImageView updateImageAnimated:
  <- SBIconView didMoveToWindow
  <- SearchUIHomeScreenAppIconView didMoveToWindow

SBIconImageView iconImageOptions
  <- SBIconImageView updateExistingIconLayerAnimated:
  <- SBIconImageView updateImageSublayerAnimated:
```

In every target call the stored flags remained false, appearance `hasGlass`
remained false, thermal state remained nominal, and the method returned true
only because Low Power Mode was enabled. Static disassembly of iOS 26.0 build
23A341 agrees with the runtime trace: the method returns true for an explicit
flat preference; for square corners with a non-glass appearance; for Low Power
Mode; or for serious/critical thermal state.

Static cross-reference enumeration also found the stock positive-policy
propagation paths in SpringBoardHome. `SBHIconManager` distributes its own
`prefersFlatImageLayers` value through
`configureIconView:forIcon:`, `configureLibraryViewController:`, library pod
configuration, and floating-dock configuration. None of those manager-owned
paths appeared in the Spotlight result-row construction trace. Spotlight's
SearchUI row directly owns the `SBIconView`, leaving the value false. This is
why toggling the SpringBoard icon manager cannot be assumed to configure a
future Spotlight PID.

The conclusion is narrower than “Spotlight requires a custom renderer.” It
does not. Spotlight requires the stock flat-image policy to evaluate true for
these transparent themed rows. Low Power Mode proves that stock end-to-end
route. Without Low Power Mode, square corners, or a serious thermal state, the
normal SearchUI construction path supplies no stock positive preference, so a
process-local policy selection is still required unless another supported
configuration entry point can be found.

### Physical-device installer

`CNDIconServicesConsumerHook.m` reproduces that control through one bounded,
PID-bound RemoteCall per SpringBoard or Spotlight incarnation:

1. bind the exact kernel proc and task identity before opening the session;
2. resolve `SBIconImageView`, `NSObject`, and both selectors in the target;
3. require the target method to be owned directly by `SBIconImageView`;
4. require both method encodings to equal `B16@0:8`;
5. obtain the existing Apple-signed source IMP;
6. call `method_setImplementation` inside the target process;
7. read the target method IMP back and compare it after stripping PAC bits;
8. roll back to the original IMP if the immediate readback fails;
9. close the only target session and verify the process identity did not
   change.

This physical path does **not** map Cyanide code, request an executable sandbox
extension, open Cyanide's executable, call `ptrace`, make a private executable
page, patch a shared-cache instruction, or contact launchd. Objective-C's own
runtime writes the method table and handles arm64e signing. The redirect is
process-wide: it is installed once per PID, never once per icon or application.

The earlier four-hook VM payload remains a useful comparison and a possible
future themed-only refinement. It is not selected by the physical path.

### Lifetime semantics

After installation, rendering does not call Cyanide and Cyanide may exit. The
method redirect remains until that consumer exits:

- SpringBoard redirect: survives Cyanide exit; ends at SpringBoard restart,
  respring, or reboot.
- Spotlight redirect: survives Cyanide exit; ends whenever that Spotlight PID
  exits, which may happen much sooner.
- IconServices store record: independent of both redirects and remains on disk
  until stock regeneration, cache replacement/eviction, or explicit restore.

The redirect affects future `SBIconImageView` construction. It is not
retroactive to a row or icon layer already materialized, so the installer must
run against a fresh/dormant PID before Spotlight rows are built; existing views
must be reconstructed after installation.

### SpringBoard-owned Spotlight lifetime assertion preflight

The 23A341 VM's historical memorystatus ledger records a suspended Spotlight
process with termination reason `idle-exit`, rather than a pressure kill. That
distinction makes a termination-resistance assertion relevant: it can suppress
ordinary idle termination, but it is not crash or jetsam immunity.

Static disassembly also provides an Apple-owned construction reference.
`SBLegacyVOIPRefreshWakeTracker` creates an `RBSAssertion` in SpringBoard for
another application identity, calls `acquireWithError:` synchronously, retains
the result in a strong ivar, and invalidates it during cleanup. Its full
short-lived VOIP profile includes CPU, running-reason, foreground jetsam,
termination-resistance, and duration attributes. Cyanide does not need that
high-impact profile merely to preserve a suspended Spotlight PID.

`scripts/lab/cnd_spotlight_assertion_probe.py` injected an inspection payload
into SpringBoard and verified the narrower primitive on the live Spotlight PID.
The exact runtime encodings were:

| Class and selector | Encoding |
| --- | --- |
| `-[RBSAssertion initWithExplanation:target:attributes:]` | `@40@0:8@16@24@32` |
| `-[RBSAssertion acquireWithError:]` | `B24@0:8o^@16` |
| `-[RBSAssertion invalidateSyncWithError:]` | `B24@0:8o^@16` |
| `-[RBSAssertion isValid]` | `B16@0:8` |
| `-[RBSAssertion state]` | `Q16@0:8` |
| `+[RBSTarget targetWithPid:]` | `@20@0:8i16` |
| `+[RBSResistTerminationGrant grantWithResistance:]` | `@20@0:8C16` |
| `+[RBSProcessHandle handleForIdentifier:error:]` | `@32@0:8@16o^@24` |
| `-[RBSProcessHandle currentState]` | `@16@0:8` |
| `-[RBSProcessState terminationResistance]` | `C16@0:8` |

SpringBoard's signed entitlements include
`com.apple.runningboard.primitiveattribute`,
`com.apple.runningboard.process-state`, and
`com.apple.runningboard.underlyingassertion`. The VM server consequently
accepted an assertion containing only
`[RBSResistTerminationGrant grantWithResistance:30]`. The grant described
itself as `NonInteractive`; acquisition returned true, the assertion became
valid in state 1, and an associated object on SpringBoard's `NSProcessInfo`
retained it after the injector exited.

RunningBoard then reported Spotlight as `running-suspended`, CPU role `None`,
and termination resistance `NonInteractive`. The custom primitive assertion
was visible alongside the normal FrontBoard after-life and underlying
assertions. No CPU-access or jetsam-priority grant was installed. Synchronous
invalidation returned true, changed the assertion to invalid state 2, removed
the associated object and custom primitive, and restored aggregate termination
resistance to `None` while Spotlight remained suspended. The lab left no
assertion installed.

This proves the exact API, entitlement, synchronous acquisition, durable
SpringBoard ownership, low-power suspended state, and bounded cleanup route.
It does not yet prove survival through a deliberately induced idle-exit or
memory-pressure cycle. A production decision should therefore distinguish two
claims: confidence is high that the assertion suppresses the observed ordinary
`idle-exit`, but it must never be presented as protection from a crash, forced
termination, SpringBoard restart, or severe jetsam pressure.

#### Background-jetsam strengthening probe

The live 23A341 VM also accepted a deliberately bounded strengthening:

```objc
@[
    [RBSResistTerminationGrant grantWithResistance:30],
    [RBSJetsamPriorityGrant grantWithBackgroundPriority],
]
```

`RBSAssertion.attributes` readback contained exactly `NonInteractive`
termination resistance and jetsam band `40`. Acquisition returned true, the
assertion remained valid in state 1 after the injector exited, and a later
status probe found the same Spotlight PID and the same retained assertion.
RunningBoard continued to report `running-suspended` and CPU role `None`.
Synchronous invalidation succeeded and restored termination resistance to
`None`; the lab left no assertion installed.

This is the strongest narrow profile justified by the current evidence. It
raises the suspended process's memory-pressure standing without adding CPU
access or a running reason. Foreground jetsam priority, CPU access, or
`Interactive` termination resistance would be substantially broader and do
not address the known `idle-exit` reason. The extra background grant still
cannot protect a replaced PID, crash, forced termination, SpringBoard restart,
reboot, or sufficiently severe memory pressure.

#### Low Power Mode notification spoof experiment

Static 23A341 disassembly shows that every
`-[SBIconImageView effectivelyPrefersFlatImageLayers]` evaluation obtains
`+[NSProcessInfo processInfo]` and calls `-isLowPowerModeEnabled`; the result is
not cached on `SBIconImageView`. Foundation forwards that call to
`_NSSwiftProcessInfo`. On its first query in a process, Foundation registers
the Darwin notification `com.apple.system.lowpowermode`, reads the associated
64-bit state, caches the resulting Boolean in process-local global state, and
updates that byte when the notification is delivered.

`scripts/lab/cnd_low_power_notify_probe.c` confirmed both sides on the VM. A
root lab process could change the notify state from `0` to `1` with
`notify_set_state` (status 0), and a separately launched process then reported
both notify state 1 and `NSProcessInfo.isLowPowerModeEnabled == YES`. Restoring
state 0 likewise made a subsequent process report false. The same new-process
seeding worked without posting the notification: set state 1 without a post,
launch a fresh process, then restore state 0 without a post.

That last sequence is a possible launch-window primitive, not a durable
Spotlight-scoped setting. Leaving the notify state at 1 affects every process
that initializes the Foundation query afterward. Posting the name updates all
existing subscribers. Avoiding the post limits disturbance, but an external
controller must set the state before Spotlight's first query, keep the launch
window free of unrelated process initialization, and restore it only after
Spotlight has cached the value. Repeating that for every replacement PID still
requires a persistent launch observer/supervisor, and power-state ownership can
overwrite the notify state later.

A direct redirect of `-[NSProcessInfo isLowPowerModeEnabled]` inside Spotlight
is therefore not an improvement: it remains PID-bound and changes every Low
Power Mode decision in Spotlight, while the existing
`effectivelyPrefersFlatImageLayers` redirect changes only the intended icon
presentation policy. The global notify route should remain a lab diagnostic,
not the production persistence mechanism.

### Current production process lifecycle

The polling lifecycle watcher is retired from production. Launch, activation,
toggle changes, Apply, Restore, and queue execution never call
`CNDIconServicesConsumerLifecycleStart`. The coordinator source remains for
bounded lab diagnostics and compatibility reads, but it is not an automatic
or user-facing runtime dependency.

Production exposes independent durable **SpringBoard Fixes** and **Spotlight
Fixes** actions. Each is adaptive: it runs immediately when queued alone or
after the queue's shared respring when another action establishes a boundary.
SpringBoard Fixes installs only the SpringBoard transparency and Clock/Calendar
presentation repair. Spotlight Fixes optionally installs the equivalent
Spotlight presentation repair, then always opens one bounded SpringBoard
RemoteCall session, creates a `NonInteractive` RunningBoard assertion with a
background jetsam-priority grant for the current Spotlight PID, retains it as
a SpringBoard-owned associated object, verifies it, and closes the session.
Cyanide keeps no timer, watcher, background task, or open RemoteCall channel
afterward.

The assertion is deliberately narrow. It addresses the observed Spotlight
`idle-exit`; it does not promise survival from a crash, forced termination,
SpringBoard restart, reboot, or severe memory pressure. A replaced Spotlight
PID needs another explicitly queued repair because an assertion and installed
method redirect are both process-incarnation scoped.

Persistent publication remains separate from presentation repair. SnowBoard
Apply and Restore publish and verify IconServices records before the shared
respring. They do not claim presentation completion and do not start lifecycle
machinery. The post-respring action must not call
`_ISInvalidateCacheEntriesForBundleIdentifier`: on iOS 26 that function sends
`clearCachedItemsForBundeID:reply:` to iconservicesagent and clears the
persistent records SnowBoard Remix replaced.

## Restore contract

Publication restore repeats the same one-shot service transaction but returns
the complete stock result from the original generator. Success requires:

Every descriptor in the journal is a separate IconServices index identity and
UUID-backed `.isdata` unit. The ordinary `RestoreStock` convenience call covers
only its default 68-point descriptor; it cannot prove that the 13, 27, 28, 38,
48, and appearance variants are stock. Bundle-wide invalidation is cheaper,
but its client boundary is void/asynchronous and only promises later lazy
regeneration. Production recovery therefore keeps per-descriptor stock
generation and exact cache/store readback. A future optimization may batch
those descriptor requests inside one daemon command, but must preserve the
same per-record proof.

- stock data contains no `CNDThemeIcon.v1` marker;
- stock UUID and validation token match the response readback;
- agent-cache data equals the stock response exactly;
- the UUID-named `.isdata` bytes equal the stock response exactly;
- the publisher IMP is stock and no copied invocation is in flight;
- the temporary publisher mapping is removed;
- the restored persistent IconServices records remain present;
- once every journaled descriptor for one app has exact stock cache/store
  readback, that app's recovery journal is removed immediately;
- later batch-transport finalization and any presentation/cache repair are
  reported independently and cannot re-dirty persistent data already proven
  restored.

Consumer presentation is process-resident. The physical flat-image redirect
also applies to stock responses and is retired only when the corresponding
SpringBoard or Spotlight PID exits. It does not alter the restored store bytes.

## Cyanide port contract

The production flow must keep publication and presentation as explicit phases:

```text
prepared
  -> service-response-built
  -> publisher-installed
  -> service-generation-matched
  -> publisher-restored
  -> agent-cache-verified
  -> indexed-store-file-verified
  -> active

Optional presentation follows as a separate non-authoritative branch:

```text
active
  -> current SpringBoard one-shot queued
  -> current Spotlight one-shot queued
  -> explicit Spotlight watcher started only by user action
```
```

Every phase must fail closed. In particular:

- use `generateImageWithDescriptor:`, never
  `prepareImageForDescriptor:`, for the publication trigger;
- issue that request through the retained `iconservicesagent` session so the
  replacement return drives IconServices' automatic publication transaction;
- accept exactly one target bundle/68-point/3x generation request;
- call stock generation before constructing the replacement;
- pass through the stock UUID, including a legitimate pre-persistence nil,
  and always reuse the validation token;
- bind the canonical UUID only from the exact data/token-matched outer
  cache/store response; never synthesize it in Cyanide;
- restore the original publisher IMP before releasing or unmapping code;
- require zero in-flight calls before unmapping;
- require exact `.isdata` readback before claiming persistence;
- never call or hook SpringBoard/Spotlight during publication;
- install presentation state separately and report each process/PID;
- require SpringBoard presentation before the Apply-time consumer-cache
  refresh;
  an idle Spotlight install may remain separately pending without rolling
  back verified persistent publication;
- never call `_ISInvalidateCacheEntriesForBundleIdentifier` after publication
  or restoration because its daemon-side cache clear discards the verified
  persistent response;
- refresh SpringBoardHome's process-local consumer caches in the same
  SpringBoard session used for presentation installation;
- never call a same-process cache hit a persistence proof;
- never claim transparent visual success from publication alone;
- never mutate the target application's bundle or LaunchServices registration
  in this route.

The implementation surfaces corresponding to this contract are:

| Responsibility | Cyanide source |
| --- | --- |
| RGBA scaling and validation | `CNDIconThemeImageProcessor.m` |
| Structured marker response | `CNDIconServicesStructuredPayload.m` |
| One-shot agent publisher | `CNDIconServicesPublisherPayload.c` |
| Publisher installation/readback | `CNDIconServicesPublisher.m` |
| Themed-only consumer payload | `CNDIconServicesConsumerPayload.c` |
| VM direct consumer mapping installer | `CNDIconServicesConsumerKernelInstaller.m` |
| Physical Apple-signed IMP consumer installer | `CNDIconServicesConsumerHook.m` |
| PID lifecycle watcher | `CNDIconServicesConsumerLifecycleCoordinator.m` |
| VM/legacy non-PAC task bridge; arm64e fail-closed guard | `CNDKernelTaskBridge.m` |
| Production transaction orchestration | `CNDSnowBoardRemix.m` |
| Retained single-app laboratory proof | `CNDIconServicesInterceptProof.m` |
| VM control implementations | `scripts/lab/cnd_iconservices_cache_theme.*` and `scripts/lab/cnd_spotlight_chiclet_patch.*` |

## Required verification sequence

For the controlled eBay proof:

1. Confirm no bundle transaction or IconServices recovery is pending.
2. Snapshot eBay's `Info.plist`, `Assets.car`, and declared legacy files as
   immutable controls.
3. Build the marked structured 68-point/3x response.
4. Run one direct generation publication.
5. Verify the original publisher IMP, zero in-flight count, removed payload
   mapping, clean transport, exact agent cache, and exact `.isdata` bytes.
6. Verify the immutable controls did not change.
7. Install and verify SpringBoard presentation for its exact PID.
8. Without opening Spotlight, verify its resident PID receives the presentation
   redirect before opening it, then search for eBay.
9. Confirm the first visible presentation on both surfaces shows themed RGBA
   pixels with no grey plate, border,
   corner mask, or shadow.
10. Restart Spotlight and verify publication remains while presentation is
    absent; rearming only the new Spotlight PID must restore correct visual
    presentation.
11. Restore stock through the one-shot IconServices path and verify exact
    `.isdata` stock bytes before clearing recovery.
12. Restart consumers if the test requires removing their resident flat-image
    redirects.

This sequence distinguishes three facts that must never be collapsed into one
success flag: the response was generated, the response was durably stored,
and each UI consumer was prepared to render its transparency correctly.
