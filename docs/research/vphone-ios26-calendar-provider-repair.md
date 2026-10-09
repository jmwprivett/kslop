# iOS 26 Calendar provider repair

This is the authoritative implementation note for theming Calendar without a
respring on iOS 26.0 (`23A341`). It supersedes earlier experiments that treated
a successful provider callback, a populated source cache, or a valid Calendar
object from `SearchUIHomeScreenModel` as sufficient proof.

## Non-negotiable identity rule

Calendar is dynamic. A valid themed `SBHCalendarApplicationIcon` is not
necessarily the object that owns the mounted consumer. Before changing its
provider, resolve the authoritative model for the target process.

### SpringBoard

Resolve Calendar only through the Home model:

```text
SBIconController.sharedInstance
  -> iconManager
  -> iconModel
  -> applicationIconForBundleIdentifier:(com.apple.mobilecal)
```

Collect and deduplicate that canonical object plus matching objects from the
authoritative `leafIconsUniquedByApplicationBundleIdentifier` collection.
Never consult `SearchUIHomeScreenModel` in SpringBoard. The class exists in the
process, but its Calendar object is not Home's mounted consumer.

### Spotlight

Spotlight has its own private `SBHIconModel`. Resolve Calendar from that model,
not from the convenience materializer's returned object:

```text
SearchUIHomeScreenModel.sharedInstance
  -> iconModel
  -> applicationIconForBundleIdentifier:(com.apple.mobilecal)
```

If the private graph has not initialized, call
`appIconForApplicationBundleIdentifier:` only to bootstrap it. Discard the
returned icon, reacquire the graph, and resolve Calendar again through the
private `SBHIconModel`. If that authoritative lookup fails, fail the repair;
do not accept the bootstrap object or fall back to SpringBoard singletons.

## Required persistent inputs

The process-local repair starts only after persistent publication succeeds and
the active journal supplies both exact Calendar responses:

- `68x68@3`, appearance 0;
- `68x68@3`, appearance 1.

Upload the exact journal-verified structured response bytes into the target
process. A nonempty cache entry is not verification: the bytes returned from
the target source cache must equal those uploaded responses.

## Provider bridge

For every authoritative Calendar model:

```text
SBHCalendarApplicationIcon.imageProvider
  -> SBCalendarIconImageProvider.preparedISIcon
```

The replacement source is the registered
`ISBundleIdentifierIcon/com.apple.mobilecal`. Preserve the provider's original
class and procedural `CUIKIcon` source in the bounded recovery registry. The
bridge uses a provider subclass whose `preparedISIcon` implementation is
`objc_getAssociatedObject`; the exact Objective-C ABI is `@16@0:8`.

Each active model owns its own provider. Do not treat one provider as global.
Reconcile retained registry entries against the current authoritative provider
set, restore and remove stale entries, and cap the set at eight objects.

## Source-cache sequence

For each distinct replacement source:

1. Resolve `ISBundleIdentifierIcon.imageCache`.
2. Verify it is an `ISImageCache` with the expected getter/setter ABIs.
3. Replace `imageBagsByDescriptor` with a fresh empty dictionary.
4. Prepare the exact 68-point appearance-0 response.
5. Prepare the exact 68-point appearance-1 response.
6. Inspect the bounded `ISImageCache -> ISImageBag -> IFImage.data` graph.
7. Require byte equality with both uploaded journal responses.

The refill poll is bounded. Empty entries, merely nonempty entries, UUID-only
agreement, or an unverified response are failures.

## Consumer update

After the source cache contains both exact responses:

1. Call `SBCalendarIconImageProvider.reloadIconImage` once per authoritative
   provider.
2. Verify its delegate is the expected Calendar model.
3. Verify `imageGeneration` advances by exactly one.
4. In SpringBoard, call the current primary
   `SBHIconImageCache.updateImageForIcon:` once per deduplicated Calendar model
   using the verified ABI `v24@0:8@16`.
5. Spotlight does not use SpringBoard's primary cache update; its exact private
   model/provider callback is the consumer boundary.

Do not follow this terminal Calendar update with a broad cache reset, generic
installed-app reload, recursive view walk, relayout guess, or direct layer
paint.

## Restore

Restore uses the same authoritative model rules. For every retained provider:

1. Restore its original class.
2. Clear the associated replacement source.
3. Verify `preparedISIcon` again returns a fresh procedural `CUIKIcon` source.
4. Call the provider reload callback and verify the consumer update.
5. In SpringBoard, perform the same bounded per-Calendar primary-cache update.
6. Remove the registry only after every provider restores successfully.

## Physical-device proof and false-success signature

The decisive failing trace reported a completely successful provider/source
transaction for `0xb2a1b37a0`, including two exact responses, while the Home
Calendar remained stock. The mounted Home model was actually `0xb27d64820`,
owned three live icon-layer views, and still returned `CUIKIcon`. This proved
that source-cache verification on the wrong model is a false success.

After enforcing the SpringBoard model boundary, both the repaired canonical
and mounted model were `0xb27d64820`. Its source changed from `CUIKIcon` to
`ISBundleIdentifierIcon`, generation advanced from 2 to 3, four mounted layer
views remained attached, and Calendar repainted immediately. The primary and
root cache pointers both remained `0xb295f7160`; SpringBoard PID 1091 did not
change.

## Acceptance checklist

A Calendar repair is accepted only when all of the following agree:

- target process identity is unchanged;
- the model came from the target's authoritative model graph;
- every current provider is bridged and no stale provider remains;
- both 68-point appearance responses match exact journal bytes;
- every provider callback succeeds;
- every model generation advances exactly once;
- SpringBoard's bounded per-model cache update succeeds when required;
- Apply visibly themes Calendar and Restore visibly returns it to stock;
- no recursive view scan, live paint, broad cache reset, or respring occurs.

Production lives in `Cyanide/tweaks/themer.m`, primarily
`themer_configure_calendar_provider_source`,
`themer_calendar_configure_active_provider`, and
`themer_calendar_refresh_springboard_consumer_cache`. The chronological VM and
physical evidence remains in `vphone-ios26-calendar-order-experiment.md`.
