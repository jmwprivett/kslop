# vPhone iOS 26 `clock.base` persistence experiment

**Date:** 2026-09-24
**Branch:** `research/vphone-ios26-spotlight`
**VM:** `cyanide-ios26-base`
**Result:** the persistent-publication decision gate failed; production was
not changed.

The complete client, daemon, and reconstructed SpringBoard trace is saved in
[`vphone-ios26-clock-base-persistence-experiment.log`](./vphone-ios26-clock-base-persistence-experiment.log).
The focused client is
[`cnd_clock_base_persistence_probe.m`](../../scripts/lab/cnd_clock_base_persistence_probe.m).

## Experiment

The root client loaded IconServices and constructed exactly:

```objc
[[ISLayeredIcon alloc]
    initWithTypeIdentifier:@"com.apple.application-icon.clock.base"
               layerGroups:@[]]
```

Each instance was passed to `-[ISIconManager findOrRegisterIcon:]`. Image
requests used `-[ISIcon prepareImageForDescriptor:]` followed by
`-[ISIcon imageForDescriptor:]`; `_generateImageWithDescriptor:` was never
used as the client proof boundary.

The descriptor was created from
`+[ISImageDescriptor imageDescriptorWithIconVariant:options:]` with preset
zero and options zero, then set to:

| Field | Observed value |
|---|---:|
| size | 68 × 68 points |
| scale | 3 |
| appearance | 0 |
| variant options | 0 |
| special icon options | 2 |
| layout direction | 5 |
| digest | `9E1D8C88-D314-329D-BE0F-1D262142B74B` |
| output | 204 × 204 RGBA |

The same request was made through the same icon twice, a second fresh icon, a
third fresh icon after fetching `+[ISIconManager sharedInstance]` again, and
the first icon after clearing its process-local `ISImageCache` with
`-setImageBagsByDescriptor:`. The cache contained two images before the clear
and zero afterward.

The daemon-side control used an ordinary `ISBundleIdentifierIcon`. It reached
`IconCacheService -generateImageWithRequest:reply:`,
`ISGenerationRequest -generateImageReturningRecordIdentifiers:`, and
`ISStore -addUnitWithData:` / `-writeStoreUnit:`. The same daemon observer was
active while the `clock.base` client and SpringBoard requests ran.

Finally, SpringBoard was restarted and the trace was injected 0.180 seconds
after the replacement process appeared. When the newly constructed Clock
consumer exposed its exact `SBLeafIcon`, one bounded
`-[SBLeafIcon iconImageWithInfo:]` request was issued on that leaf. This did
not enumerate windows or views and did not modify or repaint a view.

## Findings

`clock.base` does not become a canonical indexed icon at this boundary.

- `findOrRegisterIcon:` returned its input object unchanged. Two fresh icons
  remained different objects with different `_identity` values. A third icon
  registered through a freshly fetched manager also returned itself.
- `_identity` and `IFConcreteImage -uuid` behave as generated UUID accessors,
  not stable store identities. In the SpringBoard trace the same icon reported
  `F9EE25FA-3F92-4FEB-BA18-98D35C54EC07` entering registration and
  `9FF7C232-F946-44CC-9FDE-6DA3354DB7CC` on return. Consecutive `-uuid`
  calls on one image likewise returned different values.
- Every `clock.base` result was `IFConcreteImage`, never `IFCacheImage`.
- Every result had a zero-length validation token.
- `-[ISStore unitForUUID:]` returned `nil` for every observed UUID.
- The manager store root existed at:

  ```text
  /private/var/containers/Shared/SystemGroup/
  systemgroup.com.apple.lsd.iconscache/Library/Caches/
  com.apple.IconsCache/A8076D20-002A-3534-AFD9-AC4B7E058B7C
  ```

  but the derived `<uuid>.isdata` paths did not exist and always had length
  zero.
- Clearing the local `ISImageCache` forced regeneration but did not create a
  token or store unit.
- The daemon observer recorded ordinary bundle generation/store traffic but
  no `clock.base` or `ISLayeredIcon` request during either the client or
  SpringBoard experiment.

The deterministic stock output was:

| Measurement | Value |
|---|---|
| structured data length | 332,976 bytes |
| structured data SHA-256 | `a72c24caf2cd16bfa446b72f207dc827dd8d3362f9d1121cce21101da32fa932` |
| decoded RGBA SHA-256 | `231669e1c03cbe4770663f7d16926372f190ed68545bfd285b50da3af5307d08` |
| transparent pixels | 2,324 |
| translucent pixels | 548 |
| opaque pixels | 38,744 |
| alpha range | 0–255 |

The hashes remained identical after the local cache clear, in fresh client
processes, after `iconservicesagent` replacement, and after SpringBoard
reconstruction. This proves deterministic generation, not persistence.

The reconstructed live consumer showed the normal outer path explicitly:

```text
SBLeafIcon (com.apple.application-icon.clock.base)
  -> ISIconManager findOrRegisterIcon:
     (returns the same ISLayeredIcon)
  -> ISLayeredIcon imageForDescriptor:
  -> ISLayeredIcon imageForImageDescriptor:
  -> ISImageCache imageForDescriptor:          (miss)
  -> ISLayeredIcon _generateImageWithDescriptor:
  -> IFConcreteImage 204×204
```

The exact live request used the expected 68×68@3 descriptor, digest, special
options, and layout direction. Its generated image was inserted only into the
per-icon `ISImageCache`. No request crossed into `iconservicesagent`.

For comparison, the ordinary bundle control returned an `IFCacheImage` with a
40-byte validation token and a real indexed store unit. Its forced-generation
unit UUID was `EBE2AC36-A34B-394C-A08E-7F744A3D0732`, and the matching
`.isdata` file was written and read back successfully.

## Restart result and decision

The original `iconservicesagent` was terminated and demand-launched as a new
process. A fresh root client still produced only local `IFConcreteImage`
objects with the same hashes and no store units. SpringBoard was also replaced
and its newly constructed Clock consumer reproduced the same local path.

There is therefore no indexed response to replace with the established
persistent-store transaction. Creating a synthetic bundle record or treating
a generated `IFConcreteImage` UUID as canonical would contradict the trace.

The Phase 1 decision gate is **not satisfied**:

- no canonical indexed response exists at the registered `clock.base`
  boundary;
- identity is not reproducible from a fresh icon;
- no stock UUID/token/store unit can be journaled or replaced;
- restart stability comes from deterministic regeneration, not store lookup.

Production phases 2–4 were intentionally not started. The ordinary
`com.apple.mobiletimer` matrix, Spotlight static Clock behavior, live hand
machinery, Calendar provider, transition descriptors, and current experimental
leaf bridge remain unchanged. The next research step, if pursued, must look
outside `ISLayeredIcon` registration for a stock canonicalization boundary;
it must not invent a fake bundle identity or return to visible-view repair.
