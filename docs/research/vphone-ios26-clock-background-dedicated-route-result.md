# iOS 26 dedicated Clock-background route result

**Date:** 2026-09-24
**VM:** `cyanide-ios26-base`
**Branch:** `research/vphone-ios26-spotlight`

## Result

The proposed SpringBoard-only redirect to a dedicated Clock background object
is **not proven safe and must not be promoted to production in its current
form**.

The VM-only probe successfully constructed all of the intended isolated
objects after SpringBoard was running:

- an exact `68x68@3`, appearance `0`, variant `0`, special-options `2`,
  layout-direction `5` descriptor with digest
  `9E1D8C88-D314-329D-BE0F-1D262142B74B`;
- a dedicated `SBLeafIcon` with identifier
  `com.apple.application-icon.clock.base`;
- a dedicated `ISLayeredIcon` source with the same type identifier;
- a 204x204 transparent `IFConcreteImage` made from the staged
  `__cnd_clock_background` asset;
- a redirect of `SBHClockApplicationIconImageView -iconForImage` to the
  dedicated leaf.

The replacement decoded-pixel SHA-256 was
`8e42bb697fa62780cf9ceaa1a35bcece6f19d66a9109a9d7a6c510accb2aa483`.
Its alpha counts were 34,564 transparent, 2,849 translucent, and 4,203 opaque
pixels. Two pairs of probe-created consumers resolved the dedicated leaf,
source, exact descriptor, and replacement pixels without a view lookup.

That isolated success did not extend to a real SpringBoard consumer. The
route log for SpringBoard PID 821 contains exactly four `view-hit` events, all
from the probe's two explicit consumer phases. Opening the next Home surface
to make SpringBoard construct real icon views produced no fifth hit and
terminated SpringBoard before a real Clock consumer reached `-iconForImage`.

The crash was:

```text
SpringBoard-2026-09-24-043237.ips
PID 821
EXC_BAD_ACCESS / SIGBUS
KERN_PROTECTION_FAILURE at 0x0000000c58bb0d68

objc_retain
-[ISConcreteIcon _imageFromStoreForDescriptor:]
-[ISConcreteIcon _cachedImageForDescriptor:]
-[ISConcreteIcon imageForDescriptor:]
SBHIconServicesImageForDescriptor
SBHGetIconImageWithImageAppearance
SBHGetApplicationIconImageWithImageAppearance
SBHGetApplicationIconImageWithTraitCollection
-[SBLeafIcon customLoadingIconImageWithInfo:traitCollection:options:]
...
-[SBIconListView configureIconView:forIcon:]
-[SBFolderView scrollViewDidScroll:]
```

A separate attempt to load the same probe at SpringBoard startup also caused
repeated failures in the same ordinary `ISConcreteIcon` store-read family
before the probe reached `READY`. The two temporary startup-loader files were
removed immediately. SpringBoard recovered, and `iconservicesagent` remained
unchanged at PID 266 throughout the final post-launch attempt.

## Decision

- Do not change the production Clock implementation from this result.
- Do not claim a real Clock view, live hands, Home reconstruction, or
  Spotlight acceptance from the isolated hashes.
- Do not repeat startup injection or `iconservicesagent` replacement.
- Ordinary `com.apple.mobiletimer` records, Spotlight, Calendar, Clock hands,
  transition descriptors, and persistent publication were not modified.
- The next experiment must first explain why introducing the dedicated
  process-local source makes an unrelated ordinary `ISConcreteIcon` store
  read retain an invalid address. It must use a fresh VM snapshot or otherwise
  establish an uncontaminated IconServices store before testing a real view.

No recursive view/window walk, visible-view paint, repair timer, production
publication change, or physical-device installation was performed.
