# Hail Mary switcher and App Library follow-up

Status: **offline switcher derivation complete; live VM App Library route
captured and corrected; no safe miniature redirect selected.**

The source is the exact local Apple restore image
`iPhone17,2_26.0_23A341_Restore.ipsw` and its arm64e cache. The cache identity
is main UUID `DC5F2F67-1FC8-3905-873B-35D17D1A44E8`; the packed dispatch
entries are in `.34.dyldreadonly`, UUID
`CEEB0D68-9BA9-3CC8-AEB1-8F23BAC92B58`. The four original/replacement IMPs
are in signed RX subcache `.42`, UUID
`A495BF0F-60DC-3D51-8419-191FB857CE31`. Code-directory pages for both
subcaches were verified against the IPSW trust cache.

The reproducible derivation is
`scripts/derive_switcher_imp_redirect.py`; its reviewed output is
`docs/research/switcher-imp-redirect-23A341-iphone17,2.json`. The tool is
offline-only and contains no device access or writer.

## App-switcher title icons

The visible 28-point title icon is not an `SBIconImageView`. Stock
SpringBoard constructs an `SBHIconLayerView` and stores it in the title item's
view slot. SpringBoard already contains a complete parallel flat path: a
controller method returns `UIImage`, and a title-item setter stores it in the
image slot.

The two existing Apple method pairs are ABI exact:

| Role | Target | Replacement | Encoding |
| --- | --- | --- | --- |
| Storage | `-[SBFluidSwitcherSpaceTitleItem setImageView:]` | `-[SBFluidSwitcherSpaceTitleItem setImage:]` | `v24@0:8@16` |
| Provider | `-[SBFluidSwitcherSpaceTitleItemController _iconViewForDisplayItem:]` | `-[SBFluidSwitcherSpaceTitleItemController _iconImageForDisplayItem:]` | `@24@0:8@16` |

Both target selectors have packed preoptimized dispatch entries. Each
redirect preserves the 26-bit selector field and changes only the low 32-bit
portion of the signed 38-bit class-relative IMP field:

| Role | Slot and unslid entry | Original low word | Redirected low word | 16K frame |
| --- | --- | --- | --- | --- |
| Storage | slot 2, `0x1ffd55c98` | `0x18f3969f` | `0x18f396a4` | `0x1ffd54000` |
| Provider | slot 10, `0x1ffd8b488` | `0x18daa06b` | `0x18daa0ad` | `0x1ffd88000` |

The exact 32-byte guards are in the JSON manifest. Decoding the redirected
values resolves to `0x21d864010` (`setImage:`) and `0x21dea17c4`
(`_iconImageForDisplayItem:`), respectively. Neither value contains a pointer
or PAC bits.

### Safety consequence

This is not another one-write experiment. The entries occupy two different
`.34` pages, so the prior `SBIconImageView` page proof cannot authorize either
one. A live implementation must first perform an identical-bytes permission
probe against each exact page and bind each result to the fresh slide, frame,
physical address, aperture KVA, and guard.

The provider and storage redirects are also a matched type transaction.
Installing only the provider can pass a `UIImage` to the view setter;
installing only the storage can pass an `SBHIconLayerView` to the image setter.
Apply must therefore write storage then provider while switcher rebuilding is
quiescent; Restore reverses that order under the same condition. A durable
journal must record both independent inverse words before the first semantic
write and must represent the possible one-of-two partial state explicitly.
There is no honest atomic or single-write claim because the entries are on
different pages.

No live switcher mutation has been implemented or attempted from this
derivation.

## App Library category miniatures

The earlier offline interpretation was incomplete. The three
`SBFolderIconImageCache` implementations still exist at the previously
recorded addresses, but the live iOS 26.0 (`23A341`) App Library category pods
did **not** call them while rendering their visible miniatures.

The focused VM trace in
`scripts/lab/cnd_springboard_surface_trace.m` installed ABI-checked hooks on
all three folder-image boundaries, then left and re-entered App Library. The
focused capture observed:

- 34 `SBHLibraryCategoryPodIconListView configureIconView:forIcon:` calls;
- 0 `SBFolderIconImageCache gridCellImageForIcon:imageAppearance:` calls;
- 0 class renderer calls;
- 0 `gridCellImageOfSize:forIconImage:` compositor calls;
- 14 complete, scoped 27-point IconServices return captures.

Both class hooks were live during the capture. Their runtime encodings were:

```text
+gridCellImageOfSize:forIcon:iconImageInfo:imageAppearance:imageAttributes:
  @88@0:8{CGSize=dd}16@32{SBIconImageInfo={CGSize=dd}dd}40@72^Q80

+gridCellImageOfSize:forIconImage:
  @40@0:8{CGSize=dd}16@32
```

The first method's final argument is `^Q`, not an Objective-C object. The
tracer now checks that exact ABI before installing either hook.

### Live miniature route

The visible `SBHLibraryCategoryPodIconView` objects instead requested each
child directly from IconServices:

```text
SBHLibraryCategoryPodIconListView configureIconView:forIcon:
  -> SBHGetApplicationIconLayerWithTraitCollection / image counterpart
  -> SBHGetApplicationIconLayerWithImageAppearance / image counterpart
  -> SBHIconServicesImageForDescriptor
  -> -[ISBundleIdentifierIcon imageForDescriptor:]
  -> IFCacheImage
```

The scoped descriptor was consistently 27 by 27 points at 3x, appearance 0,
appearance variant 0, icon variant 0, and options 0. Its returned
`IFCacheImage` exposed an 87 by 87 `CGImage`; no scoped
`generateImageWithDescriptor:` call occurred. This is a direct cached
IconServices route, not a folder-composite refresh route.

Every one of the 14 saved returns had the same alpha geometry: 368 transparent
pixels, 220 translucent pixels, and 6,981 fully opaque pixels out of 7,569
(92.2% opaque). The saved Preview, Notes, and Health samples visibly contain
their rounded-square plate already. The plate therefore exists in the
IconServices return before any App Library category consumer displays it.

Local evidence for this boot is under
`build/lab-springboard-surface-trace/app-library-route-20261008-0614/`:

- `cyanide-springboard-surface-trace.log`;
- `cyanide-app-library-iconservices-001.png` through `-014.png`;
- `app-library-focused-trace.png`.

### Consequence

The failed physical cache experiment now has a direct explanation:
`SBFolderIconImageCache` purge/rebuild work cannot refresh these App Library
miniatures because the visible pods do not consume that route. Reloading the
shared `SBApplicationIcon` objects can disturb Home/dock consumers without
changing the target pixels.

The next VM canary should operate on the exact 27-point
`ISBundleIdentifierIcon` result path and prove a type-correct transparent
replacement for one bundle while leaving Home, dock, App Library list rows,
and ordinary folders unchanged. Only after that proof should offline work look
for a writable shared-data target. The known IconRendering instruction at
`0x1b0d5065c` remains RX text and is not a writable-data candidate.
