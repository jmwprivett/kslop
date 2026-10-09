# iPhone iOS 26 SpringBoard cache invalidation matrix

Build: `23A341`
Profile: `iPhone17,3`
Primary cache/surface trace PID: `39`. Notification follow-up baseline:
`2772`. A deliberately broad research-only metadata inventory held the main
thread too long and caused the intervening SpringBoard restart; no production
refresh was invoked. Therefore the final no-restart acceptance run is not yet
claimed, and every focused notification experiment below stayed on PID
`2772`.
Dyld cache: `${HOME}/Library/CyanideVPhoneLab/analysis/dyld-23A341/23A341__iPhone17,3/dyld_shared_cache_arm64e`

This document separates three independent states: persistent IconServices
records, SpringBoard's process-local caches, and already-materialized consumer
objects. A themed persistent lookup is never counted as proof that a visible
consumer repainted.

## Persistent producer proof

The rows below are unhooked persistent readbacks for
`com.apple.DocumentsApp`. `data` is the SHA-256 of the structured
IconServices response and `rgba` is the decoded pixel SHA-256. UUIDs can
change after a later replacement; descriptor plus both hashes are the stable
identity used by the experiments.

| Descriptor | Themed UUID | `data` SHA-256 | Pixels / `rgba` SHA-256 |
| --- | --- | --- | --- |
| 13x13@3, appearance 0, variant 0 | `58D4D908-096E-3743-BC8E-613F6E4DE3B9` | `232a8631b9222ce0ad59615667c6509129953a73230b998e912bd0a08a272c6d` | 60x60 / `ce94ce301a5ee1c028f7f300a6604ca2c2151a0e78c7b5e7ed739aedd66a8eb8` |
| 27x27@3, appearance 0, variant 0 | `710A2373-51DD-3AC8-AF53-CC43212F705A` | `28c496427772dd7b07264d0f42b898765b2ab38ed297cc8bfa74a2ae46bac90a` | 87x87 / `65d3dedd9d86794bd982d41013453a6305be935e53e7f3a0b86e3330c3eb6eaf` |
| 27x27@3, appearance 1, variant 0 | `11C97B84-2542-34EA-99BF-A3FFB95410CC` | `8d60f08d3b72860472704e2530ba8b4c6f180257c8a9b16f1943d285efd61534` | 87x87 / `65d3dedd9d86794bd982d41013453a6305be935e53e7f3a0b86e3330c3eb6eaf` |
| 28x28@3, appearance 0, variant 0 | `2D588334-8F42-3826-B7DC-1DC7990D2A0A` | `f31ce7bc6600fc423a3d0dc7f4491aded039a22e55ba671169a51ffbc4e89692` | 87x87 / `65d3dedd9d86794bd982d41013453a6305be935e53e7f3a0b86e3330c3eb6eaf` |
| 38x38@3, appearance 0, variant 0 | `8E649870-BCBF-3AD1-A15E-B52D24EB863B` | `a6e236b38bd10bd3c65560fb0eee5e1a66ffab295f585ad974ec5e8bd5fd785d` | 114x114 / `c6700efb7e81627be277172bac1a544e48852078d890336b5e7e4a31976a3c8c` |
| 38x38@3, appearance 1, variant 0 | `799B5C5B-165A-30F8-A9D1-CEF1E2C208F7` | `156aab4552e598d7b76257a833a788b102154d7387c1a9e95cdeccb4cddf8415` | 114x114 / `c6700efb7e81627be277172bac1a544e48852078d890336b5e7e4a31976a3c8c` |
| 48x48@3, appearance 0, variant 0 | `600B12ED-4A71-3ACD-8E50-61077EE0897B` | `581f25ed347b17bde23cf71d88e7417f28301559a63fcc7669daa8e9af078bc3` | 180x180 / `7be333e6c6436edb94e8a01e349afa7c3cd9332053f51627c6ddcf4b7505c9f4` |
| 68x68@3, appearance 0, variant 0 | `FB9E8D5D-E3FC-3F6F-8401-1170B4ABEFCF` | `eb8dd1e57f07dc9fc5cb1941562bbb40be351ffcfb862f536647045426ec6bab` | 204x204 / `c2277e4250cdbc8d9daa0b871f7d5dca5c7990c7f350f3f32a5e2e215cb0a8f9` |
| 68x68@3, appearance 1, variant 0 | `C82EF5C9-47E8-3A87-8397-F0EC94C795C1` | `84fff11f8c5f1412ac1a3779955caecf25b8759c341feb286312f56850550831` | 204x204 / `c2277e4250cdbc8d9daa0b871f7d5dca5c7990c7f350f3f32a5e2e215cb0a8f9` |
| 68x68@3, appearance 0, `variantOptions=0x20000` | `C233706B-F550-3357-AA50-3FC44C4DC339` | `5a520436611f082e6e3a22ac4320689334c9eb17d1ea3489cb3f76befb3d7817` | 204x204 / `c2277e4250cdbc8d9daa0b871f7d5dca5c7990c7f350f3f32a5e2e215cb0a8f9` |

No additional producer sizes were added. The failed repaint experiments all
started only after the required row above had an unhooked persistent readback.

## Cache and consumer matrix

Pointers are examples from PID 39 unless a row explicitly names PID 2772;
they are process-local, not constants.
“Reload” means the targeted application generation reload; it is bounded to
the active/restoring journal bundle identifiers and to canonical plus matching
live-leaf icon objects.

| Surface | Descriptor | Persistent UUID/hash | Cache owner/getter | Cache pointer | Materialized consumer | Purge selector | Repaint selector | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Home application icon | 68x68@3, appearances 0/1 | `FB9E8D5D…` / `eb8dd1e5…` / `c2277e42…`; `C82EF5C9…` / `84fff11f…` / same pixels | current `SBHIconManager.iconImageCache`; retained `SBRootFolderController.iconImageCache` propagated into root view, Home pages, dock, and mounted icon views | PID 2772 manager `0xb87bc1720`; the live root hierarchy remained on old `0xb88380a00` until explicit rebind | canonical and live-leaf `SBApplicationIcon`; `SBRootFolderController` → `SBRootFolderView` → `SBIconListView` / `SBDockIconListView` → mounted `SBIconView` / `SBIconImageView` | `resetAllIconImageCaches` replaces manager cache; purge old retained cache | `SBRootFolderController.setIconImageCache:` then `SBApplicationIcon.reloadIconImage`; final `SBHIconManager.relayout` | **Root-cache cause proved and fix implemented; end-to-end repeat pending.** Reset alone left Files stock. A focused probe found all three Home/dock lists on the old cache. The natural root setter rebound 3/3 lists and Files's live observer to `0xb87bc1720` without changing PID 2772. Reload remains necessary because canonical and leaf identities can differ. |
| Home folder preview | 13x13@3, appearance 0 | `58D4D908…` / `232a8631…` / `ce94ce30…` | outer `SBHIconManager.folderIconImageCache`; retained source `SBFolderIconImageCache.iconImageCache` | outer `0x7e3118030` stayed stable; source stayed on old `0x7e6468f00` after manager moved to `0x7e6f0caa0` | `SBFolderIcon` composite plus child application icons | purge retained source `SBHIconImageCache`; `rebuildAllCachedFolderImages` | targeted child `SBApplicationIcon.reloadIconImage`, then composite rebuild | **Pass.** Rebuild alone and source-purge+rebuild alone did not repaint. Child generation 2→3 did; production then rebuilds composites for existing and future previews. No unbounded folder-icon iteration is needed. |
| App switcher title | 28x28@3, appearance 0 | `2D588334…` / `f31ce7bc…` / `65d3dedd…` | `SBIconController.appSwitcherHeaderIconImageCache` | `0x7e6dcc280` in PID 39 and `0xb87bc3f20` in PID 2772 (aliases table UI cache; stable across reset) | title controllers in `SBDeckSwitcherViewController._appLayoutToTitleItemController`; visible `SBFluidSwitcherIconImageContainerView` reached through the exact `_visibleItemContainers`, `_visibleOverlayAccessoryViews`, and `_visibleUnderlayAccessoryViews` maps | `purgeAllCachedImages` | application generation reload; `_updateDisplayItemIcons`; clear `titleItems` on exact materialized consumers; `_performUpdateHandler` | **Missing retained-consumer cause proved statically and bounded fix implemented; live-card VM proof pending.** `_performUpdateHandler` computes a new title item, but `SBFluidSwitcherItemContainerHeaderView.setTitleItems:animated:` keys its image-view map by the unchanged `SBDisplayItem` and branches past `setImage:animated:` / `setCustomImageView:animated:`. Thus an existing card can retain stock pixels after a correct cache refill. Production now clears only map-reachable materialized consumers before rebuilding. Future cards use the purged cache. |
| App Library category large icons | 68x68@3, appearances 0/1 | `FB9E8D5D…` / `C82EF5C9…`; pixel `c2277e42…` | `SBLibraryViewController.iconImageCache` and `SBHLibraryPodFolderController.iconImageCache` | both `0x7e6468f00` before reset and new `0x7e6f0caa0` after | pod folder controller and `SBHLibraryCategoryPodIconListView` | covered by manager reset after reacquisition | app generation reload; pod `_reloadAppIcons`; library `_enqueueAppLibraryUpdate` | **Pass.** Existing category icons changed after the app reload/update; reopened categories used the new cache. |
| App Library category miniature | 27x27@3, appearances 0/1 | `710A2373…` / `28c49642…`; `11C97B84…` / `8d60f08d…`; pixel `65d3dedd…` | library manager cache plus folder-composite source | new manager `0x7e6f0caa0`; retained folder source `0x7e6468f00` | miniature child icon in category pod composite | manager reset plus retained folder-source purge | child application reload, folder rebuild, pod `_reloadAppIcons`, enqueue | **Pass.** Both appearance records resolve independently; the bounded child-generation and composite sequence updates existing pods and future composites. |
| App Library alphabetical/search list | 48x48@3, appearance 0 | `600B12ED…` / `581f25ed…` / `7be333e6…` | direct/search `SBHIconLibraryTableViewController.iconImageCache` | direct and search controller were the same `0x7e3fdd800`; cache changed `0x7e6468f00`→`0x7e6f0caa0` | current query and materialized `SBHIconTableViewCell` | manager reset/alias coverage after reacquisition | app generation reload; table `_reloadAppIcons`; `_reloadVisibleCells` | **Pass.** Table purge and both table calls alone left an open Files row stale. Application generation 3→4 repainted it; table calls remain required to rebuild closed/future and active-search query consumers. No `setActive:` and no view walk. |
| Notifications | 38x38@3, appearances 0/1 | `8E649870…` / `a6e236b3…`; `799B5C5B…` / `156aab45…`; pixel `c6700efb…` | Normal rows: `NCUIMappedImageCache.sharedCache` for `BBSectionIcon` recipes; auxiliary switcher-suggestion path: `SBIconController.notificationIconImageCache` | PID 2772 mapped `0xb86214c80`; auxiliary `0xb87bc23a0`; both stable across manager reset | retained `NCBadgedIconView._iconView` / `_subordinateIconView` reached through sections → groups → requests → current cells | mapped `removeAllObjects` plus `allKeys` FIFO barrier; auxiliary `purgeAllCachedImages` | forced section reload; clear retained `UIImageView.image`; `NCBadgedIconView._updateVisibleIcons` | **Cache and future-consumer path pass; live-row visual proof pending.** Mapped cache emptied 52→0. Fresh 38-point light/dark recipes each returned 114x114 themed pixels with `c6700efb…`. Five sections were reachable, but the VM currently had 0 groups/requests/cells, so existing-row Apply/Restore still requires a materialized notification acceptance run. |
| Launch and return transitions | 28x28@3 variant 0 and 68x68@3 `variantOptions=0x20000` | `2D588334…` / `f31ce7bc…` / `65d3dedd…`; `C233706B…` / `5a520436…` / `c2277e42…` | manager `SBHIconImageCache` | manager pointer above | transition `SBIconImageView` and crossfade consumer | manager reset | application generation reload; transition creates/refills consumer | **Pass.** Files launch and return requested these exact two descriptors. The themed UUID and pixel hash reached `setDisplayedImage:`; no speculative descriptor was needed. |

### Additional Share-sheet consumer boundary

AirDrop is not a SpringBoard surface, but its persistent pseudo-bundle record
uses the same publisher and exposed an important process-lifetime boundary.

| Surface | Descriptor | Persistent UUID/hash | Cache owner/getter | Cache pointer | Materialized consumer | Purge selector | Repaint selector | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Share sheet AirDrop tile | 64x64@3, appearance 0, variant 0 | `979F2325…` / data `f408d828…` / decoded pixels `e5e540dc…` | `SharingUIService` → `UIActivityContentViewController.activityImageProvider` → `SFUIImageProvider.imageCache` | provider `0x7b7355fe0` in PID 6173; cache object is process-local | horizontal activity cell retained the delivered stock `UIImage` `0x7b746c280` / RGBA `48fb01c4…` | no provider-specific purge selector; `NSCache.removeAllObjects` would not clear the cell's retained image | retire the exact `SharingUIService` incarnation after persistent verification; its normal relaunch rebuilds provider and cells | **Pass.** Publishing and unhooked readback alone left PID 6173 stock. Retiring only PID 6173 produced PID 6736, and the visible AirDrop tile immediately became themed without restarting SpringBoard. Production uses one identity-bound RemoteCall to that service, or no session when it is absent. |

## What reset actually does

The PID-39 before/after probe recorded:

```text
before manager=0x7e6468f00 folder=0x7e3118030
       folder-inner=0x7e6468f00 notification=0x7e6dcd2c0
       table=0x7e6dcc280 switcher=0x7e6dcc280
       library/pod/direct-table/search-table=0x7e6468f00

after  manager=0x7e6f0caa0 folder=0x7e3118030
       folder-inner=0x7e6468f00 notification=0x7e6dcd2c0
       table=0x7e6dcc280 switcher=0x7e6dcc280
       library/pod/direct-table/search-table=0x7e6f0caa0
```

The call completed synchronously in 255 microseconds. The manager's raw cache
ivar was nil immediately after reset and the getter then created
`0x7e6f0caa0`. Thus production must reacquire every getter. In particular:

- Home and all observed App Library getters follow the replacement cache.
- notification and table/switcher dedicated caches keep their instances and
  require an explicit purge;
- table UI and switcher are the same object and must be deduplicated;
- the folder-composite object stays alive and retains the old manager cache as
  its source, so that source must also be reacquired from the folder owner and
  purged;
- the live Home root hierarchy also stays bound to the old manager cache. The
  manager reset does not call `SBRootFolderController.setIconImageCache:`.
  Purging the old object is not enough; production must rebind the root after
  all purges and before application-generation reloads.

The focused PID-2772 reset repeated this result in 37 microseconds and added
the missing notification cache pointer proof:

```text
before manager=0xb88380a00 notification=0xb87bc23a0
       notification-mapped=0xb86214c80
after  manager=0xb87bc1720 notification=0xb87bc23a0
       notification-mapped=0xb86214c80
```

A subsequent focused consumer probe found the retained Home topology:

```text
manager=0xb87bc1720
root-controller/root-view/home-page-0/home-page-1/dock=0xb88380a00

after SBRootFolderController.setIconImageCache:
root-controller/root-view/home-page-0/home-page-1/dock=0xb87bc1720
```

The setter changed 3/3 root-owned list views and the Files observer binding;
SpringBoard stayed on PID 2772.

Thus `resetAllIconImageCaches` replaces neither notification cache. Production
reacquires both pointers anyway, then purges each through its own measured API.

Static disassembly corroborates the runtime result. On 23A341,
`-[SBHIconManager enumerateAllIconImageCachesUsingBlock:]` loads only the
single ivar at offset `0x98`. `resetAllIconImageCaches` enumerates/purges it,
stores nil to that ivar, and releases the old object. It does not forward to
the controller caches or the folder cache. Therefore a pre-reset cache pointer
must never be used as a stand-in for a post-reset owner lookup.

A complete Objective-C metadata sweep of the 23A341 SpringBoard image found
exactly three `SBHIconImageCache` ivars on `SBIconController`:
`_appSwitcherHeaderIconImageCache`, `_tableUIIconImageCache`, and
`_notificationIconImageCache`. The only other switcher image cache is
`SBAppSwitcherSnapshotImageCache`, which stores card snapshots rather than
title icons. For title icons, the remaining image-bearing state is the
materialized title-item chain: `SBFluidSwitcherSpaceTitleItem._image` /
`_imageView`, the item/overlay/underlay `_titleItems` arrays, and
`SBFluidSwitcherItemContainerHeaderView._itemsToIconImageViews`. This rules
out an undiscovered second switcher-title cache in the SpringBoard metadata;
the missing layer is the retained consumer handled below.

The corresponding SpringBoardHome sweep does expose the internal
`SBHIconImageVariantCache` pair (`_maskedCache` and `_unmaskedCache`) owned by
each `SBHIconImageCache`. It is not an additional owner requiring a separate
production selector: disassembly of `SBHIconImageCache.purgeAllCachedImages`
shows a main-thread assertion followed by
`enumerateVariantCachesUsingBlock:`, whose block calls
`SBHIconImageVariantCache.purgeAllCachedImages` for every variant, and then
`endObservingAllIcons`. Thus each explicit outer-cache purge already clears
the masked/unmasked image stores, stored generations, failed-icon state, and
icon-identifier mapping at their supported boundary.

## Selector/ABI and scheduling inventory

All production calls below execute through `r_msg2_main`; runtime probes
reported `main=1`. Each call returned before the after-state observation, so
the listed operations are synchronous at the invoked boundary. Production
checks every private mutator's exact runtime encoding before invoking it.

| Owner | Selector | Encoding | Observed effect |
| --- | --- | --- | --- |
| `SBHIconManager` | `iconImageCache`, `folderIconImageCache` | `@16@0:8` | Return current cache objects; the first lazily recreates after reset. |
| `SBHIconManager` | `resetAllIconImageCaches` | `v16@0:8` | Purges only the primary cache, nils/replaces it; no dedicated-cache forwarding. |
| `SBHIconManager` | `relayout` | `B16@0:8` | Returns whether relayout completed; false while a folder animation prevents immediate relayout. Production checks the BOOL. |
| `SBFolderController` / `SBRootFolderController` | `iconImageCache`, `setIconImageCache:` | `@16@0:8`, `v24@0:8@16` | The setter synchronously forwards through `SBFolderView`, every owned `SBIconListView`, and materialized `SBIconView` / `SBIconImageView`; the latter detaches from the old cache and observes the new one. |
| `SBHIconImageCache` | `purgeAllCachedImages` | `v16@0:8` | Immediately empties that cache object; it does not repaint retained consumers. |
| `SBHIconImageCache` | `updateImageForIcon:` | `v24@0:8@16` | Synchronously refreshed the exact mounted Calendar model after its verified provider/source bridge was installed. Production permits this only for Calendar's capped canonical/live-leaf set; it remains forbidden as an installed-app batch fallback. |
| `SBFolderIconImageCache` | `iconImageCache` | `@16@0:8` | Returns the retained source cache, which remains the old manager instance across reset. |
| `SBFolderIconImageCache` | `rebuildAllCachedFolderImages` | `v16@0:8` | Rebuilds registered composites; insufficient without application generation reload. |
| `SBIconModel` | `applicationIconForBundleIdentifier:` | `@24@0:8@16` | Returns canonical application icon. |
| `SBIconModel` | `leafIconsUniquedByApplicationBundleIdentifier` | `@16@0:8` | Returns live model leaves; canonical and visible leaf are not guaranteed identical. |
| `SBApplicationIcon` | `isApplicationIcon`, `reloadIconImage` | `B16@0:8`, `v16@0:8` | Reload increments generation, updates mounted layers, and notifies flat-image observers. |
| `SBLibraryViewController` | `iconImageCache`, `folderController` | `@16@0:8` | Bounded cache and category controller access. |
| `SBLibraryViewController` | `_enqueueAppLibraryUpdate` | `v16@0:8` | Enqueues the library's own category update after pod reload. |
| `SBHLibraryPodFolderController` | `_reloadAppIcons` | `v16@0:8` | Rebuilds category/pod application consumers. |
| `SBHIconLibraryTableViewController` | `iconImageCache` | `@16@0:8` | Returns list/search cache; it aliased the replacement manager cache in PID 39. |
| `SBHIconLibraryTableViewController` | `_reloadAppIcons`, `_reloadVisibleCells` | `v16@0:8` | Rebuilds table icon/query state, then reconfigures only materialized rows. |
| `SBSwitcherController` | `contentViewController` | `@16@0:8` | Returns `SBDeckSwitcherViewController`, the owner of the title-controller map. |
| `SBFluidSwitcherSpaceTitleItemController` | `_updateDisplayItemIcons`, `_performUpdateHandler` | `v16@0:8` | Recomputes retained title-item state after the app generation changes. |
| `SBFluidSwitcherItemContainer`, `SBFluidSwitcherSpaceOverlayAccessoryView`, `SBFluidSwitcherSpaceUnderlayAccessoryView` | `setTitleItems:animated:` | `v28@0:8@16B24` | Passing nil is SpringBoard's own synchronous title-removal path. It clears the retained header/footer mapping so the next controller update cannot take the equal-display-item image shortcut. |
| `NCUIMappedImageCache` | `sharedCache` | `@16@0:8` | Returns the BaseBoardUI-backed normal notification image cache; its pointer survived manager reset. |
| `BSUIMappedImageCache` | `removeAllObjects`, `allKeys` | `v16@0:8`, `@16@0:8` | Removal is queued asynchronously; the immediately following `allKeys` synchronously drains the same serial queue. Runtime result: 52→0 without a sleep. |
| `NCNotificationIconRecipe` | `imageForPointSize:interfaceStyle:completionOnMain:` | `v40@0:8d16q24@?32` | Fresh Files recipes returned themed 114x114 pixels for styles 1 and 2 on the main thread. The process-static app-ID dictionary retains `ISIcon` identity, not a decoded pixel result. |
| `NCNotificationStructuredSectionList` | `_reloadLeadingNotificationRequestsForStackedNotificationGroupListsWithForceReloadAllStacks:` | `v20@0:8B16` | Synchronously reloads each section's leading/stacked request consumers. |
| `NCNotificationStructuredSectionList` / `NCNotificationGroupList` | `allNotificationGroups`, `allNotificationRequests`, `_currentCellForNotificationRequest:` | `@16@0:8`, `@16@0:8`, `@24@0:8@16` | Fixed model/controller graph for materialized cells; production caps sections/groups/requests at 16/128/256. |
| `NCBadgedIconView` | `iconView`, `subordinateIconView`, `_updateVisibleIcons` | `@16@0:8`, `@16@0:8`, `v16@0:8` | Disassembly shows unchanged style plus non-null `UIImageView.image` skips refetch. Production clears those retained image slots, then invokes this refill method. |

`_NCIconImageForApplicationIdentifierWithFormat` has one process-static
dictionary, but its values are `ISIcon` identities rather than `UIImage`
pixels. Every call still constructs the requested descriptor and invokes
`ISIcon.prepareImageForDescriptor:`. The iOS 26 `ISIcon` instance has only its
lock and a signpost-ID dictionary—no decoded-image cache ivar. Accordingly,
production does not patch or clear that private global. The natural
`NCBulletinNotificationSource._applicationIconChanged:` listener is also not
used: it asynchronously asks BulletinBoard to resend section notices, while
the equal-description live-view fast path can still retain the old image. The
direct bounded row refill fixes the actual retained consumer without an async
notification round trip.

`ipsw dyld search objc` located the notification reload on
`NCNotificationStructuredSectionList`, `_updateVisibleIcons` on
`NCBadgedIconView`, reset on `SBHIconManager`, and the two title calls on
`SBFluidSwitcherSpaceTitleItemController`. The SpringBoardHome class dump also
exposed the folder cache's private source-cache property and the direct
App Library table/search controller graph.

## IconServices installation/garbage-collection boundary

An application install can expose a persistent-store failure that no
SpringBoard cache purge can repair. Static disassembly of iOS 26.0 23A341
establishes the following independent lifecycle:

1. `IconCacheService.clearCachedItemsForBundeID:reply:` schedules cache
   operation 1. Despite accepting one bundle identifier, operation 1 is the
   global `ISMutableIconCache.collectGarbage` pass.
2. `collectGarbage` enumerates `unitSourceRegistry` and reconstructs each
   source through `-[LSRecord initWithPersistentIdentifier:]`.
3. A failed reconstruction calls `ISStore.removeUnitForUUID:` and then removes
   the source-registry entry. The next request regenerates a stock unit.

The source is an opaque LaunchServices record identifier, not a bundle ID.
The 36-byte application identifier contains a unit ID at offset 4, table ID at
offset 8, database GUID at offset 12, and an eight-byte application identity
at offset 28. LaunchServices rejects it if the database GUID differs, the
table/unit is absent, or the appended application identity no longer matches.
Thus an unrelated install can invalidate a themed unit if it replaces the
LaunchServices database generation.

The resident trace dylib now logs this boundary without mutating the store. It
hooks the bundle/all invalidation XPC methods, operation scheduling and run,
`collectGarbage`, source registration, `LSRecord` reconstruction, and exact
unit removal. An invalid source is retained in a fixed 128-byte thread-local
buffer only until the immediately following removal, allowing one line to pair
the raw source with the removed UUID. The trace classifies the failure as
`database-guid` or `unit-or-record-identity`, records the XPC caller PID when
Foundation exposes it, and caps each registration dump at eight identifiers.

The logger is resident in VM `<VM_HOST>` agent PID 2166. All 20 runtime ABI
checks passed. Its initial Messages identity was:

```text
bundle=com.apple.MobileSMS
sequence=1960
unitID=1960 tableID=8
databaseGUID=1F26ABB1-5FAA-455C-B070-6CC78C13193B
appIdentity=0x7a8
```

If the agent PID changes, arm the research-only logger again with:

```sh
CND_VPHONE_ROOT_PASSWORD=alpine \
  python3 scripts/lab/cnd_iconservices_inspection.py watch \
  --host <VM_HOST> --bundle com.apple.MobileSMS
```

Read the bounded lifecycle timeline after the next controlled reinstall with:

```sh
CND_VPHONE_ROOT_PASSWORD=alpine \
  python3 scripts/lab/cnd_iconservices_inspection.py read \
  --host <VM_HOST> --lifecycle-only
```

### Controlled Cyanide reinstall result

> Physical-audit correction (2026-09-24): the initial app-side rolling audit
> used `ISImageCache imageForDescriptor:`, which is process-local-only, and
> consequently recorded empty evidence as an all-unchanged comparison. The
> corrected audit uses the canonical `ISConcreteIcon imageForDescriptor:`
> path, which falls through to `_imageFromStoreForDescriptor:` and the indexed
> store. Schema-1 empty baselines are rejected; schema 2 requires concrete,
> internally consistent themed response/store evidence before writing a
> baseline and preserves the baseline when a reinstall difference is found.
> This correction does not change the independent VM GC trace below.

The 2026-09-24 controlled update install produced a complete causal trace
without restarting SpringBoard or `iconservicesagent`:

- `lsd` PID 131 called the bundle invalidation endpoint for
  `com.zeroxjf.ios-cyanide1`.
- Operation 1 was scheduled 1.462 ms after invalidation entry,
  `ClearCacheOperation.run` entered 0.166 ms later, and `collectGarbage`
  entered 16.261 ms after invalidation entry. This observed install path was
  immediate, not a roughly one-second delayed collection.
- Messages remained byte-for-byte stable before and after collection:
  unit/sequence 1960, table 8, database GUID
  `1F26ABB1-5FAA-455C-B070-6CC78C13193B`, application identity `0x7a8`, and
  persistent-ID SHA-256
  `9898ec6071111ef4b32fdb1bba61f66ff8d9eb5b4ee8fb246acb8980d569bd2d`.
- GC checked 189 source entries, accepted 186, rejected three, and removed
  exactly three store units. All three rejected entries had the same source:
  unit 2632, table 8, the unchanged current database GUID, and application
  identity `0xa48`. `LSRecord` reconstruction returned nil, so the logger
  classified this as `unit-or-record-identity`, not `database-guid`.
- The removed UUIDs were
  `36B9F041-205C-3E4A-9624-03A575BB1DD0`,
  `FA059E4E-F139-3209-8B42-E6368574EFA3`, and
  `3E5D376C-8FBB-3969-A051-DF2D1DEB127C`. Their exact pre-delete file hashes
  were respectively
  `a7a30ae958617c8bb18eea5258cc628cf4bf507a13a9e0e4be563d401ca09f3e`,
  `30670ffc1d76faea201447a7147a9ef340789564bec16f3e896d179942413813`,
  and `b0772b9ecdddfa9c067c6028de49ea445e1a9a46bfe60854165dfecd375a0f9c`.
- Ninety-one ms after collection returned, UUID
  `52D34001-1748-3044-9150-0D8469D358B6` was registered with source unit 2636
  and application identity `0xa4c`. An independent read-only
  `LSApplicationRecord` query proved that exact 36-byte identifier is the new
  current identity of `com.zeroxjf.ios-cyanide1`.

This proves that reinstalling Cyanide changes Cyanide's own LaunchServices
record identity and that the resulting bundle invalidation collects units
registered against the predecessor identity. It does **not** show a database
generation replacement and it did **not** invalidate Messages' own source
identifier.

The required themed-before-install control was then run for Messages
`68x68@3`, appearance 0, variant 0. Before reinstall:

```text
UUID=00C2AAE0-DC7F-3080-97AF-AC9EEB4974E8
data SHA-256=5204990e93369a3ed05476f9a4773c02478cccc185427e8582924d05eea9cb5e
pixel SHA-256=c2277e4250cdbc8d9daa0b871f7d5dca5c7990c7f350f3f32a5e2e215cb0a8f9
source unit=1960 table=8 appIdentity=0x7a8 (com.apple.MobileSMS)
```

The same UUID/data/pixel hashes survived an unhooked agent restart. A second
Cyanide reinstall then ran GC over 188 sources. It accepted 187 and removed
only UUID `52D34001-1748-3044-9150-0D8469D358B6`, whose source was Cyanide's
now-old identity 2636/`0xa4c`. Messages remained 1960/`0x7a8`. A post-install
normal cache lookup returned the exact same themed UUID, data hash, validation
token, and pixel hash shown above.

Therefore a correctly published Messages 68-point record is owned by the
target application's LaunchServices identity, not Cyanide's requester
identity, and survives Cyanide reinstall GC. This rules out the proposed GC
mechanism for this descriptor. It does not yet prove the independently keyed
27-point App Library or 28-point switcher records survived; those exact
descriptors must be themed and fingerprinted before another install before
attributing their visual regression to a consumer refresh versus persistent
record loss.

## Minimal deterministic production sequence

The independent experiments support this bounded sequence:

1. Finish and verify every persistent record, then snapshot the exact
   active/restoring bundle identifiers.
2. Open one SpringBoard session and resolve the fixed owner/controller graph.
3. Capture all cache pointers, call `resetAllIconImageCaches`, then reacquire
   every cache and the root controller from their owners.
4. Purge each distinct dedicated cache once, including the retained folder
   source and auxiliary notification cache. Purge `NCUIMappedImageCache`, then
   use `allKeys` as its FIFO completion barrier. Treat the new manager cache as
   covered by reset.
5. Rebind `SBRootFolderController` to the replacement manager cache. This
   synchronously propagates to its root view, Home pages, dock, and mounted
   icon image views.
6. Resolve and reload every distinct matching canonical and live-leaf
   `SBApplicationIcon`.
7. Rebuild folder composites; reload App Library pods/categories; reload the
   direct/search table controllers.
8. For switcher titles, update controller icon identities, clear `titleItems`
   only on consumers reached through the three explicit visible-consumer maps,
   then run the controller update handlers. Reload the five bounded
   notification sections, enumerate only their capped group/request model,
   and for each materialized `NCBadgedIconView` clear retained image slots and
   invoke `_updateVisibleIcons`.
9. Run one final manager relayout and require its BOOL result to be true.
10. Emit one compact result per surface and close the same session.

The same entry reaches this sequence after Apply and after persistent stock
restoration. Persistent recovery cleanliness remains based on verified stock
records; an optional presentation failure does not recreate or preserve a
successfully-cleared persistent journal.

## Remaining VM acceptance items

The cache ownership, future recipe, ABI, and bounded notification consumer
graph are proven,
but the complete acceptance run must not be marked complete until a real
notification request is present in `NCNotificationRootModernList` and its
existing and newly-delivered appearance-0/1 rows are visually/hash verified
through Apply and Restore. The authorized FaceTime local-notification probe
scheduled successfully but did not enter Notification Center (`groups=0`,
`requests=0` across all five sections); that is a materialization failure, not
an invalidation result.

The switcher's cache owner, exact retained-consumer maps, setter ABI, and
equal-display-item short circuit are established. The current PID-2772 VM had
no materialized title-controller map during the focused probe, so the new
clear-then-rebuild step still needs one already-visible Files card to record
its container image hash before and after. This is a remaining acceptance
proof, not justification for adding another cache or descriptor.
