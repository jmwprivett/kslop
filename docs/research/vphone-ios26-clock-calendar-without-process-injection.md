# iOS 26 Clock and Calendar persistence without process injection

**Date:** 2026-10-07
**Target:** iPhone17,3 vPhone, iOS 26.0 (`23A341`)
**Result:** there is no full-fidelity, reboot-safe Clock/Calendar theming route
on this build that uses only writable resources or the persistent IconServices
store. A fully themed live Clock and live Calendar still require a per-consumer
change in SpringBoard and Spotlight. A persistent static surrogate is viable if
losing live hands/date behavior is acceptable.

This pass was research-only. It did not change production code or install a
theme in the VM. Runtime instrumentation was used only as a bounded observer;
it is not part of the proposed non-injection design.

## Question answered

The desired property is stronger than surviving Cyanide's exit. The theme
should remain correct when SpringBoard or Spotlight is replaced, without
opening the new process and changing its Objective-C classes, methods, caches,
or live objects.

The stock paths on `23A341` divide into two categories:

```text
ordinary application icon
  -> ISBundleIdentifierIcon
  -> indexed IconServices response on disk
  -> fresh consumers can recover themed bytes

Clock / Calendar live icon
  -> SpringBoardHome special application-icon class
  -> process-owned generator/source
  -> IFConcreteImage / local ISImageCache
  -> no indexed response to replace
```

The first path is durable. The second path is reconstructed in every new
consumer process.

## VM evidence

### SpringBoard chooses special classes independently of the app catalog

`SBHIconModel -iconClassForApplicationWithBundleIdentifier:` contains direct
handling for both `com.apple.mobiletimer` and `com.apple.mobilecal`. Clock also
declares `SBIconClass = SBClockApplicationIcon` in its app `Info.plist`.
Calendar does not need that declaration because SpringBoardHome performs its
own bundle-identifier selection.

Consequences:

- changing either app's `CFBundleIconName` or static `AppIcon` does not turn
  the live Home Screen model into an ordinary `SBApplicationIcon`;
- removing Clock's `SBIconClass` is not sufficient;
- a persistent ordinary `com.apple.mobiletimer` or `com.apple.mobilecal`
  IconServices record can cover generic consumers, but does not replace the
  source selected by the special model.

### Clock has three distinct resource boundaries

The writable Clock app catalog contains a complete static icon stack:

```text
AppIcon/2.dial
AppIcon/3.dialnumbers
AppIcon/4.hourhand
AppIcon/5.minutehand
AppIcon/6.secondhand
```

That stack is useful to ordinary icon generation, but it is not the source of
the live SpringBoard Clock.

The live Clock face is an `SBLeafIcon` whose type is
`com.apple.application-icon.clock.base`. Its data source creates a local
`ISLayeredIcon`; the exact `68x68@3` request returns `IFConcreteImage` and is
cached only by that icon instance. The previous persistence experiment proved
that this request never enters the IconServices daemon store, has no stable
validation token or store unit, and regenerates after SpringBoard restarts.

The only stock file-backed artwork found on that path is the numeral artwork
in SpringBoardHome's catalog:

```text
ClockIconNumbers1024
ClockIconNumbers60
ClockIconNumbers76
ClockIconNumbers83
```

with Arabic and Devanagari variants. The live hands are not loaded from that
catalog. `SBHClockApplicationIconImageView` implements
`makeHoursHandImageWithMetrics:imageAppearance:`,
`makeMinutesHandImageWithMetrics:imageAppearance:`, and
`makeSecondsHandImageWithMetrics:imageAppearance:`. Those methods construct
paths and render the hand images in the consumer process.

Therefore:

- replacing the app's `Assets.car` can theme only static/generic Clock
  consumers;
- replacing SpringBoardHome's catalog could at most provide a partial live
  face foothold; it cannot supply themed moving hands;
- replacing the `clock.base` IconServices record is not possible because no
  persistent record exists at that boundary.

### Calendar is entirely procedural at the live boundary

Calendar's writable app catalog also contains a static icon stack, including
`AppIcon/2.blackdots`, `AppIcon/3.reddot`, and `AppIcon/4.sash`. The
CalendarUIKit framework catalog contains UI colors but no corresponding live
icon image resources.

The live provider constructs a new date-specific `CUIKIcon` through
`SBCalendarIconImageProvider -preparedISIcon`. `CUIKDefaultIconGenerator`
then draws the background, day number, and date name with code, fonts, and
colors:

```text
iconImageWithDateComponents:...
  -> _drawBackgroundWithContext:
  -> _drawDayNumberWithContext:
  -> _drawDateNameWithContext:
```

`CUIKIcon -prepareImagesForImageDescriptors:` creates an `ISLayeredIcon` and
stores it in the `CUIKIcon` instance's own `internalIcons` dictionary. That
layered icon in turn uses a process-local `ISImageCache`. New provider
refreshes create new date-specific objects and results. There is no canonical
CalendarUIKit image asset or stable IconServices store entry that can be
replaced once and recovered by a fresh SpringBoard process.

The existing Calendar bridge works precisely because it changes the
process-owned provider's `preparedISIcon` source from the procedural
`CUIKIcon` to the ordinary, persistently themed
`ISBundleIdentifierIcon(com.apple.mobilecal)`. The themed source bytes persist;
the provider's choice to consume that source does not.

### File-system placement does not close the gap

The VM root volume is sealed and mounted read-only. The two framework catalogs
that participate in the live implementation reside under `/System`:

```text
/System/Library/PrivateFrameworks/SpringBoardHome.framework/Assets.car
/System/Library/PrivateFrameworks/CalendarUIKit.framework/Assets.car
```

Their captured SHA-256 values were:

| Catalog | SHA-256 |
| --- | --- |
| SpringBoardHome `Assets.car` | `a66fd57d78e9f1f7c021246449cc6cb2fdd189649da24cca362488aaf130b463` |
| CalendarUIKit `Assets.car` | `18a6c9423b8d2392cbdf30b94bc1751561fdc2e7eab645fb5d1863b98ef58384` |

The Clock and Calendar app bundles live under writable `/private/var` and
their captured catalogs had these hashes:

| Catalog | SHA-256 |
| --- | --- |
| MobileTimer `Assets.car` | `160dfafb59ea1a74dd3b4c4cf582ad78124a9b1a56d027041ff55541726829c7` |
| MobileCal `Assets.car` | `76a94e87b9bbe2d6a61c2621150288726d50d2801db49d51bfb78b8afa4044ab` |

Editing a writable app catalog can make stock regeneration of its ordinary
icon durable, subject to signature and cache handling, but does not change
SpringBoardHome's hard-coded special-class selection. Editing the system
framework catalog requires a custom system image, accepted seal, or boot-time
filesystem redirection. Even then it would not replace the procedural Clock
hands or Calendar generator.

## Candidate matrix

| Candidate | Clock live icon | Calendar live icon | New PID/reboot | Verdict |
| --- | --- | --- | --- | --- |
| Persistent ordinary IconServices records | Static Clock surfaces only | Static Calendar surfaces only | Bytes persist | Keep; necessary but insufficient |
| Replace app `Assets.car` | Special model bypasses it | Special model bypasses it | File may persist | Useful only for generic/static fallback |
| Replace SpringBoardHome `Assets.car` | Numeral artwork only | No | System volume is sealed | Partial, non-deployable on this profile |
| Publish `clock.base` / `CUIKIcon` record | No store boundary | No store boundary | No durable unit exists | Rejected by VM evidence |
| Edit `Info.plist` to force generic class | Hard-coded model selection remains | Hard-coded model selection remains | N/A | Rejected |
| Per-PID source/factory bridge | Full themed live behavior | Full themed provider output | Lost with target PID | Current full-fidelity route |
| Static proxy/Web Clip launcher | Static themed image | Static themed image | Can persist | Viable no-injection compromise |
| Patched SpringBoardHome/CalendarUIKit in a custom OS | Possible | Possible | Depends on boot chain | Outside Cyanide's current device model |

## Practical choices

### 1. Keep full live behavior

Retain the current narrow per-PID work:

- SpringBoard Clock: themed `clock.base` face plus the five themed hand/dot
  images;
- Spotlight Clock: force the generic static icon view before row creation;
- Clock and Calendar: retain the persistent ordinary descriptor matrices;
- Calendar: bridge each active provider's `preparedISIcon` to the persistent
  `com.apple.mobilecal` source.

This can be made operationally self-healing with lifecycle observation and
automatic repair, but that improves uptime rather than removing process
mutation. A fresh consumer still needs the bridge installed.

### 2. Remove process mutation completely

Use a generic launcher identity whose ordinary icon is backed by a themed app
catalog or persistent IconServices records, and have it open the stock app.
Calendar exposes the public `calshow` URL scheme; Clock declares private
`clock-worldclock`, `clock-alarm`, `clock-stopwatch`, and `clock-timer`
schemes on this build. The stock Clock/Calendar icons would need to be hidden
from the chosen Home layout.

This survives consumer replacement without touching SpringBoard or Spotlight,
but the costs are real:

- Clock hands do not move;
- Calendar does not change its day automatically unless a separate daily
  publisher updates the proxy icon;
- the launcher is a different bundle identity, so badges, quick actions,
  Spotlight identity, and some launch animations will not exactly match the
  stock application.

### 3. Treat system-image patching as a separate platform project

A custom VM/root filesystem could patch SpringBoardHome and CalendarUIKit
before either process launches. That would remove runtime injection in the
narrow sense, but it would require build-pinned binary patches, modified
system resources, and a boot chain willing to load them. It is materially more
fragile than the current signed-IMP/object-source bridges and is not a viable
upgrade path for Cyanide's present sealed-root target.

## Decision

For Cyanide's current target, there is no hidden persistent resource or
IconServices cache trick that preserves the native live Clock and Calendar
across fresh consumer processes. The engineering choice is binary:

1. keep the native live behavior and reinstall narrowly scoped source bridges
   per SpringBoard/Spotlight PID; or
2. use persistent static launcher icons and accept the loss of native dynamic
   behavior and exact application identity.

The persistent ordinary icon publication work remains valuable in either
case, but it cannot by itself control these two special generators.

## Related evidence

- [`vphone-ios26-clock-base-persistence-result.md`](vphone-ios26-clock-base-persistence-result.md)
- [`vphone-ios26-calendar-order-experiment.md`](vphone-ios26-calendar-order-experiment.md)
- [`vphone-ios26-iconservices-persistence-and-consumer-mappings.md`](vphone-ios26-iconservices-persistence-and-consumer-mappings.md)
- [`snowboard-remix-current-handoff.md`](snowboard-remix-current-handoff.md)
