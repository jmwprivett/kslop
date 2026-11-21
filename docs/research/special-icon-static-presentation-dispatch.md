# Clock/Calendar static presentation through shared-cache dispatch

## Result

The exact `23A341` / `iPhone17,2` cache contains direct shared-cache
presentation redirects for Clock and Calendar. The one-entry Clock route and
the three-entry Calendar route have both produced the intended appearance in
current-boot operator testing. These redirects act on existing archived
special icon objects. They do not require canonical-object removal/reinsertion,
Home visibility, Spotlight/SpringBoard injection, or `RemoteCall` by design.

The derivation itself is offline and performs no device write. Runtime
dispatch reports and operator-observed appearance remain separate evidence:
the appearance result was reported interactively and no screenshot or exported
appearance artifact is retained in this repository.

Reviewed machine-readable evidence:

- `docs/research/special-icon-presentation-dispatch-23A341-iphone17,2.json`
- `scripts/derive_special_icon_presentation_dispatch_redirect.py`

## Derived entries

| Surface | Existing special method | Ordinary replacement | Entry | 16 KiB frame | Static status |
| --- | --- | --- | --- | --- | --- |
| Clock | `SBHClockApplicationIcon iconImageViewClassForLocation:` | `SBIcon iconImageViewClassForLocation:` | `0x1ffc00120` | `0x1ffc00000` | Operator-observed success |
| Calendar bundle source | `SBHCalendarApplicationIcon applicationBundleIdentifierForImage` | `SBLeafIcon applicationBundleIdentifierForImage` | `0x1ffc18618` | `0x1ffc18000` | Operator-observed as three-entry transaction |
| Calendar image | `SBHCalendarApplicationIcon makeIconImageWithInfo:...` | `SBLeafIcon makeIconImageWithInfo:...` | `0x1ffc18590` | `0x1ffc18000` | Operator-observed as three-entry transaction |
| Calendar layer | `SBHCalendarApplicationIcon makeIconLayerWithInfo:...` | `SBLeafIcon makeIconLayerWithInfo:...` | `0x1ffc18658` | `0x1ffc18000` | Operator-observed as three-entry transaction |

All four targets are packed preoptimized Objective-C cache entries in the
pinned `.34.dyldreadonly` UUID
`CEEB0D68-9BA9-3CC8-AEB1-8F23BAC92B58`. Each derived change preserves the
entry's upper 32 bits and changes only its low word. The replacements have
exactly matching Objective-C type encodings and reside in the pinned Apple
shared-cache RX subcache UUID `E5139123-79ED-3CC2-8E2F-40C980D82033`.

Clock's replacement is the same ordinary view-class factory already observed
to give a persistent `com.apple.mobiletimer` static presentation in the old
process-local route. The new shared-cache route has now also been observed to
produce the desired Clock appearance after consumer replacement on the current
physical boot; that user-observed result is not generalized to another build
or boot.

## Calendar result and retained rejected routes

`SBHApplicationIcon` does not directly override the image or layer factories;
it inherits both from `SBLeafIcon`. The first physical trial of that exact
two-factory route produced a grey plate. Disassembly localizes why: Calendar
overrides `applicationBundleIdentifierForImage` with a two-instruction method
that returns `nil`, while `SBLeafIcon prepareImageLoadContext:` only installs
the application-icon source when that selector returns a bundle identifier.
The inherited static factories consequently had no stock Calendar source.

The prior failed class-wide experiment was not this exact pair. It redirected
the image factory to `SBLeafIcon`, but redirected the layer factory to
`SBIcon makeIconLayerFromImageWithInfo:...`. That mixed route bypassed the
provider and rendered a grey generic plate. The derivation retains its exact
replacement IMP and packed word as rejected runtime evidence.

The new candidate keeps the two `SBLeafIcon` factories but first redirects the
nil-returning Calendar selector to `SBLeafIcon`'s ABI-identical implementation.
That implementation asks the existing active data source for
`applicationBundleIdentifierForImageForIcon:`. Static analysis cannot prove
that the data source returns `com.apple.mobilecal` or that IconServices then
returns the themed stock asset. The subsequent physical appearance test
supplied that missing runtime observation for this exact product/build and
boot.

Current-boot user observation established that the Clock redirect renders the
desired static appearance and that the old exact two-`SBLeafIcon` Calendar
pair renders grey. The later three-entry Calendar transaction rendered the
intended Calendar artwork after normal consumer replacement. This is a narrow
operator-observed result, not a portable claim and not a repository-retained
appearance artifact.

## Runtime validation sequence used

The four entries occupy two read-only frames that were not the pages used by
the earlier `.34` class-selection test. Success elsewhere in the same mapping
does not prove either exact page. Before any semantic redirect, each frame
needs its own same-boot identical-bytes aperture ticket:

1. Validate the exact build, product, main-cache UUID, `.34` UUID, original
   32-byte guard, and current low word.
2. Perform an identical low-word write/readback/restore on `0x1ffc00000`.
3. Perform a separate identical low-word write/readback/restore on
   `0x1ffc18000`.
4. Test the one-entry Clock redirect alone, restart the consumers by killing
   their processes, and verify Home/App Library and a newly materialized
   Spotlight result. Do not inject either process and do not remove/re-add the
   icon object.
5. Restore Clock before testing the three Calendar entries as one guarded,
   reversible transaction. Restart the consumers and judge actual pixels, not
   only dispatch readback.

This sequence distinguishes shared-page write capability, dispatch survival,
and appearance semantics. A successful guard readback by itself is not an
appearance result.

## Implemented and exercised physical probes

The probe implementation exists in
`Cyanide/probes/CNDSpecialIconPresentationDispatchProbe.{h,m}`. Source and
host tests remain **Implemented** evidence. The exact permission, Clock, and
Calendar operations were also exercised on the target device; appearance
success is recorded here only as the operator's current-boot observation.

The permission action runs the existing read-only Hail Mary proof in
SpringBoard-only mode. It then physically reads the live main-cache header,
requires UUID `DC5F2F67-1FC8-3905-873B-35D17D1A44E8`, and validates the exact
23A341 subcache table shape (offset `0x41818`, 77 entries). Entry 33 must name
`.34.dyldreadonly`, carry UUID
`CEEB0D68-9BA9-3CC8-AEB1-8F23BAC92B58`, and point at cache VM offset
`0x78354000`; the mapped subcache header at that offset must independently
repeat the same UUID. Every physical read requires a stable repeated
SpringBoard translation. Only after that live identity proof does the action
exercise all four exact entry addresses with the primitive's checked 32-byte
transfer. Each permission transfer writes the already-present 32-byte guard
unchanged, verifies exact readback, and repeats the SpringBoard translation.
Spotlight does not need to exist and is never opened or contacted.

The first installed permission attempt exposed an implementation refusal, not
an aperture result: the consumer required the legacy Hail Mary field
`runtimeCacheUUIDVerified == true`, while that observation-only producer
deliberately initializes the field to false and never promotes it. Therefore
that version could not reach an entry read or write even after a successful
physical proof. The corrected probe replaces the impossible precondition with
the independent live header and subcache-membership proof above. That corrected
path subsequently reached the device operations described above.

Clock and Calendar have independent apply, restore, verify-redirected, and
verify-original operations. Clock changes one packed entry. Calendar changes
its bundle-source, image, and layer entries as one bounded transaction. The
retained old grey-pair state is accepted as an exact recovery input. Before
each transaction, every per-target before-state guard is captured and durably
journaled. If any write, progress journal, readback, final translation, or
final confirmation fails, every attempted entry is written back to that exact
captured guard and restoration is read back. A cleanup failure remains a
failed verdict.

The retained code still implements these diagnostic rows, but the Settings
**Probes** section now intentionally exposes only Discord Apply/Restore. The
Clock/Calendar controls remain available to launch automation and source-level
recovery work:

1. **Probe Static Presentation Entries**
2. **Apply Static Clock Presentation**
3. **Restore Live Clock Presentation**
4. **Verify Static Clock Presentation**
5. **Verify Original Clock Presentation**
6. **Apply Static Calendar Presentation**
7. **Restore Live Calendar Presentation**
8. **Verify Static Calendar Presentation**
9. **Verify Original Calendar Presentation**

The launch-argument equivalents are:

```text
--special-icon-presentation-probe
--special-icon-clock-presentation-apply
--special-icon-clock-presentation-restore
--special-icon-clock-presentation-verify-redirected
--special-icon-clock-presentation-verify-original
--special-icon-calendar-presentation-apply
--special-icon-calendar-presentation-restore
--special-icon-calendar-presentation-verify-redirected
--special-icon-calendar-presentation-verify-original
```

Apply and Restore stop after exact guard and translation verification. They do
not kill or restart a process themselves. Consumer restart remains an explicit
outside action: kill/restart SpringBoard and Spotlight normally, without
injecting either process or rebuilding/removing the Clock or Calendar object.
The retained JSON reports distinguish exact dispatch-state proof from
appearance. The final Calendar pixels were judged successful by the operator;
the JSON dispatch reports do not themselves prove that appearance.

## Persistence semantics

Runtime testing on the named boot confirmed that replacement consumers consult
the redirected shared dispatch state. A reboot is still expected, but was not
separately observed here, to restore the stock cache. A process restart after
apply is required to avoid any already-populated process-local Objective-C
method cache. This observation is scoped to `23A341` / `iPhone17,2`.

## SnowBoard integration

The SnowBoard **Icon Fixes** toggle makes base Apply run, in order, the Hail
Mary transparency redirect, Clock redirect, and Calendar transaction on the
queue worker after persistent IconServices publication succeeds. The queue
owns the shared KRW lifecycle; the probe implementations do not acquire it.
Successful earlier components remain active if a later component fails. No
coordinator-level rollback is attempted. **Restore All Icons** is the blanket
reverse path and restores Calendar, Clock, then transparency; the retained
individual restore operations remain the traditional recovery path.
