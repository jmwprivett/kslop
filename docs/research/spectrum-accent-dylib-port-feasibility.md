# Spectrum/Accent dylib behavior and Cyanide port feasibility

Date: 2026-10-11

## Executive conclusion

An Accent- or Spectrum-style feature is feasible in bounded form, but the
original jailbreak tweaks and Cyanide operate at different lifecycle layers.

The original tweaks are injected as dynamic libraries into UIKit processes.
Their Objective-C replacements are present from process startup, remain
resident for the life of the process, and are injected again when an app is
relaunched. That is why a hook such as `+[UIColor systemBlueColor]` can affect
future calls throughout an app without the tweak managing each view.

Cyanide currently opens bounded RemoteCall sessions into already-running
processes. It can construct `UIColor` objects, call UIKit methods, change
existing window/view properties, and use the Objective-C runtime from inside
the target. It does not have a general, physically proved mechanism that
injects a custom executable hook payload into every iOS 26 system-app process
at launch. Physical production code in this tree deliberately prefers
data-only redirects to existing Apple-signed implementations where possible.

The recommended first version is therefore **Accent Now**, an explicitly
process-local feature:

1. resolve and identity-check a selected running app;
2. construct the chosen light/dark accent inside that process;
3. set the tint on every current scene window and use small, audited per-app
   adapters for explicit colors such as Notes' accent;
4. retain exact original values for Restore;
5. label the result as lasting only for that app PID.

This route can support an arbitrary color without executable payload
admission. A true Spectrum-style hook, automatic application to future app
PIDs, or both should remain later gates.

## Evidence labels

This note uses the following meanings:

- **Source-observed**: directly present in the upstream tweak source or the
  current Cyanide tree.
- **Existing pattern**: Cyanide already uses the technique for another bounded
  target, but it has not necessarily been proved against Notes or Clock.
- **Candidate**: technically plausible and worth a controlled experiment, but
  not yet device-proved.
- **Blocked**: depends on a capability that the current physical evidence does
  not establish.

No Spectrum/Accent implementation was added as part of this research note.

## How the injected jailbreak tweaks work

### Loader and process lifetime

Spectrum is a conventional Theos/Logos tweak. Its injection filter names the
`com.apple.UIKit` bundle, making processes that load UIKit eligible for the
tweak dylib. When the loader inserts the dylib, its constructor executes
inside the target process. The constructor reads the current bundle identity,
preferences, exclusions, and feature flags, then initializes the appropriate
Logos hook groups.

Logos `%hook` declarations compile to Objective-C runtime method replacement.
The replacement receives normal in-process Objective-C objects and `%orig`
dispatches to the saved original implementation. This has several important
properties:

- the replacement executes in the app's own address space;
- it sees future method calls, newly constructed views, and trait changes;
- process-local `UIColor` and UIKit objects are ordinary local pointers;
- the dylib remains loaded until the process exits;
- the jailbreak loader injects it again into replacement app processes.

The apparent persistence is therefore repeated launch-time injection, not a
durable edit to UIKit or to each application bundle.

Spectrum reloads preferences through a Darwin notification. Every injected
copy holds its own process-local settings and `UIColor` objects. It also uses
the process bundle identifier to exclude apps and special-case SpringBoard.
This is materially different from one controller process owning a color object
and trying to share that pointer with other processes; Objective-C object
pointers are not portable across address spaces.

Primary upstream references:

- [Spectrum injection filter](https://raw.githubusercontent.com/Skittyblock/Spectrum/master/Spectrum.plist)
- [Spectrum implementation](https://github.com/Skittyblock/Spectrum/blob/master/Tweak.x)
- [Accent implementation](https://github.com/ivancristina/accent/blob/master/Tweak.x)

### What Accent replaces

Accent takes the broad semantic-color approach. Its source loads a selected
preset or picked RGB value, keeps an application exclusion list, and replaces
many `UIColor` class methods. The observed selectors include:

- `systemBlueColor`, `_systemBlueColor2`, and interaction/selection colors;
- system green, orange, yellow, teal, pink, and several dark/external variants;
- `linkColor` and `tableCellBlueTextColor`;
- `systemRedColor` specifically for Calendar and Clock;
- `systemOrangeColor` with a Mail exception.

It also sets the key window's tint, forces `UISwitch.onTintColor`, and contains
private-framework adapters for Game Center, the old Store UI, Messages bubble
gradients, and Notes. The Notes-specific implementation replaces
`+[UIColor ICTintColor]` and `+[UIColor ICTintedSelectionColor]`, with the
selection color derived from the chosen accent at reduced alpha. The separate
experimental note shows that blanket `UIImageView` tint interception themed
the keyboard too, documenting the collateral effect of overly broad hooks.

Relevant upstream references:

- [Accent color and app-specific hooks](https://raw.githubusercontent.com/ivancristina/accent/master/Tweak.x)
- [Accent's experimental Notes approaches](https://raw.githubusercontent.com/ivancristina/accent/master/Experimental%20Approaches.md)

This explains why Notes and Clock are not covered reliably by changing only
`systemBlueColor`: Notes used private NotesUI color accessors, while Clock and
Calendar caused Accent to special-case the red semantic color.

### What Spectrum replaces

Spectrum separates a general tint from a larger light/dark color profile.
Its source-observed behavior includes:

- intercepting `-[UIDynamicSystemColor initWithName:colorsByThemeKey:]` and
  replacing selected light/dark theme entries while an object is constructed;
- replacing `systemBlueColor`, `_systemBlueColor2`, link color, insertion-point
  color, selection highlight, and selection grabber color;
- recognizing the literal stock blue RGB constructor as a fallback for apps
  that construct `#007aff` directly;
- updating navigation bars, toolbars, and tab bars when they move into a
  hierarchy or when the trait collection changes;
- replacing `UIView.tintColor` only when the view's normal inherited tint
  matches its window tint, which attempts to preserve explicit per-view colors;
- optionally templating SpringBoard badge artwork and tinting the badge and
  badge text separately;
- loading named profiles plus distinct light and dark values for backgrounds,
  labels, separators, selection, bars, and badges.

Spectrum's inherited-tint test is the safer conceptual base for Cyanide. The
broad Accent method list is useful as an app-compatibility inventory, but
blindly mapping every semantic color to one accent would also recolor delete,
warning, success, status, tag, and category meanings.

## The Cyanide boundary

### Capabilities already in the tree

`RemoteCallSession` accepts a process name and establishes a bounded call
context in the target. The RemoteCall helpers can invoke Objective-C messages
on the main thread, invoke exported C functions, allocate target memory, and
read/write target state. This is enough for a one-shot window/view mutation
once the correct PID and process identity have been established.

The IconServices consumer work also contains method-install machinery with
arm64e pointer-authentication handling. The copied payload's installer signs a
replacement before calling `method_setImplementation`. Separately, the current
physical presentation route demonstrates the safer production pattern:
redirect a method only to an ABI-identical, existing Apple-signed
implementation, verify the replacement in the target, and introduce no new
executable bytes.

Local references:

- `Cyanide/TaskRop/RemoteCall.{h,m}`
- `Cyanide/installer/CNDIconServicesConsumerPayload.c`
- `Cyanide/installer/CNDIconServicesConsumerHook.m`
- `Cyanide/installer/CNDIconServicesConsumerKernelInstaller.m`

These are reusable mechanisms and patterns, not proof that arbitrary system
apps can already accept an Accent payload.

### Capabilities not currently proved

The existing resident-supervisor research records two relevant gaps:

1. a custom executable page is VM-proved but not physical-proved in the
   hardened iOS 26 SpringBoard environment;
2. observing replacement app PIDs and initiating serialized RemoteCall work
   from a SpringBoard-resident owner still requires physical KRW handoff and
   cross-process ownership work.

See
[`springboard-resident-repair-supervisor-feasibility.md`](springboard-resident-repair-supervisor-feasibility.md).

The same executable-admission question must be answered independently for
each target policy class. A successful payload in a lab VM, Cyanide itself, or
one daemon is not proof that Notes or Clock will accept and execute a
Cyanide-backed RX mapping on a physical device.

Attaching after launch also differs from injected startup behavior:

- system colors or named colors may already be cached;
- existing views may already hold explicit tint objects;
- a constructor hook cannot retroactively alter objects created before it was
  installed;
- SwiftUI may have captured values into environment or rendering state;
- app UI may live partly in extension or service processes;
- new scenes and new app PIDs will not be covered without an observer.

The in-app porting guide already states the core translation problem directly:
`%hook UIView` is not portable as a hook; an explicit RemoteCall message to a
known view is portable. See `Cyanide/DocsViewController.m`.

## Candidate implementation routes

| Route | Arbitrary RGB | Affects future calls/views | Survives app relaunch | Current status |
| --- | ---: | --- | ---: | --- |
| Set tint on current scene windows | Yes | New descendants that inherit those windows; not explicit app colors or future windows | No | Best first route; target-app device proof required |
| Audited per-app property adapters | Yes | Only objects reached by the adapter; inherited descendants may follow | No | Candidate for Notes and Clock |
| Redirect selectors to existing Apple color IMPs | Usually preset colors only | Future calls to redirected selectors; cached objects remain | No | Existing Cyanide pattern, but each selector/IMP pair needs ABI and result proof |
| Mutate process-local dynamic-color objects | Potentially | Depends on singleton/cache ownership | No | Research candidate; UIKit layout and aliasing unknown |
| Install a custom executable hook payload | Yes | Yes, within that PID after installation | No | Blocked on physical executable admission for the target policy class |
| SpringBoard launch observer plus reapply | Yes, using one of the routes above | Reapplies to new selected PIDs | Until SpringBoard exits | Blocked on resident-supervisor physical gates |
| Persistent app/system asset edits | Asset-dependent | On every load of the modified resource | Potentially | Poor general solution; build-specific and not equivalent to semantic tint |

### Route A: Accent Now

This is the recommended first implementation.

For every selected, already-running application:

1. resolve the application by bundle identifier, then bind the operation to
   the exact PID, executable path, kernel proc/task identity, and process-start
   generation;
2. obtain a bounded assertion or otherwise prove the target is runnable before
   attempting the RemoteCall bootstrap;
3. create light and dark `UIColor` values inside the target process;
4. enumerate `UIApplication.connectedScenes`, accept only window scenes, and
   enumerate every current window rather than relying on deprecated
   `keyWindow` behavior;
5. save each original explicit window tint, including an explicit sentinel for
   `nil`, using an associated object keyed by a stable registered selector;
6. set the chosen tint on each window on the target main thread;
7. run only build- and app-specific adapters that have exact class/selector or
   view-identity gates;
8. verify readback and record a PID-bound transient state marker.

Window tint naturally covers controls which inherit tint from that window,
including many controls created later in the same hierarchy. It does not
replace hard-coded or named app colors. This route is therefore honest as a
useful accent layer, not a complete Spectrum clone.

Restore should enumerate the same live windows, recover the associated
original or `nil` sentinel, restore it, clear the association, restore all
adapter-owned properties, and verify the result. If the exact process identity
no longer exists, its process-local mutation is already gone and the stale
marker can be cleared without touching the replacement PID.

### Route B: app-specific profiles

Profiles should be small allowlists, not arbitrary recursive recoloring.
Initial research targets should be:

| App | Bundle | What to inventory first |
| --- | --- | --- |
| Notes | `com.apple.mobilenotes` | Current replacement for historical `ICTintColor`/`ICTintedSelectionColor`; sidebar selection, toolbar controls, editor selection, attachment browser |
| Clock | `com.apple.mobiletimer` | Tab/toolbar accent sources, timer/stopwatch controls, alarms, destructive controls, any SwiftUI named-color path |

Each adapter must distinguish decorative accent from semantics. Alarm enabled
state, destructive delete actions, validation errors, warnings, and unrelated
calendar/category colors should remain stock unless the user explicitly opts
into a documented full-spectrum mode.

Adapters may set properties on exact live objects, update a target-owned
singleton, or redirect an exact selector after its contract is proved. Every
property changed must have a reversible original-value record. A view-tree
walk that simply replaces every yellow, orange, red, or green object is not an
acceptable production route.

### Route C: data-only method redirection

For a built-in palette, one candidate is to redirect an accent-producing
method to an existing Apple-signed color-producing implementation with the
same Objective-C ABI. This follows the current production consumer pattern and
does not introduce executable bytes.

It is not automatically safe. Before committing a redirect, a probe must
establish:

- both methods exist on the expected owning class/metaclass;
- their type encodings match exactly;
- the replacement code tolerates receiving the destination selector in
  `_cmd` and the destination receiver class;
- a direct before/after call resolves to the intended RGBA values in light and
  dark traits;
- the replacement does not share or corrupt unrelated cached state;
- the exact original IMP is retained and can be restored;
- method and IMP readback still match immediately before Restore.

The `_cmd` condition matters because a nominal `systemRedColor`
implementation may derive its result from the selector it receives. Installing
that IMP under `systemBlueColor` does not prove it will return red. Only target
readback and resolved-color verification can answer that.

This route may cover future calls within the current PID, but it will not
retroactively change colors already cached by the app. It is best treated as a
preset-color experiment after Route A works.

### Route D: full Spectrum payload

A faithful Spectrum port requires target-resident code. A minimal payload
would need:

- a versioned context containing light/dark components, original IMPs, method
  identities, install state, and recursion guards;
- BTI-compatible entry points and arm64e-correct IMP signing;
- an inherited-tint implementation that calls the original `UIView.tintColor`
  and preserves explicit colors;
- optional color-selector replacements and an audited dynamic-color path;
- main-thread refresh logic for objects that predate installation;
- atomic install with exact type-encoding and owner checks;
- Restore which reinstalls every original IMP before unmapping any payload
  page;
- failure cleanup which never unmaps code while an installed method can still
  reach it.

The payload cannot be called production-ready until physical Notes and Clock
each prove executable mapping, execution, PAC/BTI behavior, repeated
install/restore, and process exit without a crash. The current VM payload
machinery is useful engineering material, not that proof.

## State and lifetime contract

The UI should describe state by process lifetime:

- **Applied to PID**: the exact app incarnation is themed.
- **Not running**: no mutation is present; there is nothing to patch yet.
- **Relaunched**: stock unless a later launch observer reapplies the profile.
- **Force-quit/reboot**: stock for that process-local feature.
- **Cyanide terminated while target lives**: the target mutation can remain;
  a durable PID/generation marker permits a later Cyanide launch to Restore.

A proposed journal record should include:

- schema and implementation version;
- boot epoch;
- bundle identifier, executable path, PID, and process-start identity;
- selected profile and resolved light/dark RGBA values;
- which windows/adapters/methods were changed;
- original and installed IMPs for any method redirect;
- target-owned association-key identity;
- payload mapping address/length only when a payload route is eventually used;
- verification and restore status.

Never apply a journal from one PID generation to another. A replacement PID
must be treated as a fresh target. Never restore an IMP if its current value is
neither the recorded original nor Cyanide's recorded installed value; that is
unknown drift and must fail closed.

The existing `CNDTransientAppliedState` schema is SpringBoard/Spotlight-centric
and has a fixed key set. Accent should receive a separate per-application
state model rather than stretching that schema into a dictionary of arbitrary
app PIDs.

## Why a global shared-cache patch is not the first route

A single system-wide patch is attractive but mismatched to arbitrary accent
colors:

- an arbitrary `UIColor` object is process-local;
- a pointer created in Cyanide is invalid in Notes or Clock;
- global semantic-color behavior also reaches authentication views, system UI
  services, warnings, and accessibility surfaces;
- shared cache/data-page sharing must be proved for every target, not inferred
  from SpringBoard and Spotlight;
- a build-specific global mutation has a much larger rollback and regression
  surface than a PID-bound app operation.

The Hail Mary data-page work is evidence that a narrow, identical-bytes,
Apple-signed redirect can sometimes be made reversible. It is not evidence
that a universal UIKit accent object can be installed safely across processes.

## Suggested development gates

### Gate 0: read-only inventory

- Resolve Notes and Clock by bundle identity and exact PID.
- Inventory current scenes/windows and their explicit/inherited tint.
- Resolve candidate private selectors and type encodings.
- Record resolved light/dark RGBA values returned by candidate semantic colors.
- Determine which visible surfaces live in helper processes.
- Make no mutation.

### Gate 1: one-shot window tint canary

- Apply one arbitrary color to one foreground test app PID.
- Verify controls that inherit tint and document controls that do not.
- Exercise navigation, modal presentation, background/resume, light/dark
  changes, text selection, and creation of a new screen.
- Restore the exact original tint without killing the app.
- Repeat Apply/Restore at least ten times and verify no leaked active state.

### Gate 2: Notes and Clock profiles

- Add one exact adapter at a time.
- Prove the adapter changes only the intended accent surface.
- Capture before/apply/restore screenshots and resolved-color readback.
- Verify delete, warning, alarm state, category/tag, and accessibility colors
  remain semantically correct.
- Fail closed on missing classes, selectors, or unexpected type encodings.

### Gate 3: data-only preset redirect

- Try one ABI-identical method pair in the VM.
- Verify `_cmd` behavior and actual returned colors.
- Repeat on the physical target with an exact-build gate.
- Restore the original IMP and verify new and previously cached colors
  separately.

### Gate 4: custom payload

- Proceed only after a target-local physical RX execution canary passes.
- Install one no-op or probe method first.
- Prove teardown before adding tint logic.
- Keep Notes and Clock separate until each policy and framework path is proved.

### Gate 5: launch supervision

- Reuse the resident-supervisor gates only after physical executable admission,
  KRW ownership, and event serialization are complete.
- Observe launches first without mutation.
- Reapply only after two stable identity samples and `finishedLaunching`.
- Use one bounded RemoteCall per new PID; retain no open session between events.
- Stop at SpringBoard restart, userspace reboot, or full reboot unless a
  separately proved persistence mechanism exists.

## Acceptance checklist

- Notes and Clock can each be enabled or excluded independently.
- Apply is bound to an exact bundle/PID/executable identity.
- A custom color visibly reaches ordinary inherited-tint controls.
- Light and dark appearance resolve to the configured values.
- Notes' app-specific accent and selection path are either themed or clearly
  listed as unsupported; no false success is reported.
- Clock's ordinary accent changes without recoloring destructive or alarm-state
  semantics unintentionally.
- New views, new windows, and cached colors are tested and limitations are
  reported.
- App suspension/resume does not corrupt UI state.
- Force-quit returns to stock in the replacement PID unless launch supervision
  is explicitly active.
- Manual Restore returns exact original values in the same PID.
- Unknown method/property drift fails closed.
- No method still targets a payload before that payload is unmapped.
- Repeated Apply/Restore produces no crash, stuck assertion, leaked mapping, or
  stale ACTIVE state.
- SpringBoard and unrelated UIKit services remain unchanged by default.

## Licensing and attribution

Spectrum declares GPL-3.0 in its repository. Accent's repository exposed the
source during this review but did not visibly include a license file in its
top-level listing. Before copying implementation code, confirm license
compatibility and permission. The safer engineering route is a clean
reimplementation of the observed behavior using Cyanide's existing RemoteCall
and recovery patterns, with explicit credit to the original developers.

## Final recommendation

Build the feature in this order:

1. **Accent Now**: arbitrary per-app light/dark window tint, exact restore,
   process-lifetime labeling.
2. **Notes and Clock profiles**: small, reversible, build-gated adapters.
3. **Preset redirects**: only where existing Apple IMPs pass ABI, `_cmd`, color,
   cache, and restore verification.
4. **Full Spectrum hooks**: only after physical executable-payload admission is
   proved for the target app class.
5. **Automatic reapply**: only after the resident launch supervisor is itself
   physically proved.

This sequence produces a useful tweak early without disguising a late,
one-shot RemoteCall mutation as jailbreak-style launch-time dylib injection.
