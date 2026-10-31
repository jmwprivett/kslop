# SnowBoard Remix

SnowBoard Remix imports SnowBoard/IconBundles theme artwork and publishes
persistent IconServices records for compatible applications. It uses structured
`IFImage` data and the exact observed descriptor profile, with one pinned
`iconservicesagent` session during a transaction.

Transparent theme artwork is aspect-fitted onto a transparent square canvas.
Alpha is retained through resizing and size-constrained encoding. Opaque input
is not treated as removable-background artwork.

Apply records original stock UUIDs, store hashes, validation tokens, and
LaunchServices source identities before replacing records. Restore verifies
and republishes stock state. An app update or reinstall can change its source
identity; **Update Repair** rebases the journal and repairs newly installed or
updated apps. The manual button remains available, while **Automatic Repair**
keeps Cyanide alive, coalesces install and LaunchServices notifications, and
runs the same journal-aware operation after a settle window. It also performs
a low-frequency integrity audit and keeps the per-boot Transparency Fix
confirmed when SnowBoard is active. Automatic work reuses validated KRW; a
background notification never starts a fresh exploit acquisition. Its silent
audio and audit timer run only while the Automatic Repair preference is on,
SnowBoard's applied-state marker is active, and recovery data remains. Enabling
the preference before Apply keeps them stopped. A successfully finalized queued
Apply starts that lifetime; Restore stops it, and preference changes reconcile
immediately. Automatic passes and queued Apply/Restore share one atomic mutation
gate: automatic work defers when occupied, while queue workers wait off the main
thread for an in-flight pass. The gate covers only the SnowBoard mutation, not
unrelated queued actions.

Update Repair audits every unchanged journal against the live persistent
index, store unit, and saved themed/stock hashes. Records that IconServices
conclusively deleted or rebuilt to their byte-exact saved stock state are
republished; intact descriptors are retained and unknown drift is not
overwritten automatically.

Normal Apply targets the full matched catalog; the four-app limit is an
opt-in debug control. Persistent publication success is independent of the
advisory batch index and optional presentation cleanup, so those failures do
not request a redundant republish. Recovery state uses one atomic base journal
plus a bounded append-only checkpoint stream. Each record contains at most two
variant updates, allowing a publication result and the next descriptor's
dispatch marker to share one durable write. Readers require a contiguous,
versioned stream and replay it over the base; a missing, malformed, mismatched,
or oversized current-stream record marks every variant recovery-required.
Successful transaction boundaries compact once into a new base, rotate the
stream identity, and discard the old records. This reduces normal Apply and
Restore journal serialization from quadratic to linear in descriptor count
without removing the durable pre-dispatch boundary.

The live repair scan stays in the already-pinned IconServices batch and does
not add a second catalog/session pass. Its transport-level matrix retains one
app-scoped bundle object, canonical icon/cache, and current LaunchServices
source identity while reading that app's descriptors; cache responses, index
UUID/token pairs, and store units remain independently audited per descriptor.
The retained app context is released when the matrix switches apps or the
batch closes. Repair republishes only affected descriptor records, reuses the
structured-payload cache instead of rerendering, and keeps the other journal
entries in place. Normal Apply does not run the live scan, so its
unchanged-journal fast path remains cheap.

Restore reuses each exact `persistent-stock-verified` descriptor checkpoint
and removes a fully clean recovery journal before opening another publisher
batch. It does not remote-call SpringBoard after persistent recovery. The
queued respring naturally discards the process-local transparency and
Clock/Calendar fixes.

Recovery records live in Application Support under
`SnowBoardRemix/Transactions`. Keep this data while a theme is active. The core
profile includes 64-point Spotlight Apps-list results for every app; the
20-point SnippetUI badge is Safari-specific. Existing 10-record journals gain
the missing 64-point record without republishing their other records.
SpringBoard cache invalidation is temporarily disabled, so some materialized
surfaces may continue to show old pixels until they refresh. See
[research status](research/README.md) for measured coverage and remaining
physical validation.
