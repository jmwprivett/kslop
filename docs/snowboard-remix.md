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
identity; **Update Repair** manually rebases the journal and repairs newly
installed or updated apps. Unknown drift is not overwritten automatically.

Recovery records live in Application Support under
`SnowBoardRemix/Transactions`. Keep this data while a theme is active. The core
profile includes 64-point Spotlight Apps-list results for every app; the
20-point SnippetUI badge is Safari-specific. Existing 10-record journals gain
the missing 64-point record without republishing their other records.
SpringBoard cache invalidation is temporarily disabled, so some materialized
surfaces may continue to show old pixels until they refresh. See
[research status](research/README.md) for measured coverage and remaining
physical validation.
