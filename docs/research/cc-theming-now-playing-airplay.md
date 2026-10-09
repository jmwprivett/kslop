# Now Playing AirPlay output glyph on iOS 26

The base and expanded Now Playing controls use the system symbol
`airplay.audio`. This is independent of the Screen Mirroring module's
`Mirroring.ca` packages and the transport buttons' `PlayPauseStop.ca` and
`ForwardBackward.ca` packages.

## Captured identity

The saved VM ownership captures
`build/CCLifecycleOwnerVM-20261005-01/compact-625-complete.json` and
`media-complete-before.json` both contain this named route:

```text
MediaControlsModuleSessionView.nowPlayingView
  -> MediaControlsModuleNowPlayingView.upperRouteButton / lowerRouteButton
     -> MediaControlsModuleRouteButton
        .viewModel.some.symbol = "airplay.audio"
        .imageView -> UIImageView
```

Both route-button slots and their image-view slots were verified against typed
Swift reflection. Four captured button instances have the same machine symbol
identity. Their addresses and offsets are evidence only; production does not
retain them or resolve this view hierarchy.

## Existing artwork and production route

The original Pulsar archive contains `AirPlayControlAudioLight.ca/main.caml`
and `AirPlayControlAudioDark.ca/main.caml`. Their content is identical, SHA-256
`25f3acba533310abb168ab10396a8fee5cbadf05dfbe742480d151a92db551a8`, and
includes Pulsar's existing star/comet vector artwork. Additional user artwork
is not needed for this symbol.

Those legacy package filenames are not used for these captured Swift buttons.
The catalog generator renders the complete original drawing in a padded host
canvas, crops its actual alpha footprint, and stores `MediaAirPlay.png` in the
app's Pulsar bundle. It records the source and output digests in the priority
catalog manifest. The catalog is a host research candidate: adding a symbol to
CoreGlyphsPriority does not establish coverage of the base-CoreGlyphs provider
used by normal system-image requests. Production now leaves this catalog
pending rather than claiming AirPlay was delivered. The in-process delivery
adapter can substitute the exact `airplay.audio` provider identity when its
owning process has installed it; local tests do not prove physical installation.

All existing priority masks now use their exact pixel-edge contours rather
than overlapping rectangle strips. The downsample resolution and alpha
threshold are unchanged; shared internal edges and collinear points are the
only geometry removed. Pixel-union tests cover every existing Pulsar mask,
holes, threshold boundaries, and diagonal contacts. This lets AirPlay's three
symbol-size groups fit without dropping any previously implemented variant.

The generated priority catalog is 297,288 bytes, padded to the native 309,384
bytes. All 600 requested size/weight lookups pass: 15 themed symbol identities,
four CoreUI glyph-size values, and ten weights. Flashlight retains its existing
captured Medium-only contract. Connectivity and Display payload bytes are
unchanged by the AirPlay addition.

These lookup checks use the host CoreUI 975 renderer. The target native
catalogs use CoreUI 970; device consumption has not been verified. Other
output-device symbols selected after connecting headphones/speakers are not
inferred from this capture. Physical provider installation, appearance, and
redraw/reconstruction persistence remain separate verification steps.
