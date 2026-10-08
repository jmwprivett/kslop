# Pulsar artwork assets

The checked-in `Cyanide/PulsarControlCenter.bundle` contains PNG artwork and
stateful CAML packages. `Cyanide/tweaks/CNDPulsarControlCenterArtwork.inc` embeds
the static images and their source metadata for the Foundation artwork API.
These outputs can be built from a clean checkout without regenerating them.

The original Pulsar v2 package is pinned to the `dobabaophuc1706/misakarepo`
source commit `bd13799`. Supplemental originals and their hashes are under
`assets/pulsar-controlcenter-supplemental`. The extractor and generator retain
the original author and source identities in their manifests.

## Regeneration

Regeneration requires macOS command-line tools and local upstream inputs that
are excluded from Git:

- The extracted original package under
  `build/pulsar-controlcenter-v2-source/extracted-original/com.dobabaophuc.pulsarcc2.0`.
- Its inventory at `build/pulsar-controlcenter-v2-assets/manifest.json`, produced
  by `scripts/extract_pulsar_controlcenter_assets.py` (see `--help` for input and
  output options).
- Rendered catalog PNGs under `build/pulsar-catalog-rendered-png`.

Supply these inputs before running:

```sh
python3 scripts/generate_pulsar_controlcenter_artwork.py
```

An optional supplemental ZIP can first be imported with
`scripts/import_pulsar_supplemental_artwork.py`. Reimport preserves manifest
records for separately supplied images that are still present.

`scripts/export_stock_controlcenter_references.py` separately renders design
references from locally extracted iOS 26 build 23A341 resources. Its required
input paths are defined in the script; its output stays under `build/`.

## Host checks

These checks use synthetic inputs or checked-in artwork; normalization runs in
temporary directories:

```sh
python3 scripts/tests/test_extract_pulsar_controlcenter_assets.py
python3 scripts/tests/test_pulsar_timer_artwork.py
python3 scripts/tests/test_pulsar_supplemental_artwork.py
python3 scripts/tests/test_cc_theming_delivery.py
```

Generated native catalogs and their file-backing manifests form a separate
local research artifact set. They are not required by the checked-in artwork
API or its tests. In particular, the large stock-derived CoreGlyphs catalog
is not part of this artwork commit.
