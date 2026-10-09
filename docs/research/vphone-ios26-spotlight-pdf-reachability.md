# Spotlight CoreUI PDF reachability canary

This VM-only experiment answers one narrow question: can a persistent
IconServices structured icon record make a fresh Spotlight process materialize
and render a CoreUI PDF rendition? It does not contain malformed PDF data,
JBIG2 data, or an exploit payload.

The publisher creates a valid one-page red/green PDF with the metadata subject
`CND_SPOTLIGHT_PDF_CANARY_V1`. During structured-icon serialization it replaces
the otherwise benign SVG rendition with a CoreUI raw rendition whose pixel
format is `PDF `. Publication is rejected unless the serialized BOM archive
still contains both the PDF header and the metadata marker.

The Spotlight tracer wraps only these existing CoreUI methods and invokes their
original implementations:

- `-[_CUIThemePDFRendition _initWithCSIHeader:version:]`
- `-[_CUIThemePDFRendition createImageFromPDFRenditionWithScale:]`
- `-[CUINamedVectorPDFImage rasterizeImageUsingScaleFactor:forTargetSize:]`

It identifies the canary through `CGPDFDocumentGetInfo`, not merely by seeing
some unrelated PDF in Spotlight.

## Build offline

```sh
python3 scripts/lab/cnd_iconservices_cache_theme.py build --pdf-canary
python3 scripts/lab/cnd_spotlight_pdf_reachability.py build
python3 -m unittest \
  scripts.tests.test_iconservices_cache_theme_target \
  scripts.tests.test_spotlight_pdf_reachability
```

## Run on the vPhone VM

Start the iOS 26.0 vPhone and its SSH forward on port 22222, then run:

```sh
export CND_VPHONE_ROOT_PASSWORD='…'
python3 scripts/lab/cnd_spotlight_pdf_reachability.py run \
  --host 127.0.0.1 \
  --publish \
  --restart \
  --wait-for-render
```

If Spotlight does not relaunch automatically after the bounded PID replacement,
open Spotlight in the VM and rerun the command without `--restart`. The tracer
polls for Spotlight's text field and sets the query to `eBay` once the UI is
present.

The pass condition is a report containing all of:

```text
[CND_PDF_REACH] TRACE_READY
[CND_PDF_REACH] CANARY_PDF_INIT
[CND_PDF_REACH] CANARY_PDF_RENDER
```

## iOS 26.0 VM result (23A341)

The 2026-10-03 run reached the materialization gate but not the render gate.
The final test archive was independently inspected with `assetutil` before the
consumer run. Its live topology was:

```text
IconImageStack (1 layer)
  -> IconGroup (1 layer)
       -> Vector (the exact marked 663-byte PDF)
```

IconServices accepted that 30,808-byte archive, persisted the resulting
197,320-byte cache record, and could deserialize and render a producer-side
probe. A fresh Spotlight PID then displayed the eBay Top Hit and reported:

```text
[CND_PDF_REACH] TRACE_READY pid=2039 hooks=3/3
[CND_PDF_REACH] CANARY_PDF_INIT count=1 pid=2039
[CND_PDF_REACH] CANARY_PDF_INIT count=2 pid=2039
```

No `CANARY_PDF_RENDER` or `CANARY_VECTOR_RASTER` event appeared during the
60-second visible-result window. The Top Hit showed the structured record's
gray fallback rather than the PDF's red/green page.

This proves a persistent IconServices record can make each fresh Spotlight
process instantiate a chosen CoreUI PDF rendition. It does **not** prove that
Spotlight decodes page image streams. That distinction matters for
CVE-2026-86950: Apple's advisory identifies only a CoreGraphics out-of-bounds
write, while the local 26.0-to-26.7.1 CoreGraphics diff strongly concentrates
on JBIG2 bitmap and stream decoding. If the vulnerability is in that deferred
image decoder, this carrier does not yet cross its trigger boundary. Treat the
result as a useful persistent parser-reentry primitive, not as a demonstrated
one-shot code-execution operation.

The reports are:

```text
/var/tmp/cyanide-iconservices-theme-cache.log
/var/tmp/cyanide-spotlight-pdf-reachability.log
```

Restore the target record to stock afterward:

```sh
python3 scripts/lab/cnd_iconservices_cache_theme.py restore \
  --host 127.0.0.1 \
  --bundle com.ebay.iphone
```

Failure to serialize the marked PDF means CoreUI rejected or flattened the
carrier. Successful serialization without a canary event in a fresh Spotlight
PID means the record persisted but Spotlight did not materialize that rendition.
`CANARY_PDF_INIT` without `CANARY_PDF_RENDER` proves materialization but not
page-stream decoding. Only the full pass establishes the proposed persistent
decode-and-render route.
