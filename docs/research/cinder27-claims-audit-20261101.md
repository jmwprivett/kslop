# Cinder27 claims audit — 2026-11-01

## Scope and evidence standard

Read-only audit of `JBJFLab/admin/cinder27`; nothing from the clone was built or run.
The GitLab URL in the task did not expose a public repository. Web search located the
actual public Gitea repository at <https://git.jbjflab.top/admin/cinder27>, cloned with
`git clone --depth 1` to:

`/Users/josh/dev/incoming-untrusted/cinder27`

Audited HEAD: `fc17f7af7d88add68afd265883956504453e52f8` (2026-11-01 01:52:30 +08:00).
The local clone is shallow, so `git log` contains only HEAD. The full 21-commit list below
was read from the server's public commit page; tags and branches were independently read
with `git ls-remote`.

Labels used here:

- **[VERIFIED-LOCALLY]** — the narrow stated fact is directly confirmed by source or local binaries.
- **[PLAUSIBLE]** — a concrete implementation and credible supporting fix exist, but no successful target run is established.
- **[UNVERIFIED]** — the repository assertion is not supported by usable evidence or cheap local artifacts.
- **[REFUTED-LOCALLY]** — the shipped implementation or local binary contradicts the narrow claim. This does not necessarily refute the underlying CVE.

## Executive verdict

Cinder27 is **not a collection of 34 demonstrated working CVE PoCs**. It is a rapidly
assembled vulnerability-verification harness with a mixture of real candidate triggers,
parser probes, symbol lookups, local models, and placeholders. Its three headline iOS
27.2 differential claims have real binary support, and its Joliet PoC cites a real upstream
libarchive fix. Those positives coexist with PoC-farming indicators: helper-only files
presented as standalone PoCs, unrelated variants used to inflate module coverage, a
duplicated non-CVE builder, missing inventory, unsupported CVE-to-function mappings, and
no raw target-device evidence.

**Malicious-content result:** no obfuscation, large encoded blobs, checked-in executables,
external data exfiltration, credential harvesting, or `curl | sh` behavior was found.
There are intentionally intrusive local privacy/sandbox probes and two unsafe implementation
details noted below; neither is covert malware.

**Best technical lead:** CVE-2026-112705 / AppleAVE2 NTL. Local kext code confirms an
unbounded sequential 32-bit OOB store loop in 27.0.1 and new 27.2 validation. The useful
lead is the exact producer/validator path, not Cinder27's overly narrow “fixed-offset,
fixed-value, DoS only” model.

## 1. Repository inventory and provenance

### Layout

- 141 tracked files, approximately 2.2 MiB including the shallow `.git` directory.
- 34 `CVE-2026-*` directories, each with one C file and one Swift file.
- Four Python builders in CVE directories; a fifth under `arc.rr`.
- 44 standalone Swift files in total, not the claimed 45. The README's `tool.ipa`
  directory and `tool.ipa.swift` are absent; only 10 of the 11 advertised non-CVE
  module directories exist.
- `Sources/`: the SwiftUI harness and actual implementations for many modules.
- `docs/`: advisory list, kernel differential, kernel R/W assessment, SPTM/MIE notes.
- `scripts/`, `tools/`, `Resources/`, binary `Info.plist`, English and Chinese READMEs.
- **No project license file and no license identified by the repository page.**
- No symlinks, files over 1 MiB, static/dynamic executables, IPA, IPSW, panic `.ips`,
  device log, or raw run-output files are checked in. The only non-source binary data
  are three identical PNG icons and the binary plist.

Authors in the public history are `JBJF <jbjf@jbjf-Mac-mini.local>` and, for the initial
commit, `jbjf6666`. The repository has one branch and six releases/tags: v1.0, v2.0,
v2.1, v2.2, v2.2.1, and v2.3. All 21 commits are dated 2026-10-29 through 2026-11-01.

### Commit history

| Commit | Date (+08:00) | Author | Subject |
|---|---|---|---|
| `1ea76ab005` | 2026-10-29 02:11:12 | jbjf6666 | Initial Cinder27 lab: 51 modules, 31 CVE folders, 11 non-CVE folders |
| `7949c7ce9f` | 2026-10-29 20:08:55 | JBJF | v2.0 — 31 C POC twins + harness fixes |
| `ed682e859b` | 2026-10-31 15:27:09 | JBJF | v2.1 — CVE-2026-112705 / 112621 / 84636 |
| `c30aadf9bb` | 2026-10-31 15:37:58 | JBJF | Kernel R/W assessment for high/critical entries |
| `6f4ed67c38` | 2026-10-31 15:59:20 | JBJF | 112507 reachability closed: notification registration refused (-300) |
| `030df9a8b1` | 2026-10-31 16:06:28 | JBJF | Register the arrivals group in the lab list |
| `3ac5108928` | 2026-10-31 17:09:48 | JBJF | iOS 27.2 kernel differential + NTL fix-boundary sweep |
| `6a77b43942` | 2026-10-31 17:10:21 | JBJF | Complete iOS 27.2 advisory list |
| `300d4805be` | 2026-10-31 17:10:40 | JBJF | Kernel CVE table: advisory impact vs binary evidence vs R/W potential |
| `09a02858f6` | 2026-10-31 17:14:56 | JBJF | SPTM/MIE deep dive |
| `f14f7df318` | 2026-10-31 17:18:14 | JBJF | Function-level TLBI evidence |
| `0288f2e3ae` | 2026-10-31 17:19:13 | JBJF | Hardware verification plans for GMMU TLBI race and tag storage |
| `8a8efdf15d` | 2026-10-31 17:30:58 | JBJF | Add `sptm_gate.py` |
| `bdb029bb37` | 2026-10-31 17:30:36 | JBJF | Claim TLBI verification gate absent on iPhone19,7 |
| `6bb476a534` | 2026-10-31 17:35:09 | JBJF | Candidate sdl/mbuf/vm_map/framebank fix sites |
| `c7d4043a8c` | 2026-10-31 17:35:59 | JBJF | MTE SK tag-page check characterized as PA-range gate |
| `9d6c44de61` | 2026-10-31 17:48:34 | JBJF | Correct differential to iPhone19,7 v6x-pandia kernelcache |
| `1cab5b2428` | 2026-10-31 17:50:19 | JBJF | Claim IOGPU/IOUAT user path on final 27.2 |
| `4ed0f0b304` | 2026-10-31 17:58:43 | JBJF | Record IOGPU handler addresses and selector-recovery blocker |
| `7da28702a7` | 2026-11-01 01:43:39 | JBJF | ARM64 Cutter/rizin/rz-ghidra wrapper |
| `fc17f7af7d` | 2026-11-01 01:52:30 | JBJF | Cutter/rz-ghidra MTE gate and TLBI documentation |

### Claimed CVEs

The 34 primary folders are:

`112415, 112416, 112485, 112488, 112507, 112515, 112522, 112546, 112554,
112571, 112610, 112611, 112619, 112621, 112625, 112627, 112629, 112630,
112632, 112633, 112634, 112638, 112646, 112656, 112683, 112688, 112696,
112705, 112706, 113907, 113910, 113912, 65385, 84636` (all `CVE-2026-`).

The table also associates four aliases: `112476` with 112507, `112614` with 112633,
`84494` with 112696, and `86972` with 113912. Thus 38 CVE IDs are directly associated
with folders. A prose example additionally says `112627 / 112561`, but no 112561 source
or folder implements that alias; counting it as another delivered PoC would be wrong.
The separate 162-CVE document is an advisory transcription, not 162 claimed PoCs.

## 2. Red-flag and delivery-quality scan

### Security/hygiene result

- **No malicious network behavior found.** The only general HTTP client is the explicit
  IPSW range reader, which fetches a user-supplied URL. 112621 uses an HTTP server and
  loopback metadata fetch. No beaconing, hard-coded exfiltration endpoint, upload of
  probe results, analytics, or remote command execution was found.
- **No credential-theft or hidden persistence behavior found.** 112706 and the harness
  intentionally request fds for protected files, including keychain/Cookies/TCC paths,
  to measure a sandbox boundary. Reads stay local. Its own notes say those sensitive
  paths are denied and only an iTunes media-library area opens. This is intrusive
  dual-use PoC behavior, not exfiltration.
- **No obfuscation or encoded payloads.** No long base64/hex blobs, dynamic eval,
  compressed executable payload, or shell download-and-execute pattern was found.
- **No checked-in program binaries.** PNGs and `Info.plist` are the only binary files.
- Build scripts use ordinary local `swiftc`, `actool`, `zip`, and fixed output cleanup.
  The decompiler wrapper invokes a local Cutter installation.

### Unsafe or misleading implementation details (not covert malware)

1. **112619 shell injection:** its C `main` builds `mkdir -p '%s'` from an unescaped
   command-line `target-dir` and calls `system(cmd)`. A malicious argument can inject
   shell commands. An earlier `rm -rf` command string is constructed but never executed.
2. **112621 listener broader than documented:** `NWListener(using:on: .any)` is not
   explicitly restricted to loopback even though comments say “loopback server.” It
   serves only the generated page/image; no sensitive response or exfiltration was seen.
3. **112706 unconditional success text:** after a `Curl` attempt it prints that the
   daemon opened the path even when no fd was returned. The message is not a valid oracle.
4. **Intrusive file operations are explicit:** 113910 writes a decmpfs xattr; 112619
   attempts archive extraction; the app has container/file-modification tools. These
   should still be treated as untrusted PoCs and not run casually.

### PoC-farming and packaging indicators

- **16 of 34 standalone Swift CVE files are helper-only placeholders.** Thirteen are
  26-line files and three are 27-line files containing the same `enum B` and no payload
  or trigger: 112488, 112507, 112515, 112546, 112619, 112625, 112638, 112646,
  112683, 112696, 112706, 113907, 113910, 113912, 65385, plus 112485.
  Only 112621, 112705, and 84636 have substantial standalone Swift trigger drivers;
  most other non-placeholder Swift files are seed builders only.
- **The 112522 Swift file does not build its advertised Joliet seed.** It instead builds
  a CAB/LZX sample. The Joliet builder exists only in Python/C and the app sources.
- **`arc.rr/arc.rr.py` is byte-identical to `CVE-2026-112522/CVE-2026-112522.py`.**
  Both have git blob `dd783a73795188ae284fb2c42eaa6962ce740b9c`; it creates a Joliet
  ISO, not a RockRidge CL/PL cycle. `arc.rr.swift` is another helper-only stub.
- Several advertised sibling modules are comments rather than implementations:
  PVR in 112625, APPX in 112627, PDF raster in 112633, immersive audio in 113907.
- The claimed 45th standalone Swift file and `tool.ipa` directory are missing.
- The README says each Swift file contains a seed and a verbatim trigger closure;
  this is plainly false for the placeholders and seed-only files.

## 3. Per-CVE source and claim audit

“Real candidate trigger” below means the code calls a relevant parser/service with a
crafted input. It does **not** mean the vulnerability was reproduced.

| CVE / alias | Concrete repository claim and trigger | What the shipped source actually does | Verdict |
|---|---|---|---|
| **112415** | MVHEVC out-of-range layer ID; AVD.videodecoder; OOB read. C calls `CMVideoFormatDescriptionCreateFromHEVCParameterSets`. | Builds a short Annex-B-like buffer and passes the entire buffer as one parameter set. Swift builds bytes only. No decode or device result. | **[UNVERIFIED]** Parser probe, not demonstrated AVD trigger. README's OOB-read classification also differs from its advisory table's OOB write. |
| **112416** | 900 AVC slices exceed a cap; OOB write. | C passes only the first four bytes (an Annex-B start code) as one H.264 parameter set; the 900 slices are not submitted to the decoder. | **[REFUTED-LOCALLY]** The shipped C twin cannot test the claimed slice-count bug. CVE itself remains unverified. |
| **112485** | 2,000 nested USDA declarations; `libusd_ms` OOB read/unbounded recursion. | C really loads the generated file through `MDLAsset`; Python generates the nesting; Swift is a stub. Only a host PEGTL diagnostic is quoted. | **[PLAUSIBLE]** Real parser reach, but no memory-safety oracle or vulnerable/fixed target comparison. |
| **112488** | TIFF `TIFFReadDirEntry*Array` count truncation; OOB write. | C creates a TIFF with a large SBYTE count and calls ImageIO; Swift is a stub. Output is only accepted/refused and dimensions. | **[UNVERIFIED]** Candidate parser input, no corruption evidence. |
| **112507 / 112476** | XNU `ipc_port.c` request-table stale-index race/UAF; 27.2 adds `ipr`/`table` NULL checks in `ipc_misc.c`. | C and app code perform real port/notification churn and count `armed`. Current source explicitly says `armed=0` is not a 112507 test. Device claim: iPhone19,7/24A446, 12,288 attempts, all -300, 0 armed. | **Fix strings [VERIFIED-LOCALLY]**; race/CVE mapping **[UNVERIFIED]**. Earlier working-race claim is **retracted by the repo**. Its harness failure does not prove global unentitled unreachability. |
| **112515** | IOHIDFamily preparsed caps-table OOB read. | C only dlopens IOKit/GameController and resolves symbols; Swift is a stub. No HID report, device, or preparsed data. | **[UNVERIFIED]** Reachability probe only. |
| **112522** | libarchive `build_pathname_utf16be`; exact-1024-byte Joliet path causes two-byte heap OOB; host SIGTRAP; upstream fix `750e8d7b25de`. | C/Python construct a nested Joliet ISO and C walks it with libarchive. Swift instead builds an unrelated CAB sample. Upstream commit really adds `if (*len + 2 > max) return -1` after recursion. | **[PLAUSIBLE]** Strongest non-kernel candidate and exact real fix. Dynamic SIGTRAP/target result remains **[UNVERIFIED]**; upstream finding was static, not a reproduced exploit. |
| **112546** | `APACHOADecoder::Initialize` HOA coefficient OOB read. | C resolves codec symbols and calls `AudioConverterNew` with an HOA format ID; no crafted coefficient stream. | **[UNVERIFIED]** Codec-gate probe only. |
| **112554** | GPT partition-name scan reads 72 bytes from a claimed 28-byte field; kernel heap OOB read. | C/Swift only construct and parse their own image buffer. The C model scans 36 UTF-16 units inside a 128-byte GPT entry at offset 56 (72 bytes available), not a 28-byte allocation. No mount or kernel read. | **Shipped kernel-leak claim [REFUTED-LOCALLY]**; underlying kext bug/fix **[UNVERIFIED]**. Repo itself elsewhere admits this is only a read-width model. |
| **112571** | ImageIO `ReadUserComment`; short EXIF read discloses metadata. | C/Swift create EXIF with a far value offset; C asks ImageIO for properties and an image. It does not print/compare the returned comment bytes against a baseline. | **[UNVERIFIED]** Real metadata-parser probe, no disclosure oracle. |
| **112610** | CoreGraphics `_cmap_convert`; `/UseCMap` recursion OOB write; negative-result probe. | C/Swift build and render a PDF with a malformed codespace range, but no `/UseCMap` recursion is constructed. | **Claimed recursion PoC [REFUTED-LOCALLY]**; CVE mapping **[UNVERIFIED]**. |
| **112611** | `_cg_shading_type5_draw`; type-5 shading R=136 stack overflow/value-controlled write. | C/Swift build a type-5 shading PDF and C renders it. Host “armed” crash is asserted, with no crash log or target build result. | **[UNVERIFIED]** Real candidate renderer trigger, unproved primitive. |
| **112619** | CalendarFoundation `_UnzipArchiveWithLimits`; attachment extraction OOB/write containment failure. | C probes Objective-C selectors and tests generic libarchive with `SECURE_NODOTDOT`; it never invokes CalendarFoundation extraction. | **[UNVERIFIED]** Generic containment probe, not a Calendar PoC. Shell-injection issue noted above. |
| **112621** | `LPAnimatedImageTranscoder`; frame 0 is 256x16, frame 1 256x48; later-frame clear writes 32,768 bytes past pool; 27.2 rejects mismatch. | Swift genuinely serves a two-frame image and invokes `LPMetadataProvider`. C does not call LinkPresentation; it creates its own 16-row mapping and deliberately clears 48 rows into a guard page. | **Swift candidate [PLAUSIBLE]**; C guard-page result is only a **self-model**, not vulnerability evidence. Claimed iOS crashes/fix **[UNVERIFIED]**. |
| **112625** | ImageIO `KTX2ReadPlugin`; dimensions/level arithmetic overflow (advisory table says underflow). | C decodes a tiny-level KTX2; Python and C emit different header/level fields despite the byte-identical-seed claim. No DFD or meaningful arithmetic oracle is supplied. | **[UNVERIFIED]** Malformed-input probe with inconsistent builders. |
| **112627 / prose 112561** | `BCReadPlugin::initialize`; truncated 512x512 BC7 mip OOB read; APPX sibling also advertised. | C/Swift build a short DDS and C calls ImageIO. No APPX implementation and no 112561 source. | **[UNVERIFIED]** Candidate decode probe only. |
| **112629** | `GPSCopy::processData`; out-of-range GPS IFD offset OOB read. | C/Swift build EXIF GPS metadata; C requests ImageIO properties/decode. No resulting GPS values or memory oracle are checked. | **[UNVERIFIED]** Real parser probe only. |
| **112630** | `IIO_Reader_PNG::getImageCount`; truncated APNG fcTL exposes uninitialized stack geometry. | C/Swift produce three fcTL truncation/control modes; C gets frame count/dimensions. No repeated-decode fingerprint or comparison demonstrates uninitialized data. | **[UNVERIFIED]** Reasonable malformed-input probe, no leak evidence. |
| **112632** | `decodeStripChunky`; truncated TIFF strip copies uninitialized heap into pixels. | C/Swift build a short second strip and C decodes it. Pixel contents are never read or compared, so the claimed information leak has no oracle. | **[UNVERIFIED]** Decode probe only. |
| **112633 / 112614** | `decodeStripPlanar`; four planes into three-channel destination causes OOB scatter; PDF-raster sibling also advertised. | C builds planar TIFF and decodes it. Swift has layout differences and omits a proper StripByteCounts blob. No PDF-raster implementation or corruption oracle. | **[UNVERIFIED]** Candidate TIFF input; alias and sibling implementation unsupported. |
| **112634** | `_JPEGFile::processData`; oversized JPEG APP1 marker length OOB read. | C/Swift emit an APP1 length larger than the file and C calls ImageIO. Only entry acceptance/refusal is reported. | **[UNVERIFIED]** Generic truncation probe. |
| **112638** | `ACLC3Decoder::AppendInputData`; LC3 input-buffer overflow; entitlement gated. | C only constructs converters for two LC3 format shapes; no compressed input or append call. | **[UNVERIFIED]** Codec-gate probe only. |
| **112646** | SpringBoard `SBHomeScreenService`; stashed-layout name validation; OOB write. | C checks whether a class/selector exists in the current non-SpringBoard process and stats a container plist. No XPC message or stashed layout is sent. | **[UNVERIFIED]** Presence probe cannot establish a fix or vulnerability. |
| **112656** | CoreText `GetLigatureCaretPositionsForGlyph`; GDEF caret offset `0x7f00` OOB read. | C/Swift construct a minimal font; C calls `CTFontGetLigatureCaretPositions`. This is a relevant API/offset-chain candidate, but no leak or target result is recorded. | **[UNVERIFIED]** Real candidate trigger without proof of OOB access. |
| **112683** | FontParser Type-2 interpreter; 300 operands overflow a 48-entry stack. | Python/C build the CFF; C loads and draws it through CoreText. Swift is a stub. No vulnerable/fixed result or crash evidence. | **[UNVERIFIED]** Real candidate font trigger. |
| **112688** | `hevcbridgeParseVdrDmDataPayloadExMetadataBlocks`; six block-ID-1 entries exceed capacity four. | C builds RPU data and calls the macOS one-`CFDataRef` ABI plus a sweep. README's simulator SIGSEGV came from using the incompatible iOS four-argument call on macOS, i.e. an ABI crash at entry. | **[UNVERIFIED]** ABI mismatch is not evidence for the claimed array overrun. Relevant parser probe remains. |
| **112696 / 84494** | AppleH16ANEInterface OOB write/kernel reachability. | C only resolves ANE/CoreML symbols; Swift is a stub. Repo explicitly calls it an honest negative with no primitive. | **[UNVERIFIED]** No trigger; no CVE attribution evidence. |
| **112705** | AppleAVE2 HEVC `NumberOfTemporalLayers=16463`; `EncoderUsage=1`, `RCMode=20`, frame submit; 27.0–27.1 kernel data abort at +0xDA78, 16462 survives, 27.2 returns -12900. | Swift/C implement the real VideoToolbox recipe, property sweep, and frame submission, with a macOS host guard. No panic log is included. Local kext analysis confirms an OOB store loop and 27.2 validation, but not the exact device results. | **Bug and new validation [VERIFIED-LOCALLY]**; exact panic/threshold/status **[UNVERIFIED here]**. “Fixed-offset constant fill only” is **[REFUTED-LOCALLY]**. |
| **112706** | `mediaplaybackd.bytestream.xpc`; `.rp1/.rp2/.org`, then `Curl` vends an fd for a caller-chosen path. | C implements the FigXPC handshake, URL message, fd duplication/read. Harness says only iTunes media-library files open and sensitive containers are denied. macOS “Connection invalid” is a negative. | **[UNVERIFIED]** Real service trigger, but no raw device evidence and success output is unconditional. Broad cross-sandbox claims must be limited to the mapped domain. |
| **113907** | `AVHapticServerInstance`; custom haptic audio-event declared-size mismatch; OOB write. | C creates a normal zero-sample WAV and delivers a CoreHaptics event. Its `declared_bytes = 4` variable is only printed and never enters the WAV or API call. | **Claimed mismatch trigger [REFUTED-LOCALLY]**; CVE **[UNVERIFIED]**. |
| **113910** | XNU/AppleFSCompression chunked zlib under-production discloses kernel heap; 27.2 adds produced-vs-expected diagnostic. | C builds type-4 `com.apple.decmpfs` xattrs, sweeps under-producing chunks, reads back and classifies pointers. Host result is plain `0x41`, zero pointers; no device leak output. | **New diagnostic [VERIFIED-LOCALLY]**; actual leak/KASLR claim **[UNVERIFIED]**. |
| **113912 / 86972** | `mpddrc::UniDrcSelection`; malformed MPEG-D DRC downmix coefficients OOB read. | C resolves symbols and calls `AudioConverterNew` with `drc1`; no DRC payload or coefficient matrix. | **[UNVERIFIED]** Codec-gate probe only. |
| **65385** | `IOHIDEventAppendEvent`; short heap/fixed-offset OOB write. | C only resolves event APIs and expressly never appends an event. | **[UNVERIFIED]** Symbol-reachability probe; repo admits no primitive. |
| **84636** | configd dynamic store exposes SSID/router MAC without `wifi-info`. | C/Swift genuinely query `SCDynamicStore`, enumerate network keys, and compare `CNCopyCurrentNetworkInfo`. No on-device output is checked in. | **[UNVERIFIED]** Real privacy probe, not demonstrated vulnerable target result. |

## 4. Device/build claims and repository retractions

The primary target is consistently described as iPhone19,7 / iOS 27.0.1 / 24A446,
but **there is no raw device evidence in the repository**. In particular:

- **112507:** the current docs retract the earlier “survived the interleaving” conclusion.
  They say 12,288 registration attempts produced 12,288 `-300` results and zero armed
  entries on the target. This is the most responsible correction in the repo, but it is
  still an unaccompanied narrative. It proves, at most, that this harness did not arm
  the table—not that every unentitled process or every notification shape is unreachable.
- **112705:** 16463 panic / 16462 survival / AppleAVE2+0xDA78 / 27.2 `-12900` and a prior
  macOS panic are all repeated claims. No `.ips` or console transcript is included.
  A separately audited external AVETemporalPoC package does contain a structurally
  consistent panic, but that is not evidence supplied by Cinder27.
- **112522:** host malloc SIGTRAP is claimed without output. The upstream commit confirms
  the source bug shape but does not dynamically reproduce it.
- **112688:** the reported simulator crash is expressly an incompatible-ABI entry crash,
  and should not be counted as a vulnerability oracle.
- **112621:** the precise 32,768-byte figure comes from its own guard-page model, not from
  observing `LPAnimatedImageTranscoder` corrupt a real pooled allocation.
- **113910:** the only quoted run is a negative host run with zero kernel pointers.
  Calling it a “real repeatable kernel heap leak” goes beyond the included evidence.
- **112706:** macOS absence/“Connection invalid” is not target confirmation. The more
  specific app text limits successful reads to the iTunes media-library domain.
- The remaining entries mostly claim entry-layer refusals on the host, not successful
  vulnerable-device reproduction.

## 5. Local binary cross-checks

Artifacts used, without executing repository code:

- `/Users/josh/dev/iOS27.0.1-SPTM-Research/corpus/24A446/kernelcache.raw`
- `/Users/josh/dev/iOS27.0.1-SPTM-Research/corpus/24B119-d23/kernelcache.raw`
- `/Users/josh/dev/iOS27.0.1-SPTM-Research/corpus/24B119-iphone17/kernelcache.raw`
- `/tmp/ave-analysis/v-d23-27.0.1/AppleAVE2.__TEXT_EXEC.bin`
- `/tmp/ave-analysis/f-d23-27.2/AppleAVE2.__TEXT_EXEC.bin`
- Corresponding `AppleAVE2.kextblob` and `meta.json` files.

### CVE-2026-112507 / IPC

The 24A446 raw kernelcache has no `ipc_misc.c` or matching `ipr !=` assertion. The
24B119-d23 image contains:

```text
file offset 268582: ipr != ((void*)0)
file offset 268600: table != ((void*)0)
file offset 326438: ipc_misc.c
```

The iphone17 24B119 image contains the same additions at offsets 267542, 267560, and
325368. This directly verifies the **new-string differential**. It does not independently
assign the checks to 112507, prove a UAF, or validate the -300 device run. A simple exact
`adrp`/`add` scan over the supplied 27.2 `__TEXT_EXEC` slice did not resolve a direct xref;
that is inconclusive because assertions may be reached through other reference forms.
**Verdict: [VERIFIED-LOCALLY] for added strings; [UNVERIFIED] for CVE mapping and race.**

### CVE-2026-113910 / decmpfs

24A446 contains a `ChunkCompression.cpp` build path but not the quoted produced/expected
diagnostic. 24B119-d23 adds:

```text
file offset 4343447: %s:%d: chunk %u produced %lld of %lld expected bytes
```

The same addition appears in both 27.2 betas and the iphone17 final image. This confirms
a new diagnostic beside the claimed component. A diagnostic string alone does not prove
the exact rejection behavior, a kernel disclosure, or CVE assignment.
**Verdict: [VERIFIED-LOCALLY] for the differential; [UNVERIFIED] for the leak.**

### CVE-2026-112705 / AppleAVE2

The vulnerable 27.0.1 kext lacks the quoted NTL bound strings. The 27.2 kext adds:

```text
number of temporal layers (prop) is out of range %d %d %d
0 <= pInfo->uPropCfg.sHEVC.iNumberOfTemporalLayers &&
    pInfo->uPropCfg.sHEVC.iNumberOfTemporalLayers <= 7
AVE_HEVC_CheckVPSExtBounds
```

Thus the existence of new NTL validation is confirmed. The README's simplified “property
is clamped to 0…7” is not the whole story: the inspected fixed code has two validators
that **reject values above 6**, not 7:

```asm
f+0x714B0  ldr w8, [x20, #0x1888]
f+0x714B4  cmp w8, #6
f+0x714B8  b.hi ...

f+0x71A60  ldr w10, [x23, #8]
f+0x71A64  cmp w10, #6
f+0x71A68  b.hi ...
```

The vulnerable 27.0.1 encode-preparation loop is a forward sequential OOB write:

```asm
v+0x11C084  ldr w11, [x8, #0x3760]       ; effective count
v+0x11C08C  str w24, [x10, x9, lsl #2]  ; S + 0x4678 + 4*i
v+0x11C090  add x9, x9, #1
v+0x11C094  add x12, x12, #1
v+0x11C098  cmp x12, x11
v+0x11C09C  b.lo v+0x11C08C
```

The fixed loop still has the same store shape at a shifted structure layout; the new
input checks are the mitigation. This confirms a substantive bug and fix, while refuting
Cinder27's description of the original primitive as only a fixed-offset constant fill.
The exact runtime value control, 16463/16462 boundary, panic, and -12900 property status
were not rerun here.

### Other differential claims

- The kernel `__DATA_SPTM` identity claim is **[VERIFIED-LOCALLY]**: both supplied
  27.0.1 and 27.2 segments are 311,296 bytes with SHA-256
  `f4bc1e5e95f61af52ffe72c0566e9050f194905d04490007de194223803f8bb3`.
- The other quoted new strings `VM entry %p lock shared lock overflow`,
  `Page modified after framebank withdraw`, and `size <= sdl->sdl_alen` are present in
  27.2 and absent in 27.0.1. Their CVE/function assignments remain inferences.
- Separate SPTM firmware, DeviceTree gating, TLBI reachability, and IOGPU handler claims
  were not needed for the per-CVE verdict and were not independently validated here.

## 6. Credibility assessment

### What argues for genuine technical work

- The IPC, decmpfs, and AVE2 differential strings are real and correctly localized.
- The local AVE2 code supports a real memory-safety issue and new validation.
- The 112522 Joliet builder is tied to an exact upstream fix and the correct function and
  two-byte boundary condition.
- Several C files are substantive, relevant API drivers rather than empty main functions.
- The authors explicitly retract 112507, admit host negatives, and often distinguish a
  probe/model from arbitrary kernel R/W.

### What argues against treating it as a validated research-lab corpus

- No raw panic logs, device logs, archived run output, or reproducible target result set.
- Nearly half the standalone Swift CVE files are placeholders, contrary to the README.
- Multiple C “twins” are only symbol probes or local self-models; some cannot reach the
  claimed bug at all (112416, 112610, 113907).
- CVE aliases and sibling module names are asserted without corresponding code.
- Advisory class, claimed primitive, and implementation sometimes disagree.
- One non-CVE builder is an exact duplicate of another PoC, and one advertised tool is absent.
- Broad claims such as “all 34 have recorded oracles” include negative entry checks,
  incompatible-ABI crashes, and unconditional success messages.

**Overall:** this is best characterized as **PoC farming/repackaging with some authentic
binary-differential research**, not as 34 independently verified vulnerabilities and not
as malware. Use the three locally confirmed differential leads and the exact Joliet fix;
do not treat the remaining CVE-to-function assignments, device outcomes, or primitive
ratings as established without independent reproduction.

## References

- Repository: <https://git.jbjflab.top/admin/cinder27>
- Commit history: <https://git.jbjflab.top/admin/cinder27/commits/branch/main>
- libarchive upstream Joliet fix: <https://github.com/libarchive/libarchive/commit/750e8d7b25deeb67a976ab0c9f482ec1d2ac68a4>
