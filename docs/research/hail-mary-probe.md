# Hail Mary Probe

`CNDHailMaryProbe` is a build-locked, observation-only diagnostic for
`iPhone17,2` on `23A341`. It now proves the shared-cache relationship through
the live process page tables and exact physical bytes without changing
SpringBoard, Spotlight, either pmap, or any backing object.

The probe uses the offline-derived location for
`-[SBIconImageView effectivelyPrefersFlatImageLayers]`:

- unslid instruction address: `0x1be102ef0`
- subcache file offset: `0x44aaef0`
- expected word: `0x1a9f17f4` (`cset w20, eq`)
- 16 KiB object-page offset: `0x44a8000`

After validated KRW is available, the observation stage performs kernel reads
only. KRW acquisition is outside that count and is not claimed to be
mutation-free. The probe locates SpringBoard and Spotlight by exact kernel
process name, walks their task maps and nested submaps, reconstructs the root
virtual address, and first compares the leaf `vm_object` and object offset.
Each map header is sampled again after traversal; a changed entry count,
changed first entry, malformed link, unexpected offset layout, unsupported
device/build, absent Spotlight process, ambiguous candidate set, or
copy-on-write leaf fails closed.

The physical stage is derived from the exact `23A341` kernelcache. It validates
the live kernel UUID, reads the exact `gVirtBase`, `gPhysBase`, and `gPhysSize`
globals plus the exact-build dynamic physical-map range anchors, checks the
live 16 KiB user page-table geometry, and walks
each process from `vm_map.pmap` through its SPTM page tables. User roots are
validated as 128-byte subpage root tables; lower-level table pages retain
16 KiB alignment. Every translation entry and pmap anchor is reread before the
translation is accepted.

A `confirmed-shared-physical-frame-and-bytes` result requires both page-table
walks to resolve the target virtual address to the same physical address and
frame. The probe then reads the 188-byte context directly through the kernel's
physical-to-virtual mapping, requires instruction word `0x1a9f17f4` and SHA-256
`542063d6c8ea82afbe734ace1895ba0f2b7ab15160c6053176604644741f20d5`,
and repeats both translations after the byte read. Any mismatch fails closed.
The exact derivation is recorded in
`hail-mary-physical-page-proof-23A341-iphone17,2.json`.

The report is saved to the app's Documents directory as
`CNDHailMaryProbe.json`. Open Spotlight first, then choose **Run Hail Mary
Physical Proof** under Settings → Quick Actions.

## Physical result: iPinky Max

The installed build was run on the exact `iPhone17,2` / `23A341` device. The
probe derived a shared-cache slide of `0x19dc000` independently in both
processes and reduced seven split-cache offset candidates to one `.19`
candidate per process. SpringBoard and Spotlight reported:

- runtime instruction address: `0x1bfadeef0`
- identical shared submap: `0xffffffe374f44310`
- identical leaf map entry: `0xffffffe37502bc90`
- identical leaf object: `0xffffffe375056e00`
- identical object byte offset: `0x44aaef0`
- identical 16 KiB object-page slot: `0x44a8000` + `0x2ef0`
- leaf protection: read + execute (`5`)
- `needs_copy`: false in both processes

The earlier object-only verdict was `confirmed-shared-backing-page-slot`. The leaf
entries' `is_shared` bit was false, but both task maps pointed through the same
shared-region submap to the exact same leaf entry and object; the result does
not depend on that accounting flag. That result is retained as a prerequisite;
the physical-page result below must be populated from a newly installed run of
the expanded probe and is not inferred from the earlier evidence.

## Physical page-table result

The expanded build was installed and run on iPinky Max. The live kernel UUID
matched the extracted `23A341` kernelcache, and the exact-build physical-map
decoder returned 16 dynamic ranges. SpringBoard and Spotlight independently
walked from different pmaps and different 128-byte root tables to the same L3
table and entry:

- runtime virtual address: `0x1bfadeef0`
- SpringBoard pmap / root PA: `0xffffffe67610df00` / `0x1010ee84700`
- Spotlight pmap / root PA: `0xffffffe676127a80` / `0x1010ee87c80`
- shared L3 table / entry address: `0xfffffff05e408000` / `0xfffffff05e40b5b8`
- shared L3 entry value: `0x002001009acec6c3`
- physical address: `0x1009aceeef0`
- 16 KiB physical frame: `0x1009acec000`
- frame kernel virtual mapping: `0xfffffff0d4510000`
- instruction word: `0x1a9f17f4` (exact match)
- 188-byte guard SHA-256: exact match
- both post-read translations: unchanged

The final verdict was `confirmed-shared-physical-frame-and-bytes`, with zero
kernel writes and zero target-process mutations in the observation stage. This
proves the physical prerequisite only; the probe still contains no writer and
does not apply the proposed shared-page patch.
