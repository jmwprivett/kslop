"""LLDB callbacks for the bounded IOSurface client-reclaim witness (V11).

Four exact-build hardware breakpoints on iOS 26.0 (23A341), IOSurface 393.2.9:

* ``insert-link``: final linkage store of a selector-17 node
  (``str x24, [x23, #0x8]``); captures node=x23, owner=x19, client=x21,
  ``node+0x58``.
* ``teardown-clear``: the user-client termination store that clears
  ``client+0xd8`` (``str xzr, [x19, #0xd8]``); captures client=x19, the
  pre-clear ``client+0xd8`` and the isa at ``client+0x0``.
* ``deliver-walk``: the notification walk's ``ldr x0, [x22, #0x58]``;
  captures node=x22, owner=x20, ``node+0x58``.
* ``deliver-lockload``: delivery's ``ldr x0, [x0, #0xd8]``; captures
  client=x0, the isa at ``client+0x0`` and the lock value ``client+0xd8``.

The isa+lock pair at lockload, compared with the isa recorded at teardown,
distinguishes "same object, lock cleared" from "address reclaimed by another
allocation" — the reclaim detector. Callbacks only read registers and bounded
fields; they never modify registers or kernel memory.
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any

import lldb


_CONFIG: dict[str, Any] = {}
_BREAKPOINTS: list[lldb.SBBreakpoint] = []
_COUNTS = {
    "insertLink": 0,
    "teardownClear": 0,
    "deliverWalk": 0,
    "deliverLockload": 0,
    "readErrors": 0,
}

# IOSurface __TEXT_EXEC offsets; live = 0xfffffe000907e2b0 + slide + off
SITE_OFFSETS = {
    "insertLink": 0x1EE4C,       # str x24, [x23, #0x8]
    "teardownClear": 0x23A54,    # str xzr, [x19, #0xd8]
    "deliverWalk": 0x1EFA4,      # ldr x0, [x22, #0x58]
    "deliverLockload": 0x2828C,  # ldr x0, [x0, #0xd8]
}

SITE_EXPECTED = {
    "insertLink": "str x24, [x23, #0x8]",
    "teardownClear": "str xzr, [x19, #0xd8]",
    "deliverWalk": "ldr x0, [x22, #0x58]",
    "deliverLockload": "ldr x0, [x0, #0xd8]",
}


def _register(frame: lldb.SBFrame, name: str) -> int | None:
    value = frame.FindRegister(name)
    if not value.IsValid():
        return None
    return value.GetValueAsUnsigned()


def _read_u64(process: lldb.SBProcess, address: int | None) -> tuple[int | None, str | None]:
    if address is None or address < 0x1000:
        return None, "unreadable address"
    error = lldb.SBError()
    value = process.ReadUnsignedFromMemory(address, 8, error)
    if error.Fail():
        return None, error.GetCString() or "unknown memory read error"
    return value, None


def _hex(value: int | None) -> str | None:
    return f"{value:#018x}" if value is not None else None


def _record(event: dict[str, Any]) -> None:
    with Path(_CONFIG["event_path"]).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")
        stream.flush()


def _event(frame: lldb.SBFrame, stage: str) -> dict[str, Any]:
    process = frame.GetThread().GetProcess()
    return {
        "schema": "com.zeroxjf.cyanide.iosurface-client-reclaim-witness",
        "schemaVersion": 1,
        "stage": stage,
        "pc": _hex(frame.GetPC()),
        "threadID": frame.GetThread().GetThreadID(),
        "stopID": process.GetStopID(),
    }


def _fields(frame: lldb.SBFrame, base: int | None, offsets: tuple[int, ...]) -> dict[str, Any]:
    process = frame.GetThread().GetProcess()
    out: dict[str, Any] = {}
    for off in offsets:
        value, error = _read_u64(process, (base + off) if base is not None else None)
        if value is None:
            _COUNTS["readErrors"] += 1
        out[f"field_{off:#x}"] = _hex(value)
        out[f"field_{off:#x}_error"] = error
    return out


def on_insert_link(frame: lldb.SBFrame, _bp_loc: lldb.SBBreakpointLocation,
                   _internal_dict: dict[str, Any]) -> bool:
    event = _event(frame, "insert-link")
    node = _register(frame, "x23")
    owner = _register(frame, "x19")
    client = _register(frame, "x21")
    event.update({
        "node": _hex(node),
        "owner": _hex(owner),
        "clientArg": _hex(client),
    })
    event.update(_fields(frame, node, (0x58,)))
    _COUNTS["insertLink"] += 1
    _record(event)
    return False


def on_teardown_clear(frame: lldb.SBFrame, _bp_loc: lldb.SBBreakpointLocation,
                      _internal_dict: dict[str, Any]) -> bool:
    event = _event(frame, "teardown-clear")
    client = _register(frame, "x19")
    event.update({"client": _hex(client)})
    event.update(_fields(frame, client, (0x0, 0xD8)))
    _COUNTS["teardownClear"] += 1
    _record(event)
    return False


def on_deliver_walk(frame: lldb.SBFrame, _bp_loc: lldb.SBBreakpointLocation,
                    _internal_dict: dict[str, Any]) -> bool:
    event = _event(frame, "deliver-walk")
    node = _register(frame, "x22")
    owner = _register(frame, "x20")
    event.update({"node": _hex(node), "owner": _hex(owner)})
    event.update(_fields(frame, node, (0x58,)))
    _COUNTS["deliverWalk"] += 1
    _record(event)
    return False


def on_deliver_lockload(frame: lldb.SBFrame, _bp_loc: lldb.SBBreakpointLocation,
                        _internal_dict: dict[str, Any]) -> bool:
    event = _event(frame, "deliver-lockload")
    client = _register(frame, "x0")
    event.update({"client": _hex(client)})
    event.update(_fields(frame, client, (0x0, 0xD8)))
    _COUNTS["deliverLockload"] += 1
    _record(event)
    return False


_CALLBACKS = {
    "insertLink": on_insert_link,
    "teardownClear": on_teardown_clear,
    "deliverWalk": on_deliver_walk,
    "deliverLockload": on_deliver_lockload,
}


def _hardware_breakpoint(debugger: lldb.SBDebugger, address: int,
                         callback: str) -> lldb.SBBreakpoint:
    target = debugger.GetSelectedTarget()
    breakpoint = target.BreakpointCreateByAddress(address)
    if breakpoint.GetNumLocations() != 1:
        raise RuntimeError("IOSurface reclaim breakpoint did not resolve exactly")
    error = breakpoint.SetIsHardware(True)
    if error.Fail() or not breakpoint.IsHardware():
        raise RuntimeError(
            "could not arm required hardware breakpoint: "
            + (error.GetCString() or "unknown LLDB error")
        )
    callback_result = lldb.SBCommandReturnObject()
    debugger.GetCommandInterpreter().HandleCommand(
        f"breakpoint command add -F {callback} {breakpoint.GetID()}",
        callback_result,
    )
    if not callback_result.Succeeded():
        raise RuntimeError(
            "could not install breakpoint callback: "
            + (callback_result.GetError() or "unknown LLDB error")
        )
    return breakpoint


def _verify_site(debugger: lldb.SBDebugger, name: str, address: int) -> str:
    result = lldb.SBCommandReturnObject()
    debugger.GetCommandInterpreter().HandleCommand(
        f"disassemble --start-address {address:#x} --count 1", result
    )
    if not result.Succeeded():
        raise RuntimeError(
            f"could not disassemble {name} site {address:#x}: {result.GetError()}"
        )
    text = ""
    for line in result.GetOutput().splitlines():
        line = line.strip()
        if line.startswith(f"0x{address:x}") or line.startswith(f"{address:#x}"):
            text = line.split(":", 1)[1].strip() if ":" in line else line
            break
    if not text:
        raise RuntimeError(f"no disassembly line found for {name} site {address:#x}")
    mnemonic = text.split(None, 1)[0]
    if mnemonic != SITE_EXPECTED[name].split()[0]:
        raise RuntimeError(
            f"live instruction at {name} {address:#x} is {text!r}, expected "
            f"{SITE_EXPECTED[name]!r}"
        )
    return text


def install(debugger: lldb.SBDebugger, slide: int, event_path: str) -> None:
    """Verify and arm the four reclaim breakpoints for the current boot slide."""
    global _CONFIG, _BREAKPOINTS, _COUNTS
    if slide <= 0 or slide > 0x100000000:
        raise RuntimeError("slide is outside the bounded observer contract")
    iosurface_static_base = 0xFFFFFE000907E2B0
    _CONFIG = {"slide": slide, "event_path": event_path}
    _BREAKPOINTS = []
    _COUNTS = dict.fromkeys(_COUNTS, 0)
    Path(event_path).unlink(missing_ok=True)

    armed = []
    for name, offset in SITE_OFFSETS.items():
        address = iosurface_static_base + slide + offset
        text = _verify_site(debugger, name, address)
        bp = _hardware_breakpoint(
            debugger, address, f"cnd_lldb_iosurface_reclaim.{_CALLBACKS[name].__name__}"
        )
        armed.append((name, address, text))
        _BREAKPOINTS.append(bp)
    print(
        "CND_IOSURFACE_RECLAIM_ARMED slide={:#x} ".format(slide)
        + " ".join(f"{n}={a:#x}({t})" for n, a, t in armed),
        flush=True,
    )


def capture_for(debugger: lldb.SBDebugger, seconds: float) -> None:
    """Capture asynchronously for a bounded interval."""
    if seconds <= 0 or seconds > 300:
        raise RuntimeError("capture interval must be in (0, 300] seconds")
    process = debugger.GetSelectedTarget().GetProcess()
    debugger.SetAsync(True)
    error = process.Continue()
    if error.Fail():
        debugger.SetAsync(False)
        raise RuntimeError(
            "IOSurface reclaim capture could not continue: "
            + (error.GetCString() or "unknown LLDB error")
        )
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(0.05)
    if process.GetState() == lldb.eStateRunning:
        stop_error = process.Stop()
        if stop_error.Fail():
            debugger.SetAsync(False)
            raise RuntimeError(
                "IOSurface reclaim capture could not stop: "
                + (stop_error.GetCString() or "unknown LLDB error")
            )
    debugger.SetAsync(False)


def summary() -> dict[str, Any]:
    result = {"counts": dict(_COUNTS)}
    print("CND_IOSURFACE_RECLAIM_SUMMARY " + json.dumps(result, sort_keys=True))
    return result
