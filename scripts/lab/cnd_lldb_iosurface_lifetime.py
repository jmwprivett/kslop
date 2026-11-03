"""LLDB callbacks for the bounded IOSurfaceRootUserClient lifetime witness.

The callbacks observe two exact-build instructions with hardware breakpoints:
the teardown store that clears ``client+0xd8`` and the delivery load of that
same field.  They never modify registers or kernel memory.
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any

import lldb


_CONFIG: dict[str, Any] = {}
_FREED: dict[int, int | None] = {}
_MATCH: dict[str, Any] | None = None
_BREAKPOINTS: list[lldb.SBBreakpoint] = []


def _register(frame: lldb.SBFrame, name: str) -> int | None:
    value = frame.FindRegister(name)
    if not value.IsValid():
        return None
    return value.GetValueAsUnsigned()


def _read_u64(process: lldb.SBProcess, address: int) -> tuple[int | None, str | None]:
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


def _event(frame: lldb.SBFrame, stage: str, client: int | None,
           lock: int | None, read_error: str | None) -> dict[str, Any]:
    thread = frame.GetThread()
    return {
        "schema": "com.zeroxjf.cyanide.iosurface-lifetime-witness",
        "schemaVersion": 1,
        "stage": stage,
        "pc": _hex(frame.GetPC()),
        "threadID": thread.GetThreadID(),
        "client": _hex(client),
        "lockAtD8": _hex(lock),
        "memoryReadError": read_error,
    }


def on_free(frame: lldb.SBFrame, _bp_loc: lldb.SBBreakpointLocation,
            _internal_dict: dict[str, Any]) -> bool:
    """Record the client and pre-clear lock value, then continue."""
    client = _register(frame, "x19")
    lock = None
    read_error = "x19 unavailable"
    if client is not None:
        lock, read_error = _read_u64(frame.GetThread().GetProcess(), client + 0xD8)
        _FREED[client] = lock
    event = _event(frame, "free-before-zero", client, lock, read_error)
    event["freeCount"] = len(_FREED)
    _record(event)
    return False


def on_delivery(frame: lldb.SBFrame, _bp_loc: lldb.SBBreakpointLocation,
                _internal_dict: dict[str, Any]) -> bool:
    """Stop only when delivery reuses a recorded client whose lock is zero."""
    global _MATCH
    client = _register(frame, "x0")
    lock = None
    read_error = "x0 unavailable"
    if client is not None:
        lock, read_error = _read_u64(frame.GetThread().GetProcess(), client + 0xD8)
    event = _event(frame, "delivery-before-lock-load", client, lock, read_error)
    event["matchedFree"] = client in _FREED if client is not None else False
    event["lockBeforeZero"] = _hex(_FREED.get(client)) if client is not None else None
    matched = bool(event["matchedFree"] and lock == 0 and read_error is None)
    event["lifetimeMatch"] = matched
    _record(event)
    if matched:
        _MATCH = event
        print(
            "CND_IOSURFACE_LIFETIME_MATCH "
            f"client={event['client']} before={event['lockBeforeZero']} "
            f"after={event['lockAtD8']}",
            flush=True,
        )
    return matched


def install(debugger: lldb.SBDebugger, free_address: int,
            delivery_address: int, event_path: str) -> None:
    """Install exactly two hardware breakpoints on a connected target."""
    global _CONFIG, _FREED, _MATCH, _BREAKPOINTS
    _CONFIG = {
        "free_address": free_address,
        "delivery_address": delivery_address,
        "event_path": event_path,
    }
    _FREED = {}
    _MATCH = None
    Path(event_path).unlink(missing_ok=True)

    target = debugger.GetSelectedTarget()
    free_breakpoint = target.BreakpointCreateByAddress(free_address)
    delivery_breakpoint = target.BreakpointCreateByAddress(delivery_address)
    _BREAKPOINTS = [free_breakpoint, delivery_breakpoint]
    for breakpoint, callback in (
        (free_breakpoint, "cnd_lldb_iosurface_lifetime.on_free"),
        (delivery_breakpoint, "cnd_lldb_iosurface_lifetime.on_delivery"),
    ):
        if breakpoint.GetNumLocations() != 1:
            raise RuntimeError("IOSurface lifetime breakpoint did not resolve exactly")
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
    print(
        "CND_IOSURFACE_LIFETIME_ARMED "
        f"free={free_address:#x} delivery={delivery_address:#x}",
        flush=True,
    )


def capture(debugger: lldb.SBDebugger) -> None:
    """Continue until an exact lifetime match or an external interrupt."""
    process = debugger.GetSelectedTarget().GetProcess()
    error = process.Continue()
    if error.Fail():
        raise RuntimeError(
            "IOSurface lifetime capture could not continue: "
            + (error.GetCString() or "unknown LLDB error")
        )


def capture_for(debugger: lldb.SBDebugger, seconds: float) -> None:
    """Capture asynchronously for a bounded interval or until a match."""
    if seconds <= 0 or seconds > 120:
        raise RuntimeError("capture interval must be in (0, 120] seconds")
    process = debugger.GetSelectedTarget().GetProcess()
    debugger.SetAsync(True)
    error = process.Continue()
    if error.Fail():
        debugger.SetAsync(False)
        raise RuntimeError(
            "IOSurface lifetime capture could not continue: "
            + (error.GetCString() or "unknown LLDB error")
        )
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and _MATCH is None:
        time.sleep(0.05)
    if process.GetState() == lldb.eStateRunning:
        stop_error = process.Stop()
        if stop_error.Fail():
            debugger.SetAsync(False)
            raise RuntimeError(
                "IOSurface lifetime capture could not stop: "
                + (stop_error.GetCString() or "unknown LLDB error")
            )
    debugger.SetAsync(False)


def summary() -> dict[str, Any]:
    result = {
        "freePointerCount": len(_FREED),
        "matched": _MATCH is not None,
        "match": _MATCH,
    }
    print("CND_IOSURFACE_LIFETIME_SUMMARY " + json.dumps(result, sort_keys=True))
    return result
