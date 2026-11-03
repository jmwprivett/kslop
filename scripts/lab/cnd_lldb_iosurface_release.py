"""LLDB callbacks for the bounded IOSurface allocator-release witness.

The observer uses hardware breakpoints at four exact-build instructions:

* the ``IOSurfaceRootUserClient`` deleting-destructor tail call into the typed
  allocator release routine;
* the first instruction after that routine's underlying free call returns;
* the return from this class's exact typed-allocation wrapper, used to
  invalidate a release record if the same address is legitimately reused;
* the notification-delivery load of ``client+0xd8``.

Callbacks only read registers and, at delivery, one eight-byte object field.
They never modify registers or kernel memory.
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any

import lldb


_CONFIG: dict[str, Any] = {}
_PENDING: dict[int, dict[str, Any]] = {}
_RELEASED: dict[int, dict[str, Any]] = {}
_MATCH: dict[str, Any] | None = None
_BREAKPOINTS: list[lldb.SBBreakpoint] = []
_COMPLETION_BREAKPOINT: lldb.SBBreakpoint | None = None
_DELIVERY_BREAKPOINT: lldb.SBBreakpoint | None = None
_COUNTS = {
    "handoff": 0,
    "completion": 0,
    "allocation": 0,
    "reallocated": 0,
    "delivery": 0,
    "invalid": 0,
}


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


def _thread_id(frame: lldb.SBFrame) -> int:
    return frame.GetThread().GetThreadID()


def _record(event: dict[str, Any]) -> None:
    with Path(_CONFIG["event_path"]).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")
        stream.flush()


def _event(frame: lldb.SBFrame, stage: str) -> dict[str, Any]:
    process = frame.GetThread().GetProcess()
    return {
        "schema": "com.zeroxjf.cyanide.iosurface-allocator-release-witness",
        "schemaVersion": 1,
        "stage": stage,
        "pc": _hex(frame.GetPC()),
        "threadID": _thread_id(frame),
        "stopID": process.GetStopID(),
    }


def _refresh_delivery_breakpoint() -> None:
    """Arm delivery only for addresses with an unreallocated release."""
    if _DELIVERY_BREAKPOINT is None:
        return
    if not _RELEASED:
        _DELIVERY_BREAKPOINT.SetEnabled(False)
        _DELIVERY_BREAKPOINT.SetCondition("")
        return
    condition = " || ".join(f"$x0 == {client:#x}" for client in _RELEASED)
    _DELIVERY_BREAKPOINT.SetCondition(condition)
    _DELIVERY_BREAKPOINT.SetEnabled(True)


def on_handoff(frame: lldb.SBFrame, _bp_loc: lldb.SBBreakpointLocation,
               _internal_dict: dict[str, Any]) -> bool:
    """Record the exact typed-free arguments for completion correlation."""
    event = _event(frame, "allocator-handoff")
    descriptor = _register(frame, "x0")
    client = _register(frame, "x1")
    size = _register(frame, "x2")
    valid = (
        descriptor == _CONFIG["descriptor_address"]
        and client is not None
        and client != 0
        and size == _CONFIG["object_size"]
    )
    event.update({
        "descriptor": _hex(descriptor),
        "client": _hex(client),
        "size": size,
        "validatedTypedRelease": valid,
    })
    _COUNTS["handoff"] += 1
    if not valid:
        _COUNTS["invalid"] += 1
        _record(event)
        return False

    thread_id = event["threadID"]
    if thread_id in _PENDING:
        event["pendingCollision"] = True
        _COUNTS["invalid"] += 1
    _PENDING[thread_id] = event
    _record(event)
    return False


def on_completion(frame: lldb.SBFrame, _bp_loc: lldb.SBBreakpointLocation,
                  _internal_dict: dict[str, Any]) -> bool:
    """Record return from the allocator's underlying release call."""
    thread_id = _thread_id(frame)
    pending = _PENDING.pop(thread_id, None)
    if pending is None:
        return False

    event = _event(frame, "allocator-release-complete")
    client_text = pending["client"]
    client = int(client_text, 16)
    event.update({
        "descriptor": pending["descriptor"],
        "client": client_text,
        "size": pending["size"],
        "handoffPC": pending["pc"],
        "handoffStopID": pending["stopID"],
        "validatedTypedRelease": True,
    })
    _RELEASED[client] = event
    _refresh_delivery_breakpoint()
    _COUNTS["completion"] += 1
    _record(event)
    return False


def on_allocation(frame: lldb.SBFrame, _bp_loc: lldb.SBBreakpointLocation,
                  _internal_dict: dict[str, Any]) -> bool:
    """Invalidate a release record when this class reuses its address."""
    event = _event(frame, "allocation-return")
    client = _register(frame, "x0")
    prior_release = _RELEASED.pop(client, None) if client is not None else None
    event.update({
        "client": _hex(client),
        "invalidatedRelease": prior_release is not None,
        "invalidatedReleaseStopID": (
            prior_release["stopID"] if prior_release is not None else None
        ),
    })
    _COUNTS["allocation"] += 1
    if prior_release is not None:
        _COUNTS["reallocated"] += 1
        _refresh_delivery_breakpoint()
    _record(event)
    return False


def on_delivery(frame: lldb.SBFrame, _bp_loc: lldb.SBBreakpointLocation,
                _internal_dict: dict[str, Any]) -> bool:
    """Stop when delivery consumes a client whose typed release completed."""
    global _MATCH
    event = _event(frame, "delivery-before-lock-load")
    client = _register(frame, "x0")
    lock = None
    read_error = "x0 unavailable"
    if client is not None:
        lock, read_error = _read_u64(frame.GetThread().GetProcess(), client + 0xD8)
    release = _RELEASED.get(client) if client is not None else None
    matched = release is not None
    strictly_later = matched and event["stopID"] > release["stopID"]
    event.update({
        "client": _hex(client),
        "lockAtD8": _hex(lock),
        "memoryReadError": read_error,
        "matchedCompletedRelease": matched,
        "releasePC": release["pc"] if release is not None else None,
        "releaseThreadID": release["threadID"] if release is not None else None,
        "releaseStopID": release["stopID"] if release is not None else None,
        "sameStopGeneration": (
            matched and event["stopID"] == release["stopID"]
        ),
        "allocatorReleaseMatch": strictly_later,
    })
    _COUNTS["delivery"] += 1
    _record(event)
    if strictly_later:
        _MATCH = event
        print(
            "CND_IOSURFACE_ALLOCATOR_RELEASE_MATCH "
            f"client={event['client']} lock={event['lockAtD8']} "
            f"releasePC={event['releasePC']}",
            flush=True,
        )
    return strictly_later


def _hardware_breakpoint(debugger: lldb.SBDebugger, address: int,
                         callback: str) -> lldb.SBBreakpoint:
    target = debugger.GetSelectedTarget()
    breakpoint = target.BreakpointCreateByAddress(address)
    if breakpoint.GetNumLocations() != 1:
        raise RuntimeError("IOSurface release breakpoint did not resolve exactly")
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


def install(debugger: lldb.SBDebugger, handoff_address: int,
            completion_address: int, allocation_address: int,
            delivery_address: int,
            descriptor_address: int, object_size: int, event_path: str) -> None:
    """Install four exact-build hardware breakpoints on a connected target."""
    global _CONFIG, _PENDING, _RELEASED, _MATCH, _BREAKPOINTS
    global _COMPLETION_BREAKPOINT, _DELIVERY_BREAKPOINT, _COUNTS
    if object_size <= 0 or object_size > 0x10000:
        raise RuntimeError("object size is outside the bounded observer contract")
    _CONFIG = {
        "handoff_address": handoff_address,
        "completion_address": completion_address,
        "delivery_address": delivery_address,
        "descriptor_address": descriptor_address,
        "object_size": object_size,
        "event_path": event_path,
    }
    _PENDING = {}
    _RELEASED = {}
    _MATCH = None
    _COUNTS = {
        "handoff": 0,
        "completion": 0,
        "allocation": 0,
        "reallocated": 0,
        "delivery": 0,
        "invalid": 0,
    }
    Path(event_path).unlink(missing_ok=True)

    handoff = _hardware_breakpoint(
        debugger, handoff_address, "cnd_lldb_iosurface_release.on_handoff"
    )
    completion = _hardware_breakpoint(
        debugger, completion_address, "cnd_lldb_iosurface_release.on_completion"
    )
    allocation = _hardware_breakpoint(
        debugger, allocation_address, "cnd_lldb_iosurface_release.on_allocation"
    )
    delivery = _hardware_breakpoint(
        debugger, delivery_address, "cnd_lldb_iosurface_release.on_delivery"
    )
    delivery.SetEnabled(False)
    _COMPLETION_BREAKPOINT = completion
    _DELIVERY_BREAKPOINT = delivery
    _BREAKPOINTS = [handoff, completion, allocation, delivery]
    print(
        "CND_IOSURFACE_ALLOCATOR_RELEASE_ARMED "
        f"handoff={handoff_address:#x} completion={completion_address:#x} "
        f"allocation={allocation_address:#x} "
        f"delivery={delivery_address:#x} descriptor={descriptor_address:#x} "
        f"size={object_size:#x}",
        flush=True,
    )


def capture_for(debugger: lldb.SBDebugger, seconds: float) -> None:
    """Capture asynchronously for a bounded interval or until a match."""
    if seconds <= 0 or seconds > 300:
        raise RuntimeError("capture interval must be in (0, 300] seconds")
    process = debugger.GetSelectedTarget().GetProcess()
    debugger.SetAsync(True)
    error = process.Continue()
    if error.Fail():
        debugger.SetAsync(False)
        raise RuntimeError(
            "IOSurface release capture could not continue: "
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
                "IOSurface release capture could not stop: "
                + (stop_error.GetCString() or "unknown LLDB error")
            )
    debugger.SetAsync(False)


def capture_windows(debugger: lldb.SBDebugger, seconds: float,
                    windows: int) -> None:
    """Run contiguous bounded windows, stopping permanently on a match."""
    if windows <= 0 or windows > 12:
        raise RuntimeError("window count must be in [1, 12]")
    for _ in range(windows):
        if _MATCH is not None:
            break
        capture_for(debugger, seconds)


def summary() -> dict[str, Any]:
    result = {
        "counts": dict(_COUNTS),
        "pendingThreadCount": len(_PENDING),
        "releasedPointerCount": len(_RELEASED),
        "matched": _MATCH is not None,
        "match": _MATCH,
    }
    print("CND_IOSURFACE_ALLOCATOR_RELEASE_SUMMARY " + json.dumps(result, sort_keys=True))
    return result
