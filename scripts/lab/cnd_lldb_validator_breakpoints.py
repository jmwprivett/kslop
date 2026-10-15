"""LLDB breakpoint callbacks for the bounded validator/resume VM canary."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import lldb


_CONFIG: dict[str, Any] = {}
_IGNORED = {"pre-validator": 0, "validator": 0, "after-check": 0}
_BREAKPOINTS: dict[str, lldb.SBBreakpoint] = {}


def _register(frame: lldb.SBFrame, name: str) -> int | None:
    value = frame.FindRegister(name)
    if not value.IsValid():
        return None
    return value.GetValueAsUnsigned()


def _capture(frame: lldb.SBFrame, stage: str) -> bool:
    marker_x16 = _CONFIG["marker_x16"]
    marker_x17 = _CONFIG["marker_x17"]
    x4 = _register(frame, "x4")
    x5 = _register(frame, "x5")
    saved_state = _register(frame, "x0")
    if x4 != marker_x16 or x5 != marker_x17 or \
            saved_state != _CONFIG["saved_state"]:
        _IGNORED[stage] += 1
        return False

    process = frame.GetThread().GetProcess()
    jop_hash = None
    memory_error = None
    if saved_state is not None:
        error = lldb.SBError()
        jop_hash = process.ReadUnsignedFromMemory(
            saved_state + 0x128, 8, error)
        if not error.Success():
            memory_error = error.GetCString() or "unknown read error"
            jop_hash = None

    daif = _register(frame, "daif")
    spsel = _register(frame, "spsel")
    current_pstate = _register(frame, "cpsr")
    irq_masked = bool(
        (daif is not None and daif & 0x80) or
        (current_pstate is not None and current_pstate & 0x80)
    )
    effective_spsel = spsel if spsel is not None else (
        current_pstate & 1 if current_pstate is not None else None)
    event = {
        "schema": "com.zeroxjf.cyanide.lldb-validator-breakpoint",
        "schemaVersion": 1,
        "stage": stage,
        "pc": f"{frame.GetPC():#018x}",
        "savedState": f"{saved_state:#018x}"
            if saved_state is not None else None,
        "statePC": f"{_register(frame, 'x1'):#018x}"
            if _register(frame, "x1") is not None else None,
        "stateCPSR": f"{(_register(frame, 'x2') or 0) & 0xffffffff:#010x}",
        "stateLR": f"{_register(frame, 'x3'):#018x}"
            if _register(frame, "x3") is not None else None,
        "stateX16": f"{x4:#018x}",
        "stateX17": f"{x5:#018x}",
        "jopHash": f"{jop_hash:#018x}" if jop_hash is not None else None,
        "jopHashReadError": memory_error,
        "daif": f"{daif:#018x}" if daif is not None else None,
        "currentPSTATE": f"{current_pstate:#010x}"
            if current_pstate is not None else None,
        "irqMasked": irq_masked,
        "spsel": effective_spsel,
        "ignoredBreakpointHitsBeforeMatch": _IGNORED[stage],
    }
    with Path(_CONFIG["event_path"]).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")
        stream.flush()
    return True


def install(debugger: lldb.SBDebugger, pre_validator: int, validator: int,
            after_check: int, marker_x16: int, marker_x17: int,
            saved_state: int, event_path: str) -> None:
    global _CONFIG, _BREAKPOINTS
    _CONFIG = {
        "marker_x16": marker_x16,
        "marker_x17": marker_x17,
        "saved_state": saved_state,
        "event_path": event_path,
        "pre-validator": pre_validator,
        "validator": validator,
        "after-check": after_check,
    }
    Path(event_path).unlink(missing_ok=True)
    target = debugger.GetSelectedTarget()
    pre_breakpoint = target.BreakpointCreateByAddress(pre_validator)
    validator_breakpoint = target.BreakpointCreateByAddress(validator)
    after_breakpoint = target.BreakpointCreateByAddress(after_check)
    _BREAKPOINTS = {
        "pre-validator": pre_breakpoint,
        "validator": validator_breakpoint,
        "after-check": after_breakpoint,
    }
    if pre_breakpoint.GetNumLocations() != 1 or \
            validator_breakpoint.GetNumLocations() != 1 or \
            after_breakpoint.GetNumLocations() != 1:
        raise RuntimeError("validator breakpoint did not resolve exactly")
    validator_breakpoint.SetEnabled(False)
    after_breakpoint.SetEnabled(False)
    print(
        "CND_LLDB_ARMED "
        f"saved_state={saved_state:#x} pre={pre_validator:#x} "
        f"validator={validator:#x} after={after_check:#x}",
        flush=True,
    )


def _continue_until_marked(debugger: lldb.SBDebugger, stage: str,
                           maximum_stops: int = 16) -> None:
    """Continue past bounded unrelated hits until the exact tuple stops."""
    if stage not in _BREAKPOINTS or maximum_stops <= 0:
        raise RuntimeError(f"invalid validator capture request: {stage}")
    process = debugger.GetSelectedTarget().GetProcess()
    observed = []
    for _ in range(maximum_stops):
        error = process.Continue()
        if error.Fail():
            raise RuntimeError(
                f"could not continue to {stage}: {error.GetCString()}")
        candidates = []
        for thread_index in range(process.GetNumThreads()):
            thread = process.GetThreadAtIndex(thread_index)
            frame = thread.GetFrameAtIndex(0)
            if frame.IsValid() and frame.GetPC() == _CONFIG[stage]:
                candidates.append(frame)
        matches = [frame for frame in candidates
                   if _register(frame, "x4") == _CONFIG["marker_x16"] and
                   _register(frame, "x5") == _CONFIG["marker_x17"] and
                   _register(frame, "x0") == _CONFIG["saved_state"]]
        if len(matches) == 1:
            if not _capture(matches[0], stage):
                raise RuntimeError(f"could not record marked {stage} stop")
            _BREAKPOINTS[stage].SetEnabled(False)
            return
        _IGNORED[stage] += len(candidates)
        observed = [
            (_register(frame, "x4"), _register(frame, "x5"))
            for frame in candidates
        ]
    raise RuntimeError(
        f"no marked {stage} stop after {maximum_stops} stops; "
        f"last registers={observed}")


def capture_targeted(debugger: lldb.SBDebugger) -> None:
    """Follow the exact converter call into and back from the validator."""
    _continue_until_marked(debugger, "pre-validator")
    _BREAKPOINTS["validator"].SetEnabled(True)
    _continue_until_marked(debugger, "validator")
    _BREAKPOINTS["after-check"].SetEnabled(True)
    _continue_until_marked(debugger, "after-check")
