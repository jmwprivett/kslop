#!/usr/bin/env python3
"""Summarize named VM ownership and compare object generations by machine role."""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
from pathlib import Path


def transport_role(row: dict) -> dict | None:
    if row.get("className") != "MediaControls.TransportButton":
        return None
    fields = {item["path"]: item for item in row.get("swiftFields", [])}
    symbol = fields.get("viewModel.some.asset.symbolName", {}).get("value")
    package = fields.get("viewModel.some.asset.package.some.file", {}).get("enumCase")
    flipped = fields.get("viewModel.some.asset.package.some.isHorizontallyFlipped", {}).get("value")
    role = None
    if package == "nextPrevious" and symbol == "backward.fill" and flipped is True:
        role = "media.previous"
    elif package == "nextPrevious" and symbol == "forward.fill" and flipped is False:
        role = "media.next"
    elif package == "playPauseStop" and symbol in ("play.fill", "pause.fill", "stop.fill"):
        role = "media.playPause"
    if not role:
        return None
    return {"role": role, "symbolName": symbol, "packageEnum": package,
            "isHorizontallyFlipped": flipped, "classificationUsesPosition": False,
            "classificationUsesAccessibility": False}


def shortest_paths(report: dict, root: str, allow_discovery: bool = False) -> dict:
    outgoing = collections.defaultdict(list)
    for edge in report["edges"]:
        if edge["kind"] == "recursive-discovery" and not allow_discovery:
            continue
        if edge["kind"] == "swift-field" and edge.get("path"):
            edge = {**edge, "name": edge["path"]}
        outgoing[edge["from"]].append(edge)
    paths = {root: []}
    queue = collections.deque([root])
    while queue:
        current = queue.popleft()
        for edge in outgoing[current]:
            if edge["to"] not in paths:
                paths[edge["to"]] = paths[current] + [edge]
                queue.append(edge["to"])
    return paths


def resource_provenance(report: dict) -> dict:
    """Summarize observed stock calls without treating metadata as execution.

    Parent sequence numbers connect synchronous factory calls. Resource result
    addresses join only to named snapshot consumers; a failed join is retained
    as an explicit limitation instead of inferred from glyph appearance.
    """
    trace = report.get("resourceProvenanceTrace", {})
    events = sorted(trace.get("events", []), key=lambda event: event["sequence"])
    by_sequence = {event["sequence"]: event for event in events}
    rows = {row["address"]: row for row in report.get("objects", [])}
    outgoing = collections.defaultdict(list)
    for edge in report.get("edges", []):
        if edge["kind"] != "recursive-discovery": outgoing[edge["from"]].append(edge)
    consumers = collections.defaultdict(list)
    for row in rows.values():
        role = transport_role(row)
        if role:
            for edge in outgoing[row["address"]]:
                if edge["name"] == "packageView" and edge["kind"] == "verified-swift-object-ivar":
                    consumer = {"role": role["role"], "button": row["address"], "packageView": edge["to"]}
                    consumers[edge["to"]].append(consumer)
                    for field in rows.get(edge["to"], {}).get("swiftFields", []):
                        if field.get("name") == "packageLayer" and field.get("namedSlotVerified"):
                            consumers[field["objectAddress"]].append(consumer)
        if row["className"] == "FCUIActivityControl":
            activity = row.get("identities", {}).get("activityIdentifier")
            for edge in outgoing[row["address"]]:
                if edge["name"] == "_activityIconPackageView":
                    consumer = {"activityIdentifier": activity, "row": row["address"], "packageView": edge["to"]}
                    consumers[edge["to"]].append(consumer)
                    for layer in outgoing[edge["to"]]:
                        if layer["name"] == "_rootLayer": consumers[layer["to"]].append(consumer)

    def lineage(event):
        chain, seen = [], set()
        while event and event["sequence"] not in seen:
            seen.add(event["sequence"]); chain.append(event)
            event = by_sequence.get(event.get("parentSequence"))
        return chain

    result = {"active": trace.get("active", False), "observationConfigured": bool(trace.get("methodContracts")),
              "observedEventCount": len(events),
              "droppedEvents": trace.get("droppedEvents", 0), "factoryCalls": [],
              "packageLoads": [], "symbolCalls": [], "cacheCalls": [], "boundaryConsultations": [],
              "metadataIsNotCallEvidence": True, "classificationUsesLabelsOrGeometry": False}
    boundaries = collections.defaultdict(lambda: collections.Counter())
    for event in events:
        selector, receiver = event["selector"], event.get("receiver", {})
        cls = receiver.get("className", "")
        chain = lineage(event)
        activity = next((item.get("receiverAfter", {}).get("activityIdentifier") or
                         item.get("receiver", {}).get("activityIdentifier") or
                         next((value.get("activityIdentifier") for value in item.get("arguments", [])
                               if value.get("activityIdentifier")), None)
                         for item in chain if item.get("receiverAfter", {}).get("activityIdentifier") or
                         item.get("receiver", {}).get("activityIdentifier") or
                         any(value.get("activityIdentifier") for value in item.get("arguments", []))), None)
        base = {"sequence": event["sequence"], "parentSequence": event.get("parentSequence", 0),
                "phase": event.get("phase"), "className": cls, "selector": selector,
                "activityIdentifier": activity, "arguments": event.get("arguments", []),
                "result": event.get("result"),
                "stockCallForwardedUnchanged": event.get("stockArgumentsUnchanged") is True and
                                               event.get("stockReturnUnchanged") is True}
        if cls in ("MRUAssetsProvider", "FCUICAPackageView", "CCUICAPackageDescription") and event.get("classMethod"):
            base["namedConsumerMatches"] = consumers.get((event.get("result") or {}).get("address"), [])
            result["factoryCalls"].append(base)
            boundaries[(cls, selector)][event.get("phase", "unlabelled")] += 1
        if cls == "CAPackage" and selector == "packageWithContentsOfURL:type:options:error:":
            loaded = event.get("result") or {}
            layer = loaded.get("rootLayer", {}).get("address")
            result["packageLoads"].append({**base,
                "url": (event.get("arguments") or [{}])[0].get("value"),
                "rootLayer": layer, "namedConsumerMatches": consumers.get(layer, []),
                "factoryLineage": [{"sequence": item["sequence"], "className": item.get("receiver", {}).get("className"),
                                    "selector": item["selector"]} for item in chain[1:]]})
        if cls == "UIImage" and selector.startswith("systemImageNamed:"):
            result["symbolCalls"].append(base)
        if selector in ("objectForKey:", "setObject:forKey:"):
            result["cacheCalls"].append({**base, "cacheAddress": receiver.get("address"),
                "factoryLineage": [{"sequence": item["sequence"], "className": item.get("receiver", {}).get("className"),
                                    "selector": item["selector"]} for item in chain[1:]]})
    for (cls, selector), phases in sorted(boundaries.items()):
        result["boundaryConsultations"].append({"className": cls, "selector": selector,
            "callsByPhase": dict(phases), "consultedInMultiplePhases": len(phases) > 1,
            "newReceiverGenerationStillRequiresSnapshotComparison": True})
    result["captureComplete"] = result["observationConfigured"] and not result["droppedEvents"] and not report.get("truncated", False)
    return result


def summarize(report: dict) -> dict:
    rows = {row["address"]: row for row in report["objects"]}
    outgoing = collections.defaultdict(list)
    for edge in report["edges"]:
        outgoing[edge["from"]].append(edge)
    managers = [row for row in rows.values() if row["className"] == "CCUIModuleInstanceManager"]
    paths = shortest_paths(report, managers[0]["address"]) if len(managers) == 1 else {}
    result = {"phase": report["phase"], "pid": report["pid"], "truncated": report["truncated"],
              "mode": report["mode"], "objectCount": len(rows), "edgeCount": len(report["edges"]),
              "modules": [], "transport": [], "focusRows": [], "hostedControls": [], "packages": [],
              "anchors": {}, "verifiedSwiftSlots": [], "glyphTargets": []}
    anchors = ("SpringBoard", "SBControlCenterController", "CCUIMainViewController", "CCUIPagingViewController",
               "CCUIModuleInstanceManager", "CCUIModuleSettingsManager", "CCSModuleRepository",
               "FCActivityManager", "FCUIActivityPickerViewController", "CCUIDisplayModuleViewController",
               "MRUVolumeViewController", "CHSControlHost", "CCUIControlDescriptorProvider")
    for row in rows.values():
        cls, address = row["className"], row["address"]
        if cls in anchors:
            result["anchors"].setdefault(cls, []).append(address)
        if cls == "CCUIModuleInstance":
            metadata = [edge for edge in outgoing[address] if edge["name"] in ("_metadata", "metadata")]
            module_id = None
            for edge in metadata:
                identities = rows.get(edge["to"], {}).get("identities", {})
                module_id = identities.get("moduleIdentifier") or identities.get("_moduleIdentifier")
            result["modules"].append({"address": address, "moduleIdentifier": module_id,
                "uniqueIdentifier": row["identities"].get("uniqueIdentifier"),
                "routeFromManager": paths.get(address)})
            chain = {
                "com.apple.control-center.DisplayModule": ("brightness", ["_module", "_moduleViewController", "_sliderView", "_glyphPackageView"]),
                "com.apple.mediaremote.controlcenter.audio": ("volume", ["_module", "_volumeViewController", "viewIfLoaded", "_primarySlider", "_glyphPackageView"]),
                "com.apple.mobiletimer.controlcenter.timer": ("timer", ["_module", "_timerViewController", "_buttonModuleView", "_glyphPackageView"]),
                "com.apple.replaykit.controlcenter.screencapture": ("screenRecording", ["_module", "_currentContentViewController", "_buttonModuleView", "_glyphPackageView"]),
            }.get(module_id)
            if chain:
                role_name, names = chain
                cursor, chain_edges = address, []
                for name in names:
                    matches = [edge for edge in outgoing[cursor] if edge["name"] == name]
                    if not matches: break
                    chosen = matches[0]; chain_edges.append(chosen); cursor = chosen["to"]
                if len(chain_edges) == len(names):
                    descriptions = [edge for edge in outgoing[cursor] if edge["name"] in ("_packageDescription", "packageDescription")]
                    urls = [rows.get(edge["to"], {}).get("identities", {}).get("packageURL") for edge in descriptions]
                    result["glyphTargets"].append({"role": role_name, "address": cursor,
                        "moduleIdentifier": module_id, "moduleInstance": address,
                        "packageURLs": sorted({url for url in urls if url}),
                        "routeFromModuleInstance": chain_edges})
        role = transport_role(row)
        if role:
            role.update({"address": address, "routeFromManager": paths.get(address),
                         "packageTargets": [edge["to"] for edge in outgoing[address]
                             if edge["name"] == "packageView" and edge["kind"] == "verified-swift-object-ivar"]})
            result["transport"].append(role)
        if cls == "FCUIActivityControl":
            result["focusRows"].append({"address": address, **row.get("identities", {}),
                "routeFromManager": paths.get(address),
                "packageTargets": [edge["to"] for edge in outgoing[address] if edge["name"] == "_activityIconPackageView"]})
        if cls == "CCUIControlHostViewController":
            identities = [edge for edge in outgoing[address] if edge["name"] == "identity"]
            kinds = [rows.get(edge["to"], {}).get("identities", {}).get("_kind") for edge in identities]
            result["hostedControls"].append({"address": address, "machineKinds": kinds,
                "routeFromManager": paths.get(address)})
        if cls in ("CCUICAPackageDescription", "MediaControls.PackageView", "FCUICAPackageView", "CCUICAPackageView"):
            result["packages"].append({"address": address, "className": cls,
                "identities": row.get("identities", {}),
                "swiftMachineFields": [field for field in row.get("swiftFields", [])
                    if "enumCase" in field or "url" in field["path"].lower()],
                "routeFromManager": paths.get(address)})
        for field in row.get("swiftFields", []):
            if field.get("namedSlotVerified"):
                result["verifiedSwiftSlots"].append({"ownerClass": cls, "owner": address,
                    "name": field["name"], "targetClass": field["objectClass"],
                    "target": field["objectAddress"], "runtimeOffset": field["runtimeOffset"]})
    process_roots = [row["address"] for row in rows.values() if row["className"] == "SpringBoard"]
    if len(process_roots) == 1:
        process_paths = shortest_paths(report, process_roots[0])
        result["processRoutes"] = {name: [process_paths.get(address) for address in addresses]
                                   for name, addresses in result["anchors"].items()}
    result["providerGetters"] = report.get("staticProviderGetters", [])
    result["resourceProvenance"] = resource_provenance(report)
    result["optionalClasses"] = [{"className": row["className"], "loaded": row["loaded"]}
                                 for row in report.get("optionalClassInventory", [])]
    return result


def compare(before: dict, after: dict) -> dict:
    if before["pid"] != after["pid"]:
        raise ValueError("lifecycle comparison requires the same SpringBoard PID")
    result = {"pid": before["pid"], "before": before["phase"], "after": after["phase"],
              "capturesComplete": not (before["truncated"] or after["truncated"]), "anchors": {}, "roles": {}}
    for name in before["anchors"].keys() | after["anchors"].keys():
        a, b = set(before["anchors"].get(name, [])), set(after["anchors"].get(name, []))
        result["anchors"][name] = {"persisted": sorted(a & b), "departed": sorted(a - b), "created": sorted(b - a)}
    for category, key in (("transport", "role"), ("focusRows", "activityIdentifier"), ("glyphTargets", "role")):
        first, second = collections.defaultdict(set), collections.defaultdict(set)
        for row in before.get(category, []): first[row.get(key)].add(row["address"])
        for row in after.get(category, []): second[row.get(key)].add(row["address"])
        for role in first.keys() | second.keys():
            a, b = first[role], second[role]
            result["roles"][role] = {"persisted": sorted(a & b), "departed": sorted(a - b), "created": sorted(b - a)}
    earlier = before.get("resourceProvenance", {})
    later = after.get("resourceProvenance", {})
    prior_sequences = {row["sequence"] for row in earlier.get("factoryCalls", [])}
    consulted = [row for row in later.get("factoryCalls", []) if row["sequence"] not in prior_sequences]
    result["resourceFactoryCallsDuringInterval"] = consulted
    result["newFocusRowsWithFactoryReturnMatch"] = []
    for call in consulted:
        for consumer in call.get("namedConsumerMatches", []):
            identity = consumer.get("activityIdentifier")
            if consumer.get("row") in result["roles"].get(identity, {}).get("created", []):
                result["newFocusRowsWithFactoryReturnMatch"].append({"sequence": call["sequence"],
                    "className": call["className"], "selector": call["selector"], **consumer})
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--compare", nargs=2, action="append", default=[])
    args = parser.parse_args()
    summaries = {}
    for path in sorted(args.directory.glob("*.json")):
        if path.name.startswith(("driver-", "ownership-summary", "lifecycle-comparisons")): continue
        report = json.loads(path.read_text())
        if "objects" in report and "phase" in report: summaries[report["phase"]] = summarize(report)
    destination = args.directory / "ownership-summary.json"
    destination.write_text(json.dumps(summaries, indent=2) + "\n")
    comparisons = [compare(summaries[first], summaries[second]) for first, second in args.compare]
    (args.directory / "lifecycle-comparisons.json").write_text(json.dumps(comparisons, indent=2) + "\n")
    sources = [Path(__file__), Path(__file__).with_name("cnd_cc_lifecycle_owners.py"),
               Path(__file__).with_name("cnd_cc_lifecycle_owners.m"),
               Path(__file__).with_name("cnd_cc_resource_provenance.inc"),
               Path(__file__).with_name("cnd_cc_owner_swift_reflection.swift")]
    manifest = {"currentSources": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                                   for path in sources],
                "snapshots": [{"path": path.name, "bytes": path.stat().st_size,
                               "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                              for path in sorted(args.directory.glob("*.json"))
                              if path.stem in summaries],
                "note": "Historical snapshots include earlier probe revisions; current source hashes do not attest their build variant."}
    (args.directory / "artifact-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(destination)
    for item in comparisons: print(json.dumps(item, indent=2))


if __name__ == "__main__": main()
