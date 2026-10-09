import Foundation

// VM discovery only. Standard Swift reflection describes named stored fields;
// it neither guesses offsets nor calls private Swift entry points. References
// are retained only by the returned dictionary, which the ObjC caller releases
// after its bounded snapshot. Value/enum children are described to depth five.
private func fields(_ value: Any, path: String, depth: Int, budget: inout Int,
                    machineKey: String? = nil) -> [[String: Any]] {
    guard depth <= 5, budget > 0 else { return [] }
    let mirror = Mirror(reflecting: value)
    var result: [[String: Any]] = []
    for child in mirror.children.prefix(96) {
        guard budget > 0 else { break }
        budget -= 1
        var entryKey = machineKey
        if mirror.displayStyle == .dictionary {
            let tuple = Mirror(reflecting: child.value)
            if let key = tuple.children.first?.value as? String { entryKey = key }
        }
        let name = mirror.displayStyle == .dictionary && entryKey != nil ? "[key=\(entryKey!)]" : (child.label ?? "<unnamed>")
        let lower = name.lowercased()
        if lower.contains("accessibility") || lower.contains("displayname") ||
            lower.contains("title") || lower.contains("label") || lower.contains("delegate") ||
            lower.contains("styling") || lower.contains("observer") || lower.contains("theme") ||
            ["style", "frame", "bounds", "size", "contentMetrics", "cornerRadius", "backgroundView"].contains(name) {
            continue
        }
        let next = path.isEmpty ? name : path + "." + name
        if String(reflecting: type(of: child.value)).hasPrefix("CoreGraphics.") { continue }
        let childMirror = Mirror(reflecting: child.value)
        var row: [String: Any] = ["name": name, "path": next,
            "swiftType": String(reflecting: type(of: child.value)),
            "displayStyle": childMirror.displayStyle.map { String(describing: $0) } ?? "scalar",
            "offsetAssumption": false]
        if let entryKey { row["machineKey"] = entryKey }
        if let string = child.value as? String { row["value"] = string }
        else if let url = child.value as? URL { row["value"] = url.absoluteString }
        else if let uuid = child.value as? UUID { row["value"] = uuid.uuidString }
        else if let bool = child.value as? Bool { row["value"] = bool }
        else if let number = child.value as? Int { row["value"] = number }
        else if let number = child.value as? UInt { row["value"] = number }
        else if childMirror.displayStyle == .class {
            // Native Swift objects are reflected here, never passed to the
            // Objective-C runtime walker unless they inherit NSObject.
            if let object = child.value as? NSObject { row["object"] = object }
            else if depth < 5 { row["children"] = fields(child.value, path: next, depth: depth + 1, budget: &budget, machineKey: entryKey) }
        } else if childMirror.displayStyle == .optional {
            if let wrapped = childMirror.children.first {
                if let object = wrapped.value as? NSObject, Mirror(reflecting: wrapped.value).displayStyle == .class {
                    row["object"] = object
                } else if depth < 5 { row["children"] = fields(child.value, path: next, depth: depth + 1, budget: &budget, machineKey: entryKey) }
            } else { row["value"] = "nil" }
        } else if childMirror.displayStyle == .enum {
            // Enum case names are machine state, not UI text.
            row["enumCase"] = String(describing: child.value)
            row["children"] = fields(child.value, path: next, depth: depth + 1, budget: &budget, machineKey: entryKey)
        } else if depth < 5 {
            row["children"] = fields(child.value, path: next, depth: depth + 1, budget: &budget, machineKey: entryKey)
        }
        result.append(row)
    }
    return result
}

@_cdecl("CNDCCOwnerSwiftReflect")
public func reflectOwner(_ pointer: UnsafeRawPointer?) -> UnsafeMutableRawPointer? {
    guard let pointer else { return nil }
    let object = Unmanaged<AnyObject>.fromOpaque(pointer).takeUnretainedValue()
    var budget = 512
    let result = ["fields": fields(object, path: "", depth: 0, budget: &budget),
                  "remainingBudget": budget] as NSDictionary
    return Unmanaged.passRetained(result).toOpaque()
}
