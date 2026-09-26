"""Regression fixtures for the catalog-only phone fallback plist edit.

The production editor performs the same bounded binary-plist object-graph
operation in CNDIconDeclarationRedirect.m.  Keeping a small stdlib-only
fixture here makes the important fit guarantees testable without a device:

* the phone CFBundleIconName entry is replaced in-place;
* an existing CFBundleIconFiles key object can be reused;
* the iPad declaration remains semantically unchanged; and
* a vnode smaller than the captured original is rejected before mutation.
"""

from __future__ import annotations

import plistlib
import unittest


def _fixture() -> dict:
    return {
        "CFBundleIdentifier": "com.example.catalog-only",
        "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1",
        "CFBundleIcons": {
            "CFBundlePrimaryIcon": {
                "CFBundleIconName": "AppIcon60x60",
            },
        },
        "CFBundleIcons~ipad": {
            "CFBundlePrimaryIcon": {
                "CFBundleIconFiles": ["AppIcon60x60"],
            },
        },
    }


def _objects(data: bytes):
    trailer = data[-32:]
    offset_width = trailer[6]
    reference_width = trailer[7]
    object_count = int.from_bytes(trailer[8:16], "big")
    offset_table = int.from_bytes(trailer[24:32], "big")
    offsets = [
        int.from_bytes(
            data[offset_table + i * offset_width : offset_table + (i + 1) * offset_width],
            "big",
        )
        for i in range(object_count)
    ]
    ends = offsets[1:] + [offset_table]
    return offset_width, reference_width, offsets, ends


def _object(data: bytes, reference: int, offsets, ends, reference_width):
    offset = offsets[reference]
    marker = data[offset]
    kind = marker >> 4
    count = marker & 0x0F
    header = 1
    if count == 0x0F:
        length_marker = data[offset + 1]
        assert length_marker >> 4 == 0x1
        width = 1 << (length_marker & 0x0F)
        count = int.from_bytes(data[offset + 2 : offset + 2 + width], "big")
        header = 2 + width
    if kind == 0x5:
        return data[offset + header : offset + header + count].decode("ascii")
    if kind == 0xA:
        return [
            int.from_bytes(
                data[offset + header + i * reference_width :
                     offset + header + (i + 1) * reference_width],
                "big",
            )
            for i in range(count)
        ]
    if kind == 0xD:
        keys = [
            int.from_bytes(
                data[offset + header + i * reference_width :
                     offset + header + (i + 1) * reference_width],
                "big",
            )
            for i in range(count)
        ]
        values_offset = offset + header + count * reference_width
        values = [
            int.from_bytes(
                data[values_offset + i * reference_width :
                     values_offset + (i + 1) * reference_width],
                "big",
            )
            for i in range(count)
        ]
        return list(zip(keys, values))
    return None


def _find_dictionary_entry(
    data: bytes, dictionary: int, key: str, offsets, ends, reference_width: int
):
    for key_ref, value_ref in _object(
        data, dictionary, offsets, ends, reference_width
    ):
        if _object(data, key_ref, offsets, ends, reference_width) == key:
            return value_ref
    raise AssertionError(key)


def _same_size_catalog_edit(data: bytes, capacity: int) -> bytes | None:
    if capacity < len(data):
        return None
    offset_width, reference_width, offsets, ends = _objects(data)
    trailer = data[-32:]
    root = int.from_bytes(trailer[16:24], "big")
    icons = _find_dictionary_entry(
        data, root, "CFBundleIcons", offsets, ends, reference_width
    )
    primary = _find_dictionary_entry(
        data, icons, "CFBundlePrimaryIcon", offsets, ends, reference_width
    )
    entries = _object(data, primary, offsets, ends, reference_width)
    name_index = next(
        i
        for i, (key_ref, _) in enumerate(entries)
        if _object(data, key_ref, offsets, ends, reference_width)
        == "CFBundleIconName"
    )
    old_key, old_value = entries[name_index]
    files_key = next(
        reference
        for reference in range(len(offsets))
        if _object(data, reference, offsets, ends, reference_width)
        == "CFBundleIconFiles"
    )

    primary_offset = offsets[primary]
    header = 1
    references_offset = primary_offset + header
    values_offset = references_offset + len(entries) * reference_width
    result = bytearray(data)
    result[
        references_offset + name_index * reference_width :
        references_offset + (name_index + 1) * reference_width
    ] = files_key.to_bytes(reference_width, "big")
    result[
        values_offset + name_index * reference_width :
        values_offset + (name_index + 1) * reference_width
    ] = old_key.to_bytes(reference_width, "big")

    old_key_offset = offsets[old_key]
    old_key_span = ends[old_key] - old_key_offset
    if old_key_span < 1 + reference_width:
        return None
    result[old_key_offset : old_key_offset + old_key_span] = b"\0" * old_key_span
    result[old_key_offset] = 0xA1
    result[old_key_offset + 1 : old_key_offset + 1 + reference_width] = (
        old_value.to_bytes(reference_width, "big")
    )
    return bytes(result)


class CatalogOnlyPlistTests(unittest.TestCase):
    def test_catalog_only_reuses_key_without_touching_ipad(self):
        original = _fixture()
        data = plistlib.dumps(original, fmt=plistlib.FMT_BINARY, sort_keys=False)
        replacement = dict(original)
        replacement["CFBundleIcons"] = {
            "CFBundlePrimaryIcon": {
                "CFBundleIconFiles": ["AppIcon60x60"],
            }
        }

        staged = _same_size_catalog_edit(data, len(data))

        self.assertIsNotNone(staged)
        self.assertEqual(len(staged), len(data))
        self.assertEqual(plistlib.loads(staged), replacement)
        self.assertEqual(
            plistlib.loads(staged)["CFBundleIcons~ipad"],
            original["CFBundleIcons~ipad"],
        )

    def test_fit_boundary_rejects_shorter_vnode(self):
        original = _fixture()
        data = plistlib.dumps(original, fmt=plistlib.FMT_BINARY, sort_keys=False)
        self.assertIsNone(_same_size_catalog_edit(data, len(data) - 1))


if __name__ == "__main__":
    unittest.main()
