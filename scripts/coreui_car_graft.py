"""Preserve a native CAR and replace only existing, named CSI rendition blocks.

The donor must be authored by the same CoreUI version, with image packing
disabled. No catalog header, lookup key, tree or unrelated rendition is rebuilt.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass


class CarError(ValueError):
    pass


@dataclass(frozen=True)
class Rendition:
    block: int
    key_block: int
    name: str
    layout: int
    attributes: dict[int, int]


class Car:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 32 or data[:8] != b"BOMStore":
            raise CarError("not a BOM CAR")
        version, _, self.index_offset, index_length, vars_offset, vars_length = struct.unpack_from(
            ">6I", data, 8)
        if version != 1 or self.index_offset + index_length > len(data) or vars_offset + vars_length > len(data):
            raise CarError("invalid BOM header")
        count = struct.unpack_from(">I", data, self.index_offset)[0]
        if count < 2 or 4 + count * 8 > index_length:
            raise CarError("invalid BOM index")
        self.blocks = [struct.unpack_from(">II", data, self.index_offset + 4 + index * 8)
                       for index in range(count)]
        self.unused_blocks = {index for index, value in enumerate(self.blocks)
                              if value in ((0, 0), (0xFFFFFFFF, 0xFFFFFFFF))}
        for index, (offset, length) in enumerate(self.blocks):
            if index not in self.unused_blocks and offset + length > len(data):
                raise CarError("BOM block exceeds file")
        self.variables: dict[str, int] = {}
        count = struct.unpack_from(">I", data, vars_offset)[0]
        cursor = vars_offset + 4
        for _ in range(count):
            if cursor + 5 > vars_offset + vars_length:
                raise CarError("invalid BOM variable")
            index, length = struct.unpack_from(">IB", data, cursor)
            cursor += 5
            if cursor + length > vars_offset + vars_length:
                raise CarError("invalid BOM variable name")
            name = data[cursor:cursor + length].decode("ascii")
            self.variables[name] = index
            cursor += length
        header = self.block(self.variables["CARHEADER"])
        if header[:4] != b"RATC":
            raise CarError("unsupported CAR byte order")
        self.coreui_version, self.storage_version = struct.unpack_from("<II", header, 4)
        keyformat = self.block(self.variables["KEYFORMAT"])
        count = struct.unpack_from("<I", keyformat, 8)[0]
        if keyformat[:4] != b"tmfk" or len(keyformat) != 12 + 4 * count:
            raise CarError("unsupported key format")
        self.key_attributes = struct.unpack_from("<" + "I" * count, keyformat, 12)
        self.renditions: list[Rendition] = []
        for value, key in self.tree_entries("RENDITIONS"):
            csi = self.block(value)
            if len(csi) < 184 or csi[:4] != b"ISTC":
                raise CarError("unsupported CSI rendition")
            key_bytes = self.block(key)
            if len(key_bytes) != 2 * count:
                raise CarError("unexpected rendition lookup key")
            name = csi[40:168].split(b"\0", 1)[0].decode("utf-8")
            if name.endswith(".svg"):
                name = name[:-4]
            self.renditions.append(Rendition(value, key, name,
                struct.unpack_from("<H", csi, 36)[0],
                dict(zip(self.key_attributes, struct.unpack("<" + "H" * count, key_bytes)))))

    def block(self, index: int) -> bytes:
        if index <= 0 or index >= len(self.blocks) or index in self.unused_blocks:
            raise CarError("invalid BOM block reference")
        offset, length = self.blocks[index]
        return self.data[offset:offset + length]

    def tree_entries(self, name: str):
        tree = self.block(self.variables[name])
        if tree[:4] != b"tree":
            raise CarError("unsupported BOM tree")
        index = struct.unpack_from(">I", tree, 8)[0]
        visited: set[int] = set()
        while True:
            if index in visited:
                raise CarError("BOM tree cycle")
            visited.add(index)
            node = self.block(index)
            leaf, count = struct.unpack_from(">HH", node)
            if len(node) < 12 + count * 8:
                raise CarError("invalid BOM tree node")
            if leaf:
                break
            if not count:
                raise CarError("empty BOM branch")
            index = struct.unpack_from(">I", node, 12)[0]
        visited.clear()
        while index:
            if index in visited:
                raise CarError("BOM leaf cycle")
            visited.add(index)
            node = self.block(index)
            leaf, count, following, _ = struct.unpack_from(">HHII", node)
            if leaf != 1 or len(node) < 12 + count * 8:
                raise CarError("invalid BOM leaf")
            for position in range(count):
                yield struct.unpack_from(">II", node, 12 + position * 8)
            index = following


def graft(stock_bytes: bytes, donor_bytes: bytes, names: set[str]) -> tuple[bytes, dict]:
    stock, donor = Car(stock_bytes), Car(donor_bytes)
    if stock.coreui_version != 970 or donor.coreui_version != stock.coreui_version or \
            donor.storage_version != stock.storage_version:
        raise CarError("graft requires genuine CoreUI 970/storage-matched donor and stock")
    targets = [record for record in stock.renditions if record.name in names]
    if {record.name for record in targets} != names:
        raise CarError("target catalog does not contain every requested symbol")
    if len({record.block for record in targets}) != len(targets):
        raise CarError("shared target CSI block is unsupported")
    donor_records = [record for record in donor.renditions if record.name in names]
    replacements: dict[int, bytes] = {}
    proof_records = []
    for target in targets:
        vector = target.layout == 1017
        if target.layout not in (1017, 1003, 0):
            raise CarError(f"unsupported native target layout {target.layout}: {target.name}")
        attributes = (26, 27) if vector else (12, 26, 27, 9, 8)
        candidates = [record for record in donor_records if record.name == target.name
                      and (record.layout == 1017 if vector else record.layout == 0)
                      and all(record.attributes.get(attribute, 0) == target.attributes.get(attribute, 0)
                              for attribute in attributes)]
        if len(candidates) != 1:
            raise CarError(f"no exact standalone donor variant for {target.name}: {target.attributes}")
        source = candidates[0]
        replacement = bytearray(donor.block(source.block))
        # Keep the native rendition name; identifiers and lookup keys never move.
        replacement[40:168] = stock.block(target.block)[40:168]
        replacements[target.block] = bytes(replacement)
        proof_records.append({"name": target.name, "block": target.block,
            "nativeLayout": target.layout, "payloadLayout": source.layout,
            "attributes": target.attributes, "originalLength": len(stock.block(target.block)),
            "payloadLength": len(replacement), "donorBlock": source.block})
    # All freed slots belong exclusively to replaced target values. Allocate
    # largest first and never consume unrelated blocks or file metadata.
    spaces = sorted((stock.blocks[index][0], stock.blocks[index][1]) for index in replacements)
    output = bytearray(stock_bytes)
    for offset, length in spaces:
        output[offset:offset + length] = bytes(length)
    needs_repacking = False
    for index, replacement in sorted(replacements.items(), key=lambda pair: (-len(pair[1]), pair[0])):
        candidates = [(length, offset, position) for position, (offset, length) in enumerate(spaces)
                      if length >= len(replacement)]
        if not candidates:
            needs_repacking = True
            break
        _, offset, position = min(candidates)
        old_offset, old_length = spaces.pop(position)
        output[offset:offset + len(replacement)] = replacement
        remainder = old_length - len(replacement)
        if remainder:
            spaces.append((old_offset + len(replacement), remainder))
        struct.pack_into(">II", output, stock.index_offset + 4 + index * 8, offset, len(replacement))
    if needs_repacking:
        # A direct cache bitmap may outgrow its former InternalLink slot.
        # Repack block contents, preserving all block IDs and every tree/key.
        # Named-variable and index tables remain at their original offsets.
        metadata_offset = min(stock.index_offset, struct.unpack_from(">I", stock_bytes, 24)[0])
        if any(offset + length > metadata_offset for index, (offset, length) in enumerate(stock.blocks)
               if index not in stock.unused_blocks):
            raise CarError("unsupported interleaved BOM metadata")
        output = bytearray(stock_bytes)
        output[512:metadata_offset] = bytes(metadata_offset - 512)
        cursor = 512
        for index in range(1, len(stock.blocks)):
            if index in stock.unused_blocks:
                continue
            value = replacements.get(index, stock.block(index))
            if cursor + len(value) > metadata_offset:
                raise CarError("native vnode cannot hold complete donor renditions")
            output[cursor:cursor + len(value)] = value
            struct.pack_into(">II", output, stock.index_offset + 4 + index * 8, cursor, len(value))
            cursor = (cursor + len(value) + 3) & ~3
    result = bytes(output)
    patched = Car(result)
    unchanged = hashlib.sha256()
    count = 0
    for index in range(1, len(stock.blocks)):
        if index in stock.unused_blocks:
            if stock.blocks[index] != patched.blocks[index]:
                raise CarError("graft changed unused BOM index entries")
            continue
        if index in replacements:
            continue
        if stock.block(index) != patched.block(index):
            raise CarError(f"graft changed unrelated block {index}")
        unchanged.update(struct.pack(">I", index))
        unchanged.update(hashlib.sha256(stock.block(index)).digest())
        count += 1
    if stock.variables != patched.variables or stock.key_attributes != patched.key_attributes:
        raise CarError("graft changed native metadata")
    return result, {"method": "native-BOM-existing-CSI-slot-graft",
        "nativeCoreUIVersion": stock.coreui_version, "donorCoreUIVersion": donor.coreui_version,
        "nativeStorageVersion": stock.storage_version, "nativeHeaderPreserved": True,
        "lookupKeysAndTreesPreserved": True, "allUnrelatedBlocksByteIdentical": True,
        "unrelatedBlockCount": count, "unrelatedBlocksSHA256": unchanged.hexdigest(),
        "targetRenditions": proof_records, "targetRenditionCount": len(targets),
        "blockOffsetsRepacked": needs_repacking,
        "allTargetVectorAndCachedImageVariantsReplaced": True,
        "standaloneCachedImages": True, "exactNativeFileLengthPreserved": len(result) == len(stock_bytes)}


def compact_tree_padding(catalog_bytes: bytes) -> tuple[bytes, dict]:
    """Pack a generated catalog while retaining every tree entry and value.

    CoreUI allocates 4 KB tree pages even for tiny three-name module catalogs.
    Keep the declared entries, every nonzero byte, and a 512-byte alignment
    envelope around inline auxiliary data. Remove only zero-filled page tails;
    all independently indexed key/value blocks remain byte-identical.
    """
    catalog = Car(catalog_bytes)
    if catalog.coreui_version != 970 or catalog.storage_version != 17:
        raise CarError("tree compaction requires native CoreUI 970/storage 17")
    nodes: set[int] = set()
    pending = []
    for block in catalog.variables.values():
        value = catalog.block(block)
        if value[:4] == b"tree":
            pending.append(struct.unpack_from(">I", value, 8)[0])
    shortened = {}
    while pending:
        block = pending.pop()
        if not block or block in nodes:
            continue
        nodes.add(block)
        value = catalog.block(block)
        leaf, count, following, previous = struct.unpack_from(">HHII", value)
        used = 12 + count * 8
        if leaf not in (0, 1) or used > len(value):
            raise CarError("invalid generated BOM tree page")
        if leaf:
            pending.extend((following, previous))
        else:
            pending.extend(struct.unpack_from(">I", value, 12 + index * 8)[0]
                           for index in range(count))
        meaningful = max((index + 1 for index, byte in enumerate(value) if byte), default=0)
        used = min(len(value), (max(used, meaningful) + 511) & ~511)
        if any(value[used:]):
            raise CarError("nonzero tree page data cannot be discarded")
        shortened[block] = value[:used]
    output = bytearray(catalog_bytes[:512])
    offsets = list(catalog.blocks)
    cursor = len(output)
    for block in range(1, len(catalog.blocks)):
        if block in catalog.unused_blocks:
            continue
        value = shortened.get(block, catalog.block(block))
        output.extend(value)
        offsets[block] = (cursor, len(value))
        cursor += len(value)
        padding = (-cursor) & 3
        output.extend(bytes(padding))
        cursor += padding
    _, _, _, index_length, variables_offset, variables_length = struct.unpack_from(">6I", catalog_bytes, 8)
    new_variables_offset = len(output)
    output.extend(catalog_bytes[variables_offset:variables_offset + variables_length])
    output.extend(bytes((-len(output)) & 3))
    new_index_offset = len(output)
    index = bytearray(catalog_bytes[catalog.index_offset:catalog.index_offset + index_length])
    for block, (offset, length) in enumerate(offsets):
        struct.pack_into(">II", index, 4 + block * 8, offset, length)
    output.extend(index)
    struct.pack_into(">I", output, 16, new_index_offset)
    struct.pack_into(">I", output, 24, new_variables_offset)
    result = bytes(output)
    packed = Car(result)
    if packed.variables != catalog.variables or packed.key_attributes != catalog.key_attributes:
        raise CarError("tree compaction changed catalog metadata")
    for block in range(1, len(catalog.blocks)):
        if block not in catalog.unused_blocks and packed.block(block) != shortened.get(block, catalog.block(block)):
            raise CarError("tree compaction changed a value block")
    for name in catalog.variables:
        if catalog.block(catalog.variables[name])[:4] == b"tree" and \
                list(catalog.tree_entries(name)) != list(packed.tree_entries(name)):
            raise CarError("tree compaction changed lookup entries")
    return result, {"method": "generated-BOM-declared-tree-entry-padding-compaction",
        "treePageCount": len(shortened), "allTreeEntriesPreserved": True,
        "allValueBlocksByteIdentical": True, "allNonzeroTreePageBytesPreserved": True,
        "originalLength": len(catalog_bytes), "compactedLength": len(result)}
