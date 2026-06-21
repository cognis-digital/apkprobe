"""Minimal decoder for Android binary XML (AXML).

`AndroidManifest.xml` inside an APK is not text — it is Android's compiled
binary XML format: a chunked structure with a shared string pool. This module
decodes the chunks needed to reconstruct the manifest element tree (string
pool, start/end namespace, start/end element, attributes) without any
third-party dependency.

It is deliberately scoped to what manifest analysis needs; it is not a complete
AXML/ARSC implementation. Unknown chunks are skipped by their declared size.

References: the AOSP ResourceTypes.h chunk layout.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

# Chunk types
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

# String pool flags
UTF8_FLAG = 1 << 8

# Typed value data types (subset)
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AXMLError(ValueError):
    """Raised when a buffer is not valid AXML."""


@dataclass
class Element:
    tag: str
    attributes: dict = field(default_factory=dict)   # "ns:name" or "name" -> value (str)
    children: list = field(default_factory=list)
    namespace: str = ""

    def attr(self, name: str, default=None):
        """Get an attribute by local name, preferring the android namespace."""
        if f"android:{name}" in self.attributes:
            return self.attributes[f"android:{name}"]
        if name in self.attributes:
            return self.attributes[name]
        return default

    def iter(self, tag: Optional[str] = None):
        """Depth-first iteration over self and descendants (optionally by tag)."""
        if tag is None or self.tag == tag:
            yield self
        for child in self.children:
            yield from child.iter(tag)


class _StringPool:
    def __init__(self, strings: list[str]):
        self._strings = strings

    def get(self, index: int) -> str:
        if index < 0 or index >= len(self._strings):
            return ""
        return self._strings[index]


def _read_string_pool(data: bytes, start: int) -> _StringPool:
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, start)
    if chunk_type != RES_STRING_POOL_TYPE:
        raise AXMLError("expected string pool chunk")
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", data, start + 8
    )
    is_utf8 = bool(flags & UTF8_FLAG)
    offsets_base = start + header_size
    strings_base = start + strings_start
    strings: list[str] = []
    for i in range(string_count):
        (offset,) = struct.unpack_from("<I", data, offsets_base + i * 4)
        strings.append(_decode_pool_string(data, strings_base + offset, is_utf8))
    return _StringPool(strings)


def _decode_len_utf8(data: bytes, pos: int) -> tuple[int, int]:
    b = data[pos]
    pos += 1
    if b & 0x80:
        b = ((b & 0x7F) << 8) | data[pos]
        pos += 1
    return b, pos


def _decode_len_utf16(data: bytes, pos: int) -> tuple[int, int]:
    (v,) = struct.unpack_from("<H", data, pos)
    pos += 2
    if v & 0x8000:
        (v2,) = struct.unpack_from("<H", data, pos)
        pos += 2
        v = ((v & 0x7FFF) << 16) | v2
    return v, pos


def _decode_pool_string(data: bytes, pos: int, is_utf8: bool) -> str:
    if is_utf8:
        _char_len, pos = _decode_len_utf8(data, pos)   # UTF-16 length (unused)
        byte_len, pos = _decode_len_utf8(data, pos)
        return data[pos : pos + byte_len].decode("utf-8", errors="replace")
    unit_len, pos = _decode_len_utf16(data, pos)
    return data[pos : pos + unit_len * 2].decode("utf-16-le", errors="replace")


def parse(data: bytes) -> Element:
    """Decode AXML bytes into an :class:`Element` tree; return the root element."""
    if len(data) < 8:
        raise AXMLError("buffer too small")
    file_type, header_size, _file_size = struct.unpack_from("<HHI", data, 0)
    if file_type != RES_XML_TYPE:
        raise AXMLError(f"not an AXML file (type=0x{file_type:04x})")

    pool: Optional[_StringPool] = None
    namespaces: dict[str, str] = {}   # uri-string -> prefix (we map uri to alias)
    root: Optional[Element] = None
    stack: list[Element] = []

    pos = header_size
    n = len(data)
    while pos + 8 <= n:
        c_type, c_header, c_size = struct.unpack_from("<HHI", data, pos)
        if c_size <= 0:
            break

        if c_type == RES_STRING_POOL_TYPE:
            pool = _read_string_pool(data, pos)
        elif c_type == RES_XML_RESOURCE_MAP:
            pass
        elif c_type == RES_XML_START_NAMESPACE:
            assert pool is not None
            prefix_idx, uri_idx = struct.unpack_from("<ii", data, pos + c_header)
            namespaces[pool.get(uri_idx)] = pool.get(prefix_idx)
        elif c_type == RES_XML_END_NAMESPACE:
            pass
        elif c_type == RES_XML_START_ELEMENT:
            assert pool is not None
            el = _read_start_element(data, pos, c_header, pool, namespaces)
            if stack:
                stack[-1].children.append(el)
            else:
                root = el
            stack.append(el)
        elif c_type == RES_XML_END_ELEMENT:
            if stack:
                stack.pop()
        elif c_type == RES_XML_CDATA:
            pass

        pos += c_size

    if root is None:
        raise AXMLError("no root element found")
    return root


def _read_start_element(data, pos, header_size, pool, namespaces) -> Element:
    body = pos + header_size
    ns_idx, name_idx = struct.unpack_from("<ii", data, body)
    attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, body + 8)
    tag = pool.get(name_idx)
    namespace = pool.get(ns_idx) if ns_idx >= 0 else ""
    element = Element(tag=tag, namespace=namespace)

    attrs_base = body + attr_start
    for i in range(attr_count):
        off = attrs_base + i * 20  # each attribute is 20 bytes
        a_ns, a_name, a_raw = struct.unpack_from("<iii", data, off)
        _size, _res0, data_type = struct.unpack_from("<HBB", data, off + 12)
        (a_data,) = struct.unpack_from("<i", data, off + 16)
        name = pool.get(a_name)
        prefix = namespaces.get(pool.get(a_ns)) if a_ns >= 0 else ""
        key = f"{prefix}:{name}" if prefix else name
        element.attributes[key] = _attr_value(data_type, a_raw, a_data, pool)
    return element


def _attr_value(data_type, raw_idx, data_val, pool) -> str:
    if data_type == TYPE_STRING:
        return pool.get(raw_idx if raw_idx >= 0 else data_val)
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if data_val != 0 else "false"
    if data_type in (TYPE_INT_DEC, TYPE_REFERENCE):
        return str(data_val)
    if data_type == TYPE_INT_HEX:
        return hex(data_val & 0xFFFFFFFF)
    if raw_idx >= 0:
        return pool.get(raw_idx)
    return str(data_val)
