"""A tiny AXML *encoder*, used only by tests to produce real binary manifests.

This lets the test-suite feed genuine compiled AXML to the decoder rather than
mocking it, so a round-trip (encode here -> decode in apkprobe.axml) proves the
decoder handles the actual binary layout. Production code never imports this.
"""

from __future__ import annotations

import struct

UTF8_FLAG = 1 << 8
ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Attributes that are NOT in the android: namespace in a real manifest.
NON_NS_ATTRS = {"package", "platformBuildVersionCode", "platformBuildVersionName", "coreApp"}

# value spec: ("string", s) | ("bool", True/False) | ("int", n)


class _Pool:
    def __init__(self):
        self.items: list[str] = []
        self.index: dict[str, int] = {}

    def add(self, s: str) -> int:
        if s not in self.index:
            self.index[s] = len(self.items)
            self.items.append(s)
        return self.index[s]


def _enc_utf8_string(s: str) -> bytes:
    raw = s.encode("utf-8")
    char_len = len(s)
    byte_len = len(raw)

    def enc_len(n: int) -> bytes:
        if n > 0x7F:
            return bytes([((n >> 8) & 0x7F) | 0x80, n & 0xFF])
        return bytes([n])

    return enc_len(char_len) + enc_len(byte_len) + raw + b"\x00"


def _build_string_pool(pool: _Pool) -> bytes:
    encoded = [_enc_utf8_string(s) for s in pool.items]
    offsets = []
    running = 0
    blob = b""
    for e in encoded:
        offsets.append(running)
        blob += e
        running += len(e)
    # pad string blob to 4-byte alignment
    while len(blob) % 4 != 0:
        blob += b"\x00"

    header_size = 28
    offsets_bytes = b"".join(struct.pack("<I", o) for o in offsets)
    strings_start = header_size + len(offsets_bytes)
    chunk_size = strings_start + len(blob)
    header = struct.pack(
        "<HHIIIIII",
        0x0001, header_size, chunk_size,
        len(pool.items), 0, UTF8_FLAG, strings_start, 0,
    )
    return header + offsets_bytes + blob


def _chunk(c_type: int, ext: bytes) -> bytes:
    header_size = 16
    chunk_size = header_size + len(ext)
    common = struct.pack("<HHI", c_type, header_size, chunk_size)
    line_comment = struct.pack("<ii", 1, -1)
    return common + line_comment + ext


def encode(root: dict) -> bytes:
    """Encode a manifest tree into AXML bytes.

    ``root`` shape: {"tag": str, "attrs": {name: ("type", value)}, "children": [...]}.
    Attribute names use the android: namespace.
    """
    pool = _Pool()
    android_prefix_idx = pool.add("android")
    android_uri_idx = pool.add(ANDROID_NS)

    # Pre-register all strings (tags, attr names, string values)
    def register(node):
        pool.add(node["tag"])
        for name, (vtype, val) in node.get("attrs", {}).items():
            pool.add(name)
            if vtype == "string":
                pool.add(val)
        for child in node.get("children", []):
            register(child)

    register(root)

    body = b""
    body += _chunk(0x0100, struct.pack("<ii", android_prefix_idx, android_uri_idx))  # start ns

    def emit(node):
        nonlocal body
        attrs = node.get("attrs", {})
        ext = struct.pack("<ii", -1, pool.add(node["tag"]))   # ns, name
        ext += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
        for name, (vtype, val) in attrs.items():
            a_ns = -1 if name in NON_NS_ATTRS else android_uri_idx
            a_name = pool.add(name)
            if vtype == "string":
                raw = pool.add(val)
                data_type, data = 0x03, raw
            elif vtype == "bool":
                raw, data_type, data = -1, 0x12, (0xFFFFFFFF if val else 0)
            elif vtype == "int":
                raw, data_type, data = -1, 0x10, int(val)
            else:
                raise ValueError(f"bad value type {vtype}")
            ext += struct.pack("<iii", a_ns, a_name, raw)
            ext += struct.pack("<HBBI", 8, 0, data_type, data & 0xFFFFFFFF)
        body += _chunk(0x0102, ext)   # start element
        for child in node.get("children", []):
            emit(child)
        body += _chunk(0x0103, struct.pack("<ii", -1, pool.add(node["tag"])))  # end element

    emit(root)
    body += _chunk(0x0101, struct.pack("<ii", android_prefix_idx, android_uri_idx))  # end ns

    string_pool = _build_string_pool(pool)
    payload = string_pool + body
    file_size = 8 + len(payload)
    file_header = struct.pack("<HHI", 0x0003, 8, file_size)
    return file_header + payload
