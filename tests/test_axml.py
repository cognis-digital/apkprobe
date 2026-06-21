from apkprobe.axml import parse, AXMLError
from tests._axml_fixture import encode
from tests.conftest import manifest_tree

import pytest


def test_roundtrip_basic_tree():
    tree = manifest_tree(debuggable=("bool", True))
    root = parse(encode(tree))
    assert root.tag == "manifest"
    assert root.attributes.get("package") == "com.acme.app"


def test_attribute_namespacing_and_types():
    root = parse(encode(manifest_tree(debuggable=("bool", True))))
    app = next(root.iter("application"))
    assert app.attr("debuggable") == "true"


def test_int_and_string_values():
    root = parse(encode(manifest_tree()))
    uses_sdk = next(root.iter("uses-sdk"))
    assert uses_sdk.attr("minSdkVersion") == "21"
    assert uses_sdk.attr("targetSdkVersion") == "33"


def test_nested_structure_preserved():
    root = parse(encode(manifest_tree()))
    activities = [e for e in root.iter("activity")]
    assert len(activities) == 1
    assert activities[0].attr("name") == ".MainActivity"
    assert sum(1 for _ in activities[0].iter("intent-filter")) == 1


def test_rejects_non_axml():
    with pytest.raises(AXMLError):
        parse(b"<?xml version='1.0'?><manifest/>")


def test_rejects_tiny_buffer():
    with pytest.raises(AXMLError):
        parse(b"\x00\x01")


def test_unicode_strings_roundtrip():
    tree = {
        "tag": "manifest",
        "attrs": {"package": ("string", "com.café.приложение")},
        "children": [],
    }
    root = parse(encode(tree))
    assert root.attributes["package"] == "com.café.приложение"
