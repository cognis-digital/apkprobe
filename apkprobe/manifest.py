"""Interpret a decoded AXML manifest into a structured model.

Turns the raw :class:`apkprobe.axml.Element` tree into an :class:`AppManifest`
with the fields the rule engine cares about: package, SDK levels, permissions,
the application-level security flags, and the exported components.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .axml import Element, parse


@dataclass
class Component:
    kind: str            # activity | service | receiver | provider
    name: str
    exported: bool
    has_permission: bool
    intent_filters: int


@dataclass
class AppManifest:
    package: str = ""
    version_code: str = ""
    version_name: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: list[str] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = True          # Android default is true
    uses_cleartext_traffic: bool | None = None
    network_security_config: str = ""
    components: list[Component] = field(default_factory=list)

    @classmethod
    def from_axml(cls, data: bytes) -> "AppManifest":
        return cls.from_element(parse(data))

    @classmethod
    def from_element(cls, root: Element) -> "AppManifest":
        m = cls()
        m.package = root.attr("package", "") or root.attributes.get("package", "")
        m.version_code = str(root.attr("versionCode", "") or "")
        m.version_name = str(root.attr("versionName", "") or "")

        for el in root.iter("uses-sdk"):
            m.min_sdk = _as_int(el.attr("minSdkVersion"))
            m.target_sdk = _as_int(el.attr("targetSdkVersion"))

        for el in root.iter("uses-permission"):
            name = el.attr("name")
            if name:
                m.permissions.append(name)

        for app in root.iter("application"):
            m.debuggable = _as_bool(app.attr("debuggable"), False)
            m.allow_backup = _as_bool(app.attr("allowBackup"), True)
            cleartext = app.attr("usesCleartextTraffic")
            m.uses_cleartext_traffic = None if cleartext is None else _as_bool(cleartext, False)
            m.network_security_config = app.attr("networkSecurityConfig", "") or ""
            for kind in ("activity", "service", "receiver", "provider"):
                for comp in app.iter(kind):
                    if comp.tag != kind:
                        continue
                    m.components.append(_component(comp, kind))
            break
        return m


def _component(el: Element, kind: str) -> Component:
    filters = sum(1 for _ in el.iter("intent-filter"))
    exported_attr = el.attr("exported")
    # If 'exported' is unset, Android implicitly exports a component that has an
    # intent-filter (pre-S behavior). Capture that as the effective default.
    if exported_attr is None:
        exported = filters > 0
    else:
        exported = _as_bool(exported_attr, False)
    has_perm = bool(el.attr("permission"))
    return Component(kind=kind, name=el.attr("name", "") or "", exported=exported,
                     has_permission=has_perm, intent_filters=filters)


def _as_bool(value, default: bool) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("true", "1", "0xffffffff", "-1")


def _as_int(value) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0
