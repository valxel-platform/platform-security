"""A product's security spec (products/<product>.yaml), checked before anything is generated."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

NAME = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
SCOPE = re.compile(r"^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$")


class SpecError(ValueError):
    pass


def load(path: str | Path) -> dict[str, Any]:
    spec = yaml.safe_load(Path(path).read_text()) or {}
    problems = check(spec)
    if problems:
        raise SpecError(f"{path}: " + "; ".join(problems))
    return spec


def check(spec: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in ("product", "domain", "namespace", "audience"):
        if not spec.get(key):
            out.append(f"{key} is required")
    for key in ("product", "namespace", "audience"):
        if spec.get(key) and not NAME.match(str(spec[key])):
            out.append(f"{key} {spec[key]!r} is not a lowercase name")
    roles = set(spec.get("roles") or [])
    for scope, granted in (spec.get("scopes") or {}).items():
        if not SCOPE.match(scope):
            out.append(f"scope {scope!r} should look like greetings:read")
        unknown = set(granted or []) - roles
        if unknown:
            out.append(f"scope {scope} grants unknown roles {sorted(unknown)}")
    lifetime = int(spec.get("token_lifetime_seconds", 300))
    if not 60 <= lifetime <= 900:
        out.append("token_lifetime_seconds must be 60-900: access tokens stay short")
    if not (spec.get("bff") or {}).get("client_id"):
        out.append("bff.client_id is required")
    names = (
        [spec.get("bff", {}).get("client_id")]
        + [s["name"] for s in spec.get("services") or []]
        + [a["name"] for a in spec.get("agents") or []]
        + [m["name"] for m in spec.get("mcp_servers") or []]
    )
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        out.append(f"names used twice: {dupes}")
    for m in spec.get("mobile") or []:
        for uri in m.get("redirect_uris") or []:
            if "*" in uri:
                out.append(f"{m.get('client_id')}: redirect URIs must be exact, not {uri}")
    for c in spec.get("calls") or []:
        if not (c.get("from") and c.get("to") and c.get("port")):
            out.append(f"call {c} needs from, to and port")
    return out
