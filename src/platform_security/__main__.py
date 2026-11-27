"""python -m platform_security check|realm security.yaml [-o FILE]

A product's security spec lives in its own security repo (security.yaml); its CI runs `check` with a
pinned release of this package. The mesh rules are rendered by OpenChoreo from the platform's
component types, with each component's callers set from the spec's `calls` by the Valxel SDLC."""

from __future__ import annotations

import argparse
import json
import sys

from . import realm, spec


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="platform_security")
    p.add_argument("what", choices=["check", "realm"])
    p.add_argument("spec")
    p.add_argument("-o", "--output")
    args = p.parse_args(argv)
    try:
        s = spec.load(args.spec)
    except spec.SpecError as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.what == "check":
        print(f"{args.spec}: ok")
        return 0
    text = json.dumps(realm.render(s), indent=2) + "\n"
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
