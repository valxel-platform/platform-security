"""python -m platform_security realm|mesh products/<product>.yaml [-o FILE]"""

from __future__ import annotations

import argparse
import json
import sys

from . import mesh, realm, spec


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="platform_security")
    p.add_argument("what", choices=["realm", "mesh", "check"])
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
    text = json.dumps(realm.render(s), indent=2) + "\n" if args.what == "realm" else mesh.dump(mesh.render(s))
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
