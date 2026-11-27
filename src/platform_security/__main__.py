"""python -m platform_security realm|mesh|check products/<product>.yaml [-o FILE]
python -m platform_security bundle products -o DIR   (every product's mesh policies, for Flux)"""

from __future__ import annotations

import argparse
import json
import sys

from . import bundle, mesh, realm, spec


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="platform_security")
    p.add_argument("what", choices=["realm", "mesh", "check", "bundle"])
    p.add_argument("spec")
    p.add_argument("-o", "--output")
    args = p.parse_args(argv)
    if args.what == "bundle":
        if not args.output:
            print("bundle needs -o DIR", file=sys.stderr)
            return 2
        try:
            names = bundle.build(args.spec, args.output)
        except spec.SpecError as exc:
            print(exc, file=sys.stderr)
            return 1
        print(f"{args.output}: {len(names)} product(s)" + (f": {', '.join(names)}" if names else ""))
        return 0
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
