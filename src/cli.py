"""The `cra` command-line tool.

Exit codes: 0 = all fine, 1 = some component is UNKNOWN (a human must look), 2 = input rejected.

Run it with:  python -m src <command>   (from the project folder, using the .venv python)
"""

import argparse
import sys

from src.sbom_reader import ConfigError, SbomError, load_sbom, read_product_config


def _check_sbom(args):
    try:
        config = read_product_config(args.config) if args.config else None
        result = load_sbom(args.sbom)
    except (ConfigError, SbomError) as error:
        print(f"REJECTED: {error}", file=sys.stderr)
        return 2

    if config:
        print(f"Product: {config['product_name']} ({config['manufacturer']})")
        print(f"Member states: {', '.join(config['member_states'])}")
    print(f"Components found: {len(result.components)}")
    for component in result.components:
        label = f"{component.name or '(unnamed)'} {component.version or '?'}"
        if component.status == "OK":
            print(f"  OK       {label}  [{component.ecosystem}]")
        else:
            print(f"  UNKNOWN  {label}  - {component.reason}")
    for warning in result.warnings:
        print(f"WARNING: {warning}")
    unknown = sum(1 for c in result.components if c.status != "OK")
    if unknown:
        print(f"{unknown} component(s) are UNKNOWN: they could not be checked and need a human.")
        return 1
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cra", description="CRA Copilot: helps with the CRA 24-hour early warning. Never sends anything."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check-sbom", help="read an SBOM and list its components")
    check.add_argument("sbom", help="path to a CycloneDX JSON file")
    check.add_argument("--config", help="path to the product config JSON file")
    check.set_defaults(handler=_check_sbom)
    return parser


def main(argv=None):
    # A Windows console may not be able to show every character: never crash because of that.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
