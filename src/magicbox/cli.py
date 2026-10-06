"""Initialize a key capsule; retain the legacy suite's commands."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .capsule import init_file, inspect_file
from .core import DEFAULT_MAX_WORK, MagicBoxError, open_file, seal_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="magicbox", description="AES-256 encryption with an embedded computational lock."
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    initialized = commands.add_parser("init", help="encrypt a file with an internal key capsule")
    initialized.add_argument("file", type=Path)
    initialized.add_argument("-o", "--output", type=Path, required=True)
    initialized.add_argument("--work", type=int, required=True, help="embedded computation count")
    seal = commands.add_parser("seal", help="create a legacy suite-01 box")
    seal.add_argument("file", type=Path)
    seal.add_argument("-o", "--output", type=Path, required=True)
    seal.add_argument("--work", type=int, required=True, help="number of squarings to open")
    opened = commands.add_parser("open", help="open a legacy suite-01 box")
    opened.add_argument("box", type=Path)
    opened.add_argument("-o", "--output", type=Path, required=True)
    opened.add_argument("--max-work", type=int, default=DEFAULT_MAX_WORK)
    inspected = commands.add_parser("inspect", help="read unauthenticated public lock metadata")
    inspected.add_argument("box", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "init":
            info = init_file(arguments.file, arguments.output, work=arguments.work)
            print(f"initialized {arguments.output} (internal key capsule; work={info.work})")
        elif arguments.command == "seal":
            info = seal_file(arguments.file, arguments.output, work=arguments.work)
            print(f"sealed {arguments.output} ({info.work} squarings to open)")
        elif arguments.command == "open":
            def progress(done: int, total: int) -> None:
                print(f"\rsolving lock: {done}/{total}", end="", file=sys.stderr, flush=True)

            interactive = sys.stderr.isatty()
            try:
                open_file(
                    arguments.box, arguments.output, max_work=arguments.max_work,
                    progress=progress if interactive else None,
                )
            finally:
                if interactive:
                    print(file=sys.stderr)
            print(f"opened {arguments.output}; authentication verified")
        else:
            print(json.dumps(asdict(inspect_file(arguments.box)), indent=2, sort_keys=True))
    except (MagicBoxError, OSError) as error:
        print(f"magicbox: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nmagicbox: interrupted", file=sys.stderr)
        return 130
    return 0
