# bindecrypter/cli.py
import argparse
import logging
import sys

from .core import bindecrypt


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(levelname)s] %(message)s"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="bindecrypter",
        description="Deobfuscate bincrypter-wrapped binaries (<= v1.3)"
    )
    parser.add_argument("file", help="Obfuscated bincrypter binary")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    try:
        out = bindecrypt(args.file)
        logging.info("Deobfuscated binary written to: %s", out)
        return 0
    except Exception as e:
        logging.error("%s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
