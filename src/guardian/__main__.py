"""Support execution with python -m guardian."""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
