"""Enable `python -m mewtwo ...` as an alternative to the `mewtwo` console script.

Useful on systems where the entry-point Scripts directory is not on PATH.
"""

from .cli import cli

if __name__ == "__main__":
    cli()
