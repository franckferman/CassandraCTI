# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# __main__.py
#
# Lets `python -m cassandra_cti` run the CLI. The GUI runner relies on this as
# its last-resort way to reach the CLI when no console script is on PATH.
from .cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
