# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# gui/__main__.py
#
# Lets `python -m cassandra_cti.gui` launch the window.
import sys

from .app import main

if __name__ == "__main__":
    sys.exit(main())
