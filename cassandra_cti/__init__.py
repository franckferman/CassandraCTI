# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# __init__.py
# Single source of truth for the version; pyproject.toml reads it dynamically
# and the CLI's --version flag prints it, so a pip install and the frozen binary
# always agree.
__version__ = "2.0.0"
__all__ = ["__version__"]
