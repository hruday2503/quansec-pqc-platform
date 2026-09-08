"""Compatibility entry point for local runs; containers use services.api."""

from services.api import app

__all__ = ["app"]
