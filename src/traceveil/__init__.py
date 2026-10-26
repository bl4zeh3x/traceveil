"""Conservative local processing for browser HTTP archives."""

from .core import inspect_har, is_sanitized, sanitize

__version__ = "0.1.0"
__all__ = ["sanitize", "inspect_har", "is_sanitized"]
