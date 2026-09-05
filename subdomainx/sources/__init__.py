"""Passive source adapters.

Every module in this package that defines a
:class:`~subdomainx.sources.base.PassiveSource` subclass is discovered and
registered automatically by :mod:`subdomainx.sources.registry`.

The registry is exposed lazily so that importing submodules from this package
never creates an import cycle.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "PassiveSource",
    "SourceError",
    "RateLimitedError",
    "SourceUnavailableError",
    "ParserError",
    "SOURCE_REGISTRY",
    "build_registry",
    "get_source",
    "filter_sources",
    "source_catalog",
    "iter_source_classes",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401 - lazy attribute access
    """Lazily expose the registry and base classes."""
    if name in {"PassiveSource", "SourceError", "RateLimitedError", "SourceUnavailableError", "ParserError"}:
        from . import base

        return getattr(base, name)

    if name == "SOURCE_REGISTRY":
        from .registry import build_registry

        return build_registry()

    if name in {
        "build_registry",
        "get_source",
        "filter_sources",
        "source_catalog",
        "iter_source_classes",
        "iter_enabled",
    }:
        from . import registry

        return getattr(registry, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
