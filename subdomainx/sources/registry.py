"""Dynamic source registry.

Sources are discovered automatically by scanning every module in
``subdomainx/sources/`` for :class:`~subdomainx.sources.base.PassiveSource`
subclasses.  No manual registration step is required - dropping a file into the
package is enough.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Any, Dict, Iterator, List, Optional, Sequence

from ..utils.logging import get_logger
from .base import PassiveSource

logger = get_logger()

#: Modules that must not be scanned for source implementations.
_INTERNAL_MODULES = {"base", "registry"}


def iter_source_classes() -> Dict[str, type]:
    """Return ``{source_name: source_class}`` for every discovered source."""
    package = __package__ or "subdomainx.sources"
    try:
        package_module = importlib.import_module(package)
    except ImportError:  # pragma: no cover - package always importable
        return {}

    discovered: Dict[str, type] = {}
    for module_info in pkgutil.iter_modules(getattr(package_module, "__path__", [])):
        if module_info.name in _INTERNAL_MODULES or module_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"{package}.{module_info.name}")
        except Exception as exc:  # noqa: BLE001 - a broken module must not kill discovery
            logger.debug("Skipping source module %s: %s", module_info.name, exc)
            continue
        for _, obj in vars(module).items():
            if not inspect.isclass(obj):
                continue
            if obj is PassiveSource or not issubclass(obj, PassiveSource):
                continue
            if getattr(obj, "__module__", "") != module.__name__:
                continue  # imported, not defined here: avoid double registration
            if inspect.isabstract(obj):
                continue
            name = getattr(obj, "name", None) or obj.__name__.lower()
            if name in discovered:
                logger.debug("Duplicate source name %s ignored", name)
                continue
            discovered[name] = obj
    return discovered


def build_registry(
    http: Optional[Any] = None,
    enabled: Optional[Dict[str, bool]] = None,
) -> List[PassiveSource]:
    """Instantiate every discovered source.

    ``enabled`` optionally maps a source name to a boolean; unknown names are
    enabled by default.
    """
    sources: List[PassiveSource] = []
    for name, cls in sorted(iter_source_classes().items()):
        try:
            instance = cls(http=http, enabled=bool((enabled or {}).get(name, True)))
        except Exception as exc:  # noqa: BLE001 - never fail the whole registry
            logger.debug("Could not instantiate source %s: %s", name, exc)
            continue
        sources.append(instance)
    return sources


def source_catalog(sources: Optional[Sequence[PassiveSource]] = None) -> List[Dict[str, Any]]:
    """Serialisable catalogue used by ``--list-sources`` and the docs."""
    items: List[Dict[str, Any]] = []
    for source in sources if sources is not None else build_registry():
        items.append(
            {
                "name": source.name,
                "category": source.category,
                "description": source.description,
                "requires_api_key": source.requires_api_key,
                "enabled": source.enabled,
                "homepage": source.homepage,
                "status": source.health.status.value,
            }
        )
    return items


def get_source(name: str, sources: Optional[Sequence[PassiveSource]] = None) -> Optional[PassiveSource]:
    """Return the source instance with the given name (case insensitive)."""
    wanted = (name or "").strip().lower()
    for source in sources if sources is not None else build_registry():
        if source.name.lower() == wanted:
            return source
    return None


def filter_sources(
    sources: Sequence[PassiveSource],
    selection: Optional[Sequence[str]] = None,
) -> List[PassiveSource]:
    """Select sources by name.

    ``selection`` accepts ``all``, a comma separated string, or a list of names.
    Unknown names are ignored with a warning.
    """
    if not selection:
        return list(sources)
    if isinstance(selection, str):
        selection = [part.strip() for part in selection.split(",")]
    wanted = {s.strip().lower() for s in selection if s and s.strip()}
    if not wanted or "all" in wanted:
        return [s for s in sources if s.requires_api_key is False]

    chosen = [s for s in sources if s.name.lower() in wanted and not s.requires_api_key]
    missing = wanted - {s.name.lower() for s in chosen}
    if missing:
        logger.warning("Unknown or unavailable source(s): %s", ", ".join(sorted(missing)))
    return chosen


def iter_enabled(sources: Sequence[PassiveSource]) -> Iterator[PassiveSource]:
    """Yield sources that are enabled and do not require credentials."""
    for source in sources:
        if source.enabled and not source.requires_api_key:
            yield source
