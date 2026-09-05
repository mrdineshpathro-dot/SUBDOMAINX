"""Local on-disk HTTP response cache.

Layout::

    .cache/
        crtsh/
            ab/abcdef....json
        urlscan/
        commoncrawl/
        rapiddns/

Cache keys are SHA-256 hashes of the full request identity, so no URL or
hostname is ever written to disk in clear text.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

from ..utils.helpers import sha256

DEFAULT_ROOT = ".cache"
DEFAULT_TTL = 86_400


class ResponseCache:
    """A tiny, dependency-free JSON file cache with TTL support."""

    def __init__(
        self,
        root: str = DEFAULT_ROOT,
        ttl: int = DEFAULT_TTL,
        enabled: bool = True,
    ) -> None:
        self.root = Path(root)
        self.ttl = int(ttl)
        self.enabled = bool(enabled)
        self.hits = 0
        self.misses = 0

    # -- public API --------------------------------------------------------
    def get(self, key: str, namespace: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Return a cached payload or ``None`` (missing / expired / disabled)."""
        if not self.enabled:
            return None
        path = self.path_for(key, namespace)
        if not path.exists():
            self.misses += 1
            return None
        try:
            if self.ttl > 0 and (time.time() - path.stat().st_mtime) > self.ttl:
                path.unlink(missing_ok=True)
                self.misses += 1
                return None
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                self.misses += 1
                return None
            self.hits += 1
            return payload.get("value")
        except (OSError, ValueError):
            self.misses += 1
            return None

    def put(self, key: str, value: Any, ttl: Optional[int] = None, namespace: Optional[str] = None) -> bool:
        """Store ``value`` under ``key``.  Never raises."""
        if not self.enabled:
            return False
        path = self.path_for(key, namespace)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(
                    {
                        "key": sha256(key),
                        "stored_at": time.time(),
                        "ttl": ttl or self.ttl,
                        "value": value,
                    },
                    ensure_ascii=False,
                    default=str,
                ),
                encoding="utf-8",
            )
            tmp.replace(path)
            return True
        except OSError:
            return False

    def path_for(self, key: str, namespace: Optional[str] = None) -> Path:
        """Return the cache file path for ``key``."""
        digest = sha256(key)
        folder = namespace or self._namespace_from_key(key)
        return self.root / folder / digest[:2] / f"{digest}.json"

    def clear(self, older_than: Optional[int] = None) -> int:
        """Remove cache entries (all, or older than ``older_than`` seconds)."""
        removed = 0
        if not self.root.exists():
            return 0
        now = time.time()
        for path in self.root.rglob("*.json"):
            try:
                if older_than is None or (now - path.stat().st_mtime) > older_than:
                    path.unlink()
                    removed += 1
            except OSError:
                continue
        return removed

    def stats(self) -> Dict[str, Any]:
        """Return cache usage statistics."""
        files = 0
        size = 0
        if self.root.exists():
            for path in self.root.rglob("*.json"):
                try:
                    files += 1
                    size += path.stat().st_size
                except OSError:
                    continue
        return {
            "enabled": self.enabled,
            "root": str(self.root),
            "ttl": self.ttl,
            "entries": files,
            "bytes": size,
            "hits": self.hits,
            "misses": self.misses,
        }

    # -- internals ---------------------------------------------------------
    @staticmethod
    def _namespace_from_key(key: str) -> str:
        """Derive a directory name from the key (``source:...`` -> ``source``)."""
        head = (key or "").split(":", 1)[0].strip().lower()
        safe = "".join(ch for ch in head if ch.isalnum() or ch in "-_")
        return safe or "misc"
