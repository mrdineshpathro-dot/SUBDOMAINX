"""Configuration handling.

Configuration may come from (in increasing priority):

1. built-in defaults
2. ``config.toml`` (or ``--config PATH``)
3. command line arguments

No secrets are ever read or written - SUBDOMAINX has nothing to authenticate.
"""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Optional

from .utils.http import DEFAULT_USER_AGENT

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - fallback for exotic builds
    tomllib = None  # type: ignore[assignment]


PROFILES = ("fast", "balanced", "deep")
OUTPUT_PROFILES = ("minimal", "standard", "detailed", "json", "csv", "html")
FORMATS = ("txt", "json", "csv", "html")


@dataclass
class GeneralConfig:
    """Global execution settings."""

    threads: int = 10
    timeout: int = 10
    retries: int = 2
    profile: str = "balanced"
    user_agent: str = DEFAULT_USER_AGENT
    rate_limit: float = 1.0
    verify_tls: bool = True


@dataclass
class DNSConfig:
    """DNS enrichment settings."""

    enabled: bool = True
    threads: int = 10
    timeout: float = 5.0
    retries: int = 1
    nameservers: List[str] = field(default_factory=list)
    detect_wildcard: bool = True
    dnssec: bool = False
    record_types: List[str] = field(
        default_factory=lambda: ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"]
    )


@dataclass
class HTTPConfig:
    """HTTP probing settings."""

    enabled: bool = False
    threads: int = 10
    timeout: float = 8.0
    max_body_size: int = 1_000_000
    verify_tls: bool = True
    fallback_http: bool = True
    capture_tls: bool = False


@dataclass
class CacheConfig:
    """Local response cache settings."""

    enabled: bool = True
    ttl: int = 86_400
    path: str = ".cache"


@dataclass
class StorageConfig:
    """SQLite settings."""

    enabled: bool = True
    path: str = "subdomainx.db"


@dataclass
class SourcesConfig:
    """Per-source enable/disable map."""

    enabled: Dict[str, bool] = field(default_factory=dict)


@dataclass
class OutputConfig:
    """Reporting settings."""

    format: str = "txt"
    output: Optional[str] = None
    profile: str = "standard"
    color: bool = True
    quiet: bool = False
    verbose: bool = False
    debug: bool = False
    log_format: str = "text"
    log_file: Optional[str] = None


@dataclass
class Config:
    """Complete SUBDOMAINX configuration."""

    general: GeneralConfig = field(default_factory=GeneralConfig)
    dns: DNSConfig = field(default_factory=DNSConfig)
    http: HTTPConfig = field(default_factory=HTTPConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    sources: SourcesConfig = field(default_factory=SourcesConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    # -- serialisation -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """Return the config as a plain dict (round-trippable)."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Build a config from a nested dictionary, ignoring unknown keys."""
        config = cls()
        for section_field in fields(cls):
            section_name = section_field.name
            section_data = (data or {}).get(section_name)
            if not isinstance(section_data, dict):
                continue
            section = getattr(config, section_name)
            if isinstance(section, SourcesConfig):
                for key, value in section_data.items():
                    section.enabled[str(key)] = bool(value)
                continue
            for item_field in fields(section):
                if item_field.name not in section_data:
                    continue
                value = section_data[item_field.name]
                if value is None:
                    continue
                current = getattr(section, item_field.name)
                if isinstance(current, bool):
                    setattr(section, item_field.name, _to_bool(value))
                elif isinstance(current, int) and not isinstance(current, bool):
                    setattr(section, item_field.name, int(value))
                elif isinstance(current, float):
                    setattr(section, item_field.name, float(value))
                elif isinstance(current, list):
                    setattr(section, item_field.name, list(value))
                else:
                    setattr(section, item_field.name, value)
        return config

    # -- profiles ----------------------------------------------------------
    def apply_profile(self, profile: Optional[str]) -> "Config":
        """Apply one of the FAST / BALANCED / DEEP performance profiles."""
        name = (profile or "").strip().lower()
        if not name:
            return self
        if name not in PROFILES:
            raise ValueError(f"unknown profile {profile!r}; choose from {', '.join(PROFILES)}")
        self.general.profile = name
        if name == "fast":
            self.dns.enabled = False
            self.http.enabled = False
            self.dns.detect_wildcard = False
            self.http.capture_tls = False
            self.dns.dnssec = False
        elif name == "balanced":
            self.dns.enabled = True
            self.http.enabled = True
            self.dns.detect_wildcard = True
            self.http.capture_tls = False
            self.dns.dnssec = False
        elif name == "deep":
            self.dns.enabled = True
            self.http.enabled = True
            self.dns.detect_wildcard = True
            self.http.capture_tls = True
            self.dns.dnssec = True
            self.general.threads = max(self.general.threads, 15)
        return self

    # -- misc --------------------------------------------------------------
    def clone(self) -> "Config":
        """Deep copy of the configuration."""
        return copy.deepcopy(self)

    def merge_cli(self, args: Any) -> "Config":
        """Overlay the most common command line arguments."""
        if args is None:
            return self
        get = (lambda key: getattr(args, key, None)) if not isinstance(args, dict) else args.get

        if get("threads"):
            self.general.threads = int(get("threads"))
        if get("timeout"):
            self.general.timeout = int(get("timeout"))
        if get("retries") is not None:
            self.general.retries = int(get("retries"))
        if get("profile"):
            self.apply_profile(get("profile"))

        if get("resolve") is not None:
            self.dns.enabled = bool(get("resolve"))
        if get("no_resolve"):
            self.dns.enabled = False
        if get("probe"):
            self.http.enabled = True
        if get("no_probe"):
            self.http.enabled = False

        if get("no_cache"):
            self.cache.enabled = False
        if get("cache"):
            self.cache.enabled = True
        if get("cache_ttl"):
            self.cache.ttl = int(get("cache_ttl"))

        if get("db"):
            self.storage.path = str(get("db"))
        if get("no_db"):
            self.storage.enabled = False

        if get("format"):
            self.output.format = str(get("format")).lower()
        if get("output"):
            self.output.output = str(get("output"))
        if get("output_profile"):
            self.output.profile = str(get("output_profile")).lower()
        if get("no_color"):
            self.output.color = False
        if get("quiet"):
            self.output.quiet = True
        if get("verbose"):
            self.output.verbose = True
        if get("debug"):
            self.output.debug = True
        if get("log_format"):
            self.output.log_format = str(get("log_format")).lower()
        return self

    def render_toml(self) -> str:
        """Render an example ``config.toml`` (written by ``--write-config``)."""
        data = self.to_dict()
        lines: List[str] = [
            "# SUBDOMAINX configuration",
            "# Generated by `subdomainx --write-config config.toml`",
            "# No secrets: SUBDOMAINX never uses API keys or credentials.",
            "",
        ]
        for section, values in data.items():
            if section == "sources":
                lines.append("[sources]")
                lines.append("# Set a source to false to disable it permanently.")
                for name, requires_key in _known_source_names(self):
                    if requires_key:
                        lines.append(f"# {name} requires an API key and is never executed")
                        lines.append(f"{name} = false")
                    else:
                        lines.append(f"{name} = {_toml_value(self.sources.enabled.get(name, True))}")
                lines.append("")
                continue
            lines.append(f"[{section}]")
            for key, value in (values or {}).items():
                lines.append(f"{key} = {_toml_value(value)}")
            lines.append("")
        return "\n".join(lines)


def _known_source_names(config: "Config") -> List[tuple]:
    """Return ``(name, requires_api_key)`` for every discovered source."""
    names: List[tuple] = []
    try:
        from .sources.registry import iter_source_classes

        classes = iter_source_classes()
        names = [(name, bool(getattr(classes[name], "requires_api_key", False))) for name in sorted(classes)]
    except Exception:  # noqa: BLE001 - registry discovery is best effort
        names = []
    known = {name for name, _ in names}
    for extra in (config.sources.enabled or {}):
        if extra not in known:
            names.append((extra, False))
    return names


def _toml_value(value: Any) -> str:  # noqa: ANN401
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        inner = "\n".join(f"  {k} = {_toml_value(v)}" for k, v in value.items())
        return "{\n" + inner + "\n}"
    return '"' + str(value).replace('"', '\\"') + '"'


def _to_bool(value: Any) -> bool:  # noqa: ANN401
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def load_config(path: Optional[str] = None) -> Config:
    """Load a configuration file, falling back to defaults."""
    if not path:
        return Config()
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"configuration file not found: {path}")
    if tomllib is None:  # pragma: no cover
        raise RuntimeError("tomllib unavailable: Python 3.11+ is required for config.toml")
    with file_path.open("rb") as handle:
        data = tomllib.load(handle)
    return Config.from_dict(data or {})


def find_default_config(cwd: str = ".") -> Optional[str]:
    """Return the path of a ``config.toml`` / ``.subdomainx.toml`` if present."""
    for name in ("config.toml", "subdomainx.toml", ".subdomainx.toml"):
        candidate = Path(cwd) / name
        if candidate.exists():
            return str(candidate)
    return None


def default_config() -> Config:
    """Return the default configuration (BALANCED profile)."""
    return Config()
