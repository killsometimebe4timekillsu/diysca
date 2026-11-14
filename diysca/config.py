"""Settings: defaults < config.yml < environment variables (DIYSCA_*)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml


@dataclass
class Settings:
    data_dir: str = "./data"
    db_path: str = ""  # default: <data_dir>/diysca.db
    inventories: list[str] = field(default_factory=list)  # Ansible inventory files/dirs
    use_ansible_inventory_cli: bool = True

    ssh_user: str = ""
    ssh_key: str = ""
    ssh_known_hosts: str = ""  # "" = ~/.ssh/known_hosts, "ignore" = don't verify, or a path
    ssh_timeout: int = 15
    scan_concurrency: int = 8

    scan_interval_hours: float = 12  # 0 disables the built-in scheduler
    repo_fetch: str = "scanner"  # scanner | host | off  (who downloads repo indexes)

    osv_mode: str = "api"  # api = query api.osv.dev per scan | bulk = mirror per-distro zips locally
    osv_url: str = "https://api.osv.dev"
    osv_bulk_url: str = "https://osv-vulnerabilities.storage.googleapis.com"
    osv_bulk_hours: float = 12  # re-download bulk data after this many hours
    nvd_enabled: bool = True
    nvd_api_key: str = ""
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_enabled: bool = True
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    vuln_cache_hours: float = 24
    http_timeout: float = 60
    http_proxy_ca: str = ""  # optional CA bundle for egress proxies

    web_user: str = ""  # set both to enable HTTP basic auth
    web_password: str = ""
    base_url: str = "http://localhost:8080"

    @property
    def database(self) -> str:
        return self.db_path or str(Path(self.data_dir) / "diysca.db")


def _coerce(t, v):
    if t in (bool, "bool"):
        return str(v).lower() in ("1", "true", "yes", "on")
    if t in (int, "int"):
        return int(v)
    if t in (float, "float"):
        return float(v)
    if t in ("list[str]",) or t == list[str]:
        return [x.strip() for x in str(v).split(",") if x.strip()] if isinstance(v, str) else list(v)
    return v


def load_settings(path: str | None = None) -> Settings:
    s = Settings()
    path = path or os.environ.get("DIYSCA_CONFIG") or ("config.yml" if Path("config.yml").exists() else None)
    if path and Path(path).exists():
        data = yaml.safe_load(Path(path).read_text()) or {}
        for f in fields(s):
            if f.name in data and data[f.name] is not None:
                setattr(s, f.name, _coerce(f.type, data[f.name]))
    for f in fields(s):
        env = os.environ.get("DIYSCA_" + f.name.upper())
        if env is not None:
            setattr(s, f.name, _coerce(f.type, env))
    return s


settings = load_settings()


def reload(path: str | None = None) -> Settings:
    new = load_settings(path)
    for f in fields(new):
        setattr(settings, f.name, getattr(new, f.name))
    return settings
