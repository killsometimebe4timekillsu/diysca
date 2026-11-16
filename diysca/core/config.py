"""Settings: defaults < config.yml < environment variables (DIYSCA_*)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml


@dataclass
class Settings:
    data_dir: str = ""  # default: $STATE_DIRECTORY (systemd) or $XDG_DATA_HOME/diysca
    database_url: str = ""  # postgresql://user:pass@host:5432/diysca (recommended); empty = SQLite file
    db_path: str = ""  # SQLite only. default: <data_dir>/diysca.db
    inventories: list[str] = field(default_factory=list)  # Ansible inventory files/dirs
    use_ansible_inventory_cli: bool = True
    # Directories the web UI may import further inventories from (Systems > Import Ansible inventory).
    # Empty: only the inventories listed above, and files below those that are directories.
    inventory_dirs: list[str] = field(default_factory=list)

    ssh_user: str = ""
    ssh_key: str = ""
    ssh_known_hosts: str = ""  # "" = ~/.ssh/known_hosts, "ignore" = don't verify, or a path
    ssh_timeout: int = 15
    scan_concurrency: int = 8

    scan_languages: bool = True  # PyPI, npm, RubyGems, Maven, Packagist, crates.io, Go
    lang_scan_paths: list[str] = field(default_factory=lambda: [
        "/opt", "/srv", "/usr/local", "/home", "/root", "/var/www", "/var/lib/jenkins", "/usr/lib/node_modules"])
    container_lang_scan_paths: list[str] = field(default_factory=lambda: [
        "/app", "/usr/src", "/usr/local", "/opt", "/srv", "/home", "/root", "/var/www", "/workspace"])
    lang_scan_timeout: int = 600
    scan_containers: bool = True  # scan the images of running containers on each host
    container_runtimes: list[str] = field(default_factory=lambda: ["podman", "docker", "nerdctl", "crictl"])
    container_sudo: bool = False  # prefix runtime calls with "sudo -n"

    scan_interval_hours: float = 12  # 0 disables the built-in scheduler
    repo_fetch: str = "scanner"  # scanner | host | off  (who downloads repo indexes)

    osv_mode: str = "api"  # api = query api.osv.dev per scan | bulk = mirror per-distro zips locally
    osv_url: str = "https://api.osv.dev"
    osv_bulk_url: str = "https://osv-vulnerabilities.storage.googleapis.com"
    osv_bulk_hours: float = 12  # re-download bulk data after this many hours
    nvd_enabled: bool = True
    nvd_api_key: str = ""
    nvd_budget_seconds: float = 0  # time per enrichment run; 0 = 90 s without an API key, 600 s with one
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_enabled: bool = True
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    vuln_cache_hours: float = 24
    http_timeout: float = 60
    http_proxy_ca: str = ""  # optional CA bundle for egress proxies

    run_scheduler: bool = True  # false: this process only serves the UI/API; run `diysca worker` elsewhere
    inventory_providers: list = field(default_factory=list)  # libvirt, proxmox, vsphere, openstack, kubernetes, ... see docs
    modules: list[str] = field(default_factory=list)  # optional modules to enable: alerting, mitigation, auth (default: all)
    sources: list = field(default_factory=list)  # extra vulnerability sources, see config.example.yml
    repo_managers: list = field(default_factory=list)  # aptly / pulp / foreman, see config.example.yml

    # API tokens for agents, CI/CD and MCP clients: {name: token}. Sent as "Authorization: Bearer <token>".
    # Env: DIYSCA_API_TOKENS="ci:abc123,agent:def456"
    api_tokens: dict = field(default_factory=dict)
    agents_can_approve: bool = False  # may token holders (agents, MCP) approve findings themselves?
    # auth module (docs/auth.md): OIDC login, roles, host scopes, audit log
    oidc: dict = field(default_factory=dict)   # issuer, client_id, client_secret, scopes, username_claim, groups_claim
    rbac: dict = field(default_factory=dict)   # default_role, bindings: [{group|user|email, role, hosts}]
    session_secret: str = ""  # signs login cookies; generated into data_dir when empty
    session_hours: float = 8
    audit_days: int = 365  # keep the audit log this long
    web_user: str = ""  # set both to enable HTTP basic auth
    web_password: str = ""
    # Without a login (web_user / web_password or OIDC) everyone who reaches the UI is an admin. diysca then only
    # listens on 127.0.0.1 and refuses web pages while API tokens are set. true lifts both (lab setups only).
    allow_no_login: bool = False
    login_max_failures: int = 5          # failed logins per client address before it has to wait; 0 = no limit
    login_lockout_seconds: float = 300   # first wait; doubles with each further failure, at most 1 h
    base_url: str = "http://localhost:8080"

    def __post_init__(self):
        if not self.data_dir:
            self.data_dir = default_data_dir()

    @property
    def database(self) -> str:
        return self.db_path or str(Path(self.data_dir) / "diysca.db")


def default_data_dir() -> str:
    if os.environ.get("STATE_DIRECTORY"):  # systemd StateDirectory=
        return os.environ["STATE_DIRECTORY"].split(":")[0]
    xdg = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(xdg, "diysca")


def default_config_path() -> str | None:
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    for p in ("config.yml", os.path.join(xdg, "diysca", "config.yml"), "/etc/diysca/config.yml"):
        if Path(p).exists():
            return p
    return None


def _coerce(t, v):
    if t in (bool, "bool"):
        return str(v).lower() in ("1", "true", "yes", "on")
    if t in (int, "int"):
        return int(v)
    if t in (float, "float"):
        return float(v)
    if t in (dict, "dict"):
        if isinstance(v, dict):
            return {str(k): (x if isinstance(x, dict) else str(x)) for k, x in v.items()}
        return dict(p.split(":", 1) for p in str(v).split(",") if ":" in p)
    if t in ("list[str]",) or t == list[str]:
        return [x.strip() for x in str(v).split(",") if x.strip()] if isinstance(v, str) else list(v)
    return v


class ConfigError(Exception):
    """The configuration can't be used. The message is written for the person who edits config.yml."""


# what happened while loading: unknown keys (typos) and the like. Shown by `diysca` commands and at startup.
warnings: list[str] = []


def _set(s: Settings, f, value, where: str):
    try:
        setattr(s, f.name, _coerce(f.type, value))
    except (TypeError, ValueError) as e:
        raise ConfigError(f"{where}: {f.name} has the value {value!r}, which is not a valid "
                          f"{getattr(f.type, '__name__', f.type)} ({e})") from None


def load_settings(path: str | None = None, explicit: bool = False) -> Settings:
    """`explicit`: the path was given on the command line (-c), so a missing file is an error. A missing
    $DIYSCA_CONFIG is not: the OCI image sets it, and is often configured with environment variables only."""
    s = Settings()
    warnings.clear()
    path = path or os.environ.get("DIYSCA_CONFIG") or default_config_path()
    if path and not Path(path).exists():
        if explicit:
            raise ConfigError(f"config file {path} does not exist")
    elif path:
        try:
            data = yaml.safe_load(Path(path).read_text()) or {}
        except OSError as e:
            raise ConfigError(f"config file {path} can't be read: {e.strerror or e}") from None
        except yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)
            at = f" in line {mark.line + 1}" if mark else ""
            raise ConfigError(f"config file {path} is not valid YAML{at}: {getattr(e, 'problem', None) or e}") from None
        if not isinstance(data, dict):
            raise ConfigError(f"config file {path} must hold settings as `name: value` lines")
        names = {f.name for f in fields(s)}
        unknown = sorted(k for k in data if k not in names)
        if unknown:
            import difflib
            hints = []
            for k in unknown:
                near = difflib.get_close_matches(str(k), names, n=1)
                hints.append(f"{k}" + (f" (did you mean {near[0]}?)" if near else ""))
            warnings.append(f"{path}: unknown setting{'s' if len(unknown) > 1 else ''} ignored: {', '.join(hints)}")
        for f in fields(s):
            if f.name in data and data[f.name] is not None:
                _set(s, f, data[f.name], path)
    for f in fields(s):
        env = os.environ.get("DIYSCA_" + f.name.upper())
        if env is not None:
            _set(s, f, env, "environment variable DIYSCA_" + f.name.upper())
    return s


try:
    settings = load_settings()
except ConfigError as _e:  # diysca is an application: say what is wrong instead of a traceback at import
    raise SystemExit(f"diysca: {_e}") from None


def reload(path: str | None = None) -> Settings:
    new = load_settings(path, explicit=bool(path))
    for f in fields(new):
        setattr(settings, f.name, getattr(new, f.name))
    return settings
