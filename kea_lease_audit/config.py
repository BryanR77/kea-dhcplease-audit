"""Load the YAML inventory and resolve per-server settings.

Settings cascade:  built-in defaults <- top-level `defaults` <- region <- server.
Any key valid in `defaults` may also appear on a region or a server.
"""

import copy
import os

import yaml

BUILTIN_DEFAULTS = {
    "method": "api",          # api | ssh
    "families": [4],          # which lease families to audit: 4 and/or 6
    "timeout": 30,
    "api": {
        "scheme": "http",
        "port": 8000,
        "path": "/",
        # "dhcp4"/"dhcp6" when talking to kea-ctrl-agent; set to null when talking
        # directly to the DHCP daemon's own HTTP listener (Kea 2.7.2+/3.x).
        "service": True,
        "page_size": 1000,
        "username": None,
        "password": None,
        "password_env": None,
        "verify_tls": True,
        "ca_file": None,
        "cert_file": None,
        "key_file": None,
        # Reach the API through an ssh port-forward (uses the `ssh` settings),
        # for servers whose API listens only on loopback.
        "tunnel": False,
        "tunnel_host": "127.0.0.1",   # API address as seen from the server
    },
    "ssh": {
        "user": None,
        "port": 22,
        "identity_file": None,     # private key to use; ssh then offers only this key
        "known_hosts_file": None,  # host keys for these servers (default: ~/.ssh/known_hosts)
        "options": [],        # extra -o options, e.g. ["ProxyJump=bastion"]
        # Keep a background master connection for this many seconds after last
        # use, so repeated runs reuse one login (0 = new login every time).
        "control_persist": 600,
        "control_dir": None,      # default: $XDG_RUNTIME_DIR/kea-lease-audit or ~/.ssh/kea-lease-audit
        "sudo": False,
        "lease_dir": "/var/lib/kea",
        "lease_file4": "kea-leases4.csv",
        "lease_file6": "kea-leases6.csv",
    },
    "compare": {
        # Seconds of slack around "now" when deciding whether a lease is live.
        # Covers clock skew between servers and the auditor, and reclamation lag.
        "expiry_grace": 60,
        # Allowed difference in expire/cltt between partners. HA replicates cltt
        # verbatim, so 0 is correct for a healthy pair.
        "time_tolerance": 0,
        # Leases whose cltt falls within this many seconds of the snapshot are
        # still "in flight" (HA update may not have landed yet).
        "settle_window": 30,
        "recheck_rounds": 1,
        "recheck_delay": 15,
        "ignore_fields": [],  # e.g. ["hostname", "fqdn_fwd", "fqdn_rev"]
        # Warn when a server's clock is this far off the monitoring host, or
        # (HA check) off its partner. Kea's HA gives up at 60s.
        "clock_warn": 30,
    },
}


def _merge(base, override):
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class ConfigError(Exception):
    pass


class Server:
    def __init__(self, region, name, host, settings):
        self.region = region
        self.name = name
        self.host = host
        self.settings = settings

    @property
    def method(self):
        return self.settings["method"]

    def api_password(self):
        api = self.settings["api"]
        if api.get("password_env"):
            return os.environ.get(api["password_env"])
        return api.get("password")

    def __repr__(self):
        return f"Server({self.region}/{self.name} {self.method}://{self.host})"


class Region:
    def __init__(self, name, servers, compare):
        self.name = name
        self.servers = servers
        self.compare = compare


_SETTING_KEYS = set(BUILTIN_DEFAULTS)


def _settings_of(node):
    return {k: v for k, v in (node or {}).items() if k in _SETTING_KEYS}


def _resolve_ssh_files(where, settings):
    """Expand ~ in key/known_hosts paths and fail early if they are unusable."""
    uses_ssh = settings["method"] == "ssh" or settings["api"].get("tunnel")
    ssh = settings["ssh"]
    for opt in ("identity_file", "known_hosts_file"):
        if not ssh.get(opt):
            continue
        path = ssh[opt] = os.path.expanduser(os.path.expandvars(ssh[opt]))
        if uses_ssh and not os.path.isfile(path):
            raise ConfigError(f"{where}: ssh.{opt} {path} does not exist")
        if uses_ssh and opt == "identity_file" and os.stat(path).st_mode & 0o077:
            raise ConfigError(f"{where}: ssh.identity_file {path} is readable by others; "
                              f"ssh will refuse it (chmod 600)")


def load(path):
    with open(path) as fh:
        doc = yaml.safe_load(fh) or {}
    return parse(doc)


def parse(doc):
    defaults = _merge(BUILTIN_DEFAULTS, doc.get("defaults"))
    regions_doc = doc.get("regions")
    if not isinstance(regions_doc, dict) or not regions_doc:
        raise ConfigError("config must contain a non-empty 'regions' mapping")

    regions = []
    for rname, rnode in regions_doc.items():
        rnode = rnode or {}
        rsettings = _merge(defaults, _settings_of(rnode))
        servers_doc = rnode.get("servers") or []
        if len(servers_doc) < 2:
            raise ConfigError(f"region '{rname}' needs at least two servers to compare")
        servers = []
        seen = set()
        for snode in servers_doc:
            if isinstance(snode, str):
                snode = {"host": snode}
            host = snode.get("host")
            if not host:
                raise ConfigError(f"region '{rname}': every server needs a 'host'")
            name = snode.get("name") or host.split(".")[0]
            if name in seen:
                raise ConfigError(f"region '{rname}': duplicate server name '{name}'")
            seen.add(name)
            settings = _merge(rsettings, _settings_of(snode))
            if settings["method"] not in ("api", "ssh"):
                raise ConfigError(f"{rname}/{name}: method must be 'api' or 'ssh'")
            fams = settings["families"]
            if isinstance(fams, int):
                settings["families"] = fams = [fams]
            if not fams or any(f not in (4, 6) for f in fams):
                raise ConfigError(f"{rname}/{name}: families must be a list containing 4 and/or 6")
            _resolve_ssh_files(f"{rname}/{name}", settings)
            servers.append(Server(rname, name, host, settings))
        # Comparison settings are per-region (they apply to the set, not a member).
        regions.append(Region(rname, servers, rsettings["compare"]))
    return regions
